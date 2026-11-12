"""LAN whiteboard server.

Architecture: one listener thread, one reader thread + one writer thread per client,
one UDP discovery thread, and one lock-protected Room object per session. The Room
holds the authoritative state: an ordered op log. Every accepted op gets the next
sequence number (seq) under the room lock, so all clients see the same total order.

Sending never blocks the room: each client has its own outgoing queue drained by its
own writer thread. A client that stops reading (full TCP window) only stalls its own
writer; after TIMEOUT_SEC (or once its queue is too big) it is dropped and will
reconnect. Without this, one slow laptop would freeze drawing for everyone
("head-of-line blocking").

Op types (state-changing, sequenced, stored):
  ADD  - a new drawable object (stroke / line / rect / oval / text / sticky note / image)
  VIS  - set visibility of object ids (used by erase, clear, undo, redo)
Everything else (cursor, live stroke preview, chat, presence) is not part of the canvas log.

Reliability: every client request that carries a msg_id is answered with ACK once it
has been processed. The client keeps unacknowledged requests and resends them after
a reconnect; the per-user msg_id filter makes the resend harmless if the original
had already arrived (at-least-once delivery + duplicate suppression = exactly-once effect).

Persistence: every change is also written to a SQLite database (db.py, default
whiteboard.db next to the server). On startup all rooms are rebuilt by replaying their
op logs, so a server restart does not lose any board, chat or history, and connected
clients resume automatically.

Accounts and security (auth.py): users register/log in with a password that is stored only
as a salted PBKDF2 hash. A successful login returns a JWT (signed with HMAC-SHA256); the client
shows it when joining or reconnecting, and the server takes the user name from the verified token,
so nobody can act under someone else's name. Failed logins are rate limited per IP address.
All TCP traffic is wrapped in TLS (self-signed certificate created on first start), so passwords,
tokens and drawings cannot be read or changed on the LAN. --no-auth / --no-tls turn these off.

Extras (each one is a networking topic of its own):
  web.py        - browsers / phones join through HTTP + a hand-written WebSocket server (second port).
  chaos lab     - the host can make the server drop / delay messages for a room; ACK + retransmit timer,
                  in-order processing with a reorder buffer, sequence-gap resync and the heartbeat
                  check repair the board.
  compression   - big frames are zlib-compressed (flag = top bit of the length prefix).
  hot standby   - `--standby-of HOST:PORT` turns a second server into a live replica that takes over
                  when the primary dies (primary/backup replication of the op log).

Undo/redo is per user: it only affects that user's own latest action, so one
person's undo never destroys another person's work. (Undo stacks are not stored in
the database, so they start empty after a server restart.)
"""
import argparse
import heapq
import hmac
import itertools
import json
import os
import random
import re
import secrets
import signal
import ssl
import socket
import string
import subprocess
import threading
import time
import uuid
from collections import deque

from auth import (MIN_PASSWORD, USERNAME_RE, RateLimiter, TokenError, ensure_certificate, fingerprint,
                  hash_password, issue_token, jwt_decode, jwt_encode, verify_password)
from db import Store
from protocol import (DEFAULT_PORT, DISCOVER_MAGIC, DISCOVERY_PORT, TIMEOUT_SEC, VOICE_PORT, WEB_PORT,
                      compress_frame, encode_msg, is_loopback, listen_socket, norm_addr, recv_frame, send_msg)
import voice
import web
from webpage import ADMIN_PAGE, PAGE

COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
KINDS = {"stroke", "line", "rect", "oval", "text", "sticky", "image", "enc"}   # enc = end-to-end encrypted
MAX_IMAGE_B64 = 700_000           # ~500 KB image after base64
MAX_ENC_B64 = 1_000_000           # one end-to-end encrypted object (an encrypted image fits)
MAX_ROOM_IMAGE_B64 = 20_000_000   # all images in a room (erased ones too); keeps snapshots < MAX_MSG
MAX_QUEUED_BYTES = 64 * 1024 * 1024  # per-client outgoing backlog before we give up on that client
MAX_VERSIONS = 40
SAVE_DIR = "saves"
USER_COLORS = ["#e6194b", "#3cb44b", "#4363d8", "#f58231", "#911eb4",
               "#008080", "#9a6324", "#800000", "#808000", "#000075"]


class Stats:
    """Server-wide network counters (shown in the console every 10 s and sent to clients in PONG)."""
    def __init__(self):
        self.t0 = time.time()
        self.lock = threading.Lock()
        self.c = dict(conns=0, msgs_in=0, msgs_out=0, bytes_in=0, bytes_out=0, ops=0, dups=0,
                      rejected=0, timeouts=0, reconnects=0, slow_drops=0, discovery=0, db_writes=0,
                      logins=0, login_fails=0, registrations=0, tls_fails=0,
                      chaos_drops=0, chaos_delayed=0, out_of_order=0, z_frames=0, z_saved=0,
                      web_conns=0, repl_events=0, shed=0, rate_limited=0, voice_pkts=0, voice_drops=0,
                      file_offers=0)

    def add(self, **kw):
        with self.lock:
            for k, v in kw.items():
                self.c[k] += v

    def snapshot(self):
        with self.lock:
            return dict(self.c, uptime=int(time.time() - self.t0))


stats = Stats()
store = None        # db.Store, or None when started with --no-db
AUTH = True         # accounts required (--no-auth turns this off: anyone joins with any name)
users = {}          # lower-case name -> (name, pw_hash)
users_lock = threading.Lock()
jwt_secret = secrets.token_bytes(32)   # replaced by the one stored in the database
limiter = RateLimiter()
tls_ctx = None      # ssl.SSLContext when TLS is on
DUMMY_HASH = hash_password("timing-equaliser")   # so "no such user" takes as long as "wrong password"
COMPRESS = True     # --no-compress turns frame compression off (e.g. for a readable Wireshark capture)
ROLE = "primary"    # "standby" while this server is a replica of another one (--standby-of)
CLUSTER_KEY = ""    # shared secret a standby must present before it is given the data (--cluster-key)
replicas = []       # connections of standby servers that receive every state change
WEB = None          # port of the HTTP/WebSocket listener, or None
VOICE = None        # UDP port of the voice relay, or None
TCP_PORT = DEFAULT_PORT

# Chaos lab: which message types may be DROPPED. Only the ones that have a recovery mechanism:
#   client -> server requests with a msg_id are retransmitted until ACKed; OP / ACK losses are repaired
#   by the sequence-gap resync and the retransmit timer; PING/PONG, LIVE, CURSOR, LASER are disposable.
# Everything else (chat lines, user lists, join replies) is only delayed, never dropped.
LOSSY_OUT = {"OP", "ACK", "PONG", "LIVE", "CURSOR", "LASER", "OPS_SINCE", "SNAPSHOT"}
LOSSY_IN = {"PING", "LIVE", "CURSOR", "LASER", "RESYNC_REQ"}       # plus anything that carries a msg_id

# Quality of service. Disposable traffic is sent only when no board traffic is waiting, is limited per
# client on the way in (token bucket), and is shed first when a link cannot keep up.
LOW_PRIO = {"CURSOR", "LIVE", "LASER"}
SHAPED = LOW_PRIO | {"OP"}          # what the chaos lab's bandwidth cap applies to
MAX_LOW_BACKLOG = 30                # disposable frames waiting per client before the oldest are dropped
TRANSIENT_RATE, TRANSIENT_BURST = 80, 80   # CURSOR/LIVE/LASER messages accepted per client per second / burst


def _plain(x):
    """Room / Member objects as plain data for the replication stream."""
    if isinstance(x, Room):
        return {"code": x.code, "password": x.password, "host": x.host}
    if isinstance(x, Member):
        return {"name": x.name, "token": x.token, "color": x.color, "role": x.role}
    return x


def persist(method, *args):
    """Record a state change: queue the database write (never blocks; see db.py) and forward the
    same event to every standby server. Called with the room lock held, so the standby sees the
    events of a room in exactly the order they happened."""
    if store is not None:
        getattr(store, method)(*args)
    if replicas:
        enc = Encoded({"type": "REPL", "m": method, "a": [_plain(a) for a in args]})
        stats.add(repl_events=1)
        for r in list(replicas):
            r.send_enc(enc)


events = deque(maxlen=200)     # recent server events, shown on the admin dashboard
ADMIN_KEY = ""


def event(text, flush=True):
    """Print a server event and remember it for the dashboard."""
    print(text, flush=flush)
    events.append([time.strftime("%H:%M:%S"), text])


def admin_state():
    """Everything the admin dashboard shows, as plain data."""
    with rooms_lock:
        rs = list(rooms.values())
    out = []
    for r in rs:
        with r.lock:
            out.append({"code": r.code, "host": r.host, "seq": r.seq(), "objects": len(r.objects),
                        "members": len(r.members), "password": bool(r.password), "chaos": r.chaos,
                        "chaos_n": dict(r.chaos_n), "qos": dict(r.qos), "chat": len(r.chat),
                        "clients": [{"name": m.name, "kind": m.client.kind, "rtt": m.rtt, "role": m.role,
                                     "addr": m.client.addr[0], "queued": m.client.queued}
                                    for m in r.members.values() if m.client]})
    return {"role": ROLE, "auth": AUTH, "tls": tls_ctx is not None, "compress": COMPRESS, "port": TCP_PORT,
            "web": WEB, "voice": VOICE, "ip": lan_ip(), "accounts": len(users), "stats": stats.snapshot(),
            "rooms": out, "standbys": backups_payload(), "events": list(events)[-80:], "now": time.time()}


def web_extra(route, query):
    """Extra HTTP routes: the admin dashboard (protected by the key printed at startup)."""
    if route not in ("/admin", "/admin/state"):
        return None
    if not hmac.compare_digest(query.get("key", "").encode(), ADMIN_KEY.encode()):
        return "403 Forbidden", b"Wrong or missing admin key (the server prints the dashboard link at startup)"
    if route == "/admin":
        return "200 OK", ADMIN_PAGE.encode("utf-8"), "text/html; charset=utf-8"
    return "200 OK", json.dumps(admin_state()).encode("utf-8"), "application/json"


class Encoded:
    """A message encoded once. The compressed variant is made only if some receiver wants it."""
    def __init__(self, msg):
        self.type = msg.get("type")
        self.plain = encode_msg(msg)
        self._z = None

    def wire(self, z):
        if not (z and COMPRESS):
            return self.plain
        if self._z is None:
            self._z = compress_frame(self.plain)
        return self._z


class Delayer:
    """Runs callbacks at a later time (one thread, a heap ordered by due time). Used by the chaos lab
    to delay messages the way a slow link would."""
    def __init__(self):
        self.heap, self.cv, self.n = [], threading.Condition(), itertools.count()
        threading.Thread(target=self._run, daemon=True).start()

    def at(self, due, fn, *args):
        with self.cv:
            heapq.heappush(self.heap, (due, next(self.n), fn, args))
            self.cv.notify()

    def _run(self):
        while True:
            with self.cv:
                while not self.heap or self.heap[0][0] > time.time():
                    self.cv.wait(self.heap[0][0] - time.time() if self.heap else None)
                _, _, fn, args = heapq.heappop(self.heap)
            try:
                fn(*args)
            except Exception as e:                 # a bad delayed message must not stop the clock
                event(f"[chaos] delayed call failed: {e!r}", flush=True)


delayer = Delayer()


def chaos_delay(ch):
    if not (ch["delay"] or ch["jitter"]):
        return 0.0
    return max(0.0, ch["delay"] + random.uniform(-ch["jitter"], ch["jitter"])) / 1000.0


_CLOSE = object()   # writer-queue marker: flush everything before this, then close the connection


class Client:
    """One TCP connection. send() only enqueues; a dedicated writer thread does the blocking sendall."""
    def __init__(self, sock, addr):
        self.sock, self.addr = sock, addr
        self.user = None
        self.room = None
        self.alive = True
        self.kind = "tcp"        # "tcp" desktop client, "web" browser (WebSocket), "replica" standby server
        self.z = False           # peer said it understands compressed frames
        self.in_due = self.out_due = 0.0   # chaos lab: when the previous delayed message is due (keeps order)
        self.hi, self.lo = deque(), deque()   # outgoing frames: board traffic / disposable traffic
        self.cv = threading.Condition()
        self.queued = 0          # bytes waiting in both queues
        self.tokens, self.tok_at = 0.0, time.time()      # outgoing byte bucket (chaos lab bandwidth cap)
        self.in_tokens, self.in_at = float(TRANSIENT_BURST), time.time()   # incoming rate limiter
        threading.Thread(target=self._writer, daemon=True).start()

    def send(self, msg):
        self.send_enc(Encoded(msg))

    def frame_for(self, enc):
        """The bytes this kind of connection puts on the wire for a message."""
        frame = enc.wire(self.z)
        if frame is not enc.plain:
            stats.add(z_frames=1, z_saved=len(enc.plain) - len(frame))
        return frame

    def send_enc(self, enc):
        """Queue a message. With the chaos lab on for this client's room the message may be dropped
        or held back first, exactly as an unreliable, slow link would do."""
        if not self.alive:
            return
        room, now, due = self.room, time.time(), 0.0
        ch = room.chaos if room is not None else None
        if ch:
            if enc.type in LOSSY_OUT and random.random() * 100 < ch["loss"]:
                stats.add(chaos_drops=1)
                room.chaos_n["out"] += 1
                return
            due = now + chaos_delay(ch)
        if due > now or self.out_due > now:
            self.out_due = max(self.out_due, due)        # never overtake an earlier delayed message
            if ch:
                stats.add(chaos_delayed=1)
            delayer.at(self.out_due, self.send_frame, self.frame_for(enc), enc.type)
        else:
            self.send_frame(self.frame_for(enc), enc.type)

    def send_frame(self, frame, mtype=None):
        """Put a frame in this client's outgoing queue. Two priority classes: board traffic (ops, ACKs,
        chat, ...) always goes before disposable traffic (cursor positions, live stroke previews, laser).
        If the disposable class backs up, the OLDEST entries are thrown away: a newer cursor position
        makes them worthless anyway."""
        if not self.alive:
            return
        low = mtype in LOW_PRIO
        shed = 0
        with self.cv:
            if low:
                while len(self.lo) >= MAX_LOW_BACKLOG:
                    old = self.lo.popleft()
                    self.queued -= len(old[0])
                    shed += 1
                self.lo.append((frame, mtype))
            else:
                self.hi.append((frame, mtype))
            self.queued += len(frame)
            too_slow = self.queued > MAX_QUEUED_BYTES
            self.cv.notify()
        if shed:
            stats.add(shed=shed)
            if self.room is not None:
                self.room.qos["shed"] += shed
        if too_slow:
            stats.add(slow_drops=1)
            event(f"[!] {self.addr} is not keeping up ({self.queued // 1024} KB queued) - dropping it")
            self.kill()

    def _mark(self, marker):
        with self.cv:
            self.hi.append((marker, None))
            self.cv.notify()

    def close_after_flush(self):
        """Used for KICK: the goodbye message is sent first, then the socket is shut down."""
        if self.out_due > time.time():                   # the goodbye itself is still being delayed
            delayer.at(self.out_due, self._mark, _CLOSE)
        else:
            self._mark(_CLOSE)

    def kill(self):
        self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)    # also wakes up the reader thread
        except OSError:
            pass
        with self.cv:
            self.hi.appendleft((None, None))
            self.cv.notify()

    def _throttle(self, n, mtype):
        """Chaos lab bandwidth cap: a token bucket in bytes. Tokens drip in at the configured rate; a
        frame may leave only when the bucket holds enough. Applied to board ops and disposable
        traffic, so a narrow link shows the priority queue at work."""
        room = self.room
        ch = room.chaos if room is not None else None
        if not ch or not ch.get("bw") or mtype not in SHAPED:
            return
        rate = ch["bw"] * 125.0                          # kbit/s -> bytes per second
        now = time.time()
        self.tokens = min(rate * 0.5, self.tokens + (now - self.tok_at) * rate)   # bucket depth = 0.5 s
        self.tok_at = now
        self.tokens -= n                                 # may go negative: that debt is the waiting time
        if self.tokens < 0:
            time.sleep(min(3.0, -self.tokens / rate))

    def _writer(self):
        while True:
            with self.cv:
                while not self.hi and not self.lo:
                    self.cv.wait()
                frame, mtype = self.hi.popleft() if self.hi else self.lo.popleft()
            if frame is None:
                return
            if frame is _CLOSE:
                self.kill()
                return
            self._throttle(len(frame), mtype)
            try:
                self.sock.sendall(frame)      # may block (receiver's TCP window full) - only this thread waits
            except socket.timeout:            # receiver accepted nothing for TIMEOUT_SEC: give up on it
                stats.add(slow_drops=1)
                event(f"[!] {self.addr} stopped reading - dropping it")
                self.kill()
                return
            except OSError:                   # connection closed / reset
                self.kill()
                return
            with self.cv:
                self.queued -= len(frame)
            stats.add(msgs_out=1, bytes_out=len(frame))


class WebClient(Client):
    """A browser connected through WebSocket: same messages, but each one travels as a WebSocket
    text frame instead of a length-prefixed frame (and without our own compression)."""
    def __init__(self, sock, addr):
        super().__init__(sock, addr)
        self.kind = "web"

    def frame_for(self, enc):
        return web.ws_encode(enc.plain[4:])


class Member:
    """A participant record that survives disconnects (for reconnection)."""
    def __init__(self, name, token, color, role):
        self.name, self.token, self.color, self.role = name, token, color, role
        self.client = None                 # current live connection or None
        self.undo, self.redo = [], []      # per-user action stacks
        self.seen = deque(maxlen=500)      # recent msg_ids -> duplicate filter
        self.next_rn = 1                   # next request number expected from this client
        self.held = {}                     # rn -> request that arrived before an earlier one (reorder buffer)
        self.rtt = None                    # latest round-trip time (ms) reported by this client


class Room:
    def __init__(self, code, password, host):
        self.code, self.password, self.host = code, password, host
        self.lock = threading.RLock()
        self.log = []          # sequenced ops; log[i]["seq"] == i + 1
        self.objects = {}      # id -> {"obj":..., "visible": bool}
        self.members = {}      # name -> Member
        self.banned = set()    # names kicked by the host (cannot rejoin, even with their token)
        self.image_bytes = 0   # base64 size of all images ever added (they are hidden, never deleted)
        self.chat = []
        self.versions = []     # version history: {"id","label","ts","seq","visible":[ids]}
        self.next_version = 1
        self.restoring = False  # no auto-snapshot half way through a restore
        self.chaos = None       # chaos lab settings {"loss": %, "delay": ms, "jitter": ms} or None (not saved)
        self.chaos_n = {"in": 0, "out": 0}    # messages dropped on purpose, per direction
        self.qos = {"shed": 0, "limited": 0}  # disposable frames shed (slow link) / refused (sender too fast)

    def take_version(self, label):
        """Snapshot = the set of visible object ids (objects are never deleted, only hidden,
        so ids are enough to restore any past state)."""
        v = {"id": self.next_version, "label": label, "ts": time.strftime("%H:%M:%S"),
             "seq": self.seq(), "visible": self.visible_ids()}
        self.next_version += 1
        self.versions.append(v)
        persist("add_version", self.code, v)
        while len(self.versions) > MAX_VERSIONS:       # drop the oldest automatic one first
            autos = [x for x in self.versions if x["label"].startswith("auto")]
            old = autos[0] if autos else self.versions[0]
            self.versions.remove(old)
            persist("delete_version", self.code, old["id"])
        return v

    def versions_payload(self):
        return [{k: v[k] for k in ("id", "label", "ts", "seq")} | {"count": len(v["visible"])}
                for v in reversed(self.versions)]

    # ---- helpers (call with lock held) ----
    def seq(self):
        return len(self.log)

    def users_payload(self):
        return [{"name": m.name, "color": m.color, "role": m.role,
                 "online": m.client is not None, "host": m.name == self.host}
                for m in self.members.values()]

    def broadcast(self, msg, skip=None):
        enc = Encoded(msg)                     # encode once, queue the same bytes for everyone
        for m in self.members.values():
            if m.client and m.client is not skip:
                m.client.send_enc(enc)

    def snapshot(self):
        return {"seq": self.seq(),
                "objects": [{**o["obj"], "visible": o["visible"]} for o in self.objects.values()]}

    def commit(self, op):
        """Assign the next seq, apply to state, broadcast. The ONE place state changes."""
        op["seq"] = self.seq() + 1
        op["type"] = "OP"
        stats.add(ops=1)
        self.apply(op)
        persist("add_op", self.code, op)
        self.broadcast(op)
        if len(self.log) % 25 == 0 and not self.restoring:
            self.take_version(f"auto @op {len(self.log)}")

    def apply(self, op):
        """Apply one sequenced op to the state (used live by commit() and when replaying the database)."""
        if op["op"] == "ADD":
            self.objects[op["obj"]["id"]] = {"obj": op["obj"], "visible": True}
            if op["obj"]["kind"] in ("image", "enc"):
                self.image_bytes += len(op["obj"]["data"])
        elif op["op"] == "VIS":
            for i in op["ids"]:
                if i in self.objects:
                    self.objects[i]["visible"] = op["visible"]
        self.log.append(op)

    def visible_ids(self):
        return [i for i, o in self.objects.items() if o["visible"]]

    def image_fits(self, obj):
        return (obj["kind"] not in ("image", "enc")
                or self.image_bytes + len(obj["data"]) <= MAX_ROOM_IMAGE_B64)


rooms = {}
rooms_lock = threading.Lock()


def new_code():
    while True:
        c = "".join(random.choices(string.ascii_uppercase + string.digits, k=5))
        if c not in rooms:
            return c


# ------------------------------------------------------------------ handlers
def valid_obj(o):
    try:
        if o["kind"] not in KINDS or not COLOR_RE.match(o["color"]):
            return False
        if not isinstance(o["id"], str) or len(o["id"]) > 64:
            return False
        pts = o["points"]
        if len(pts) > 20000 or any(len(p) != 2 or not all(isinstance(v, (int, float)) for v in p) for p in pts):
            return False
        if o["kind"] == "text" and len(str(o.get("text", ""))) > 500:
            return False
        if o["kind"] == "sticky" and (len(pts) != 1 or len(str(o.get("text", ""))) > 300):
            return False
        if o["kind"] == "enc":          # ciphertext only: the server cannot look inside (see e2e.py)
            d = o.get("data")
            return len(pts) == 1 and isinstance(d, str) and 64 <= len(d) <= MAX_ENC_B64
        if o["kind"] == "image":
            d = o.get("data")
            if (len(pts) != 1 or not isinstance(d, str) or len(d) > MAX_IMAGE_B64
                    or not (1 <= int(o["w"]) <= 2000 and 1 <= int(o["h"]) <= 2000)):
                return False
        return 1 <= float(o["width"]) <= 50
    except (KeyError, TypeError, ValueError):
        return False


def push_action(m, kind, ids):
    m.undo.append({"kind": kind, "ids": ids})
    m.redo.clear()


def handle(client, msg):
    room, t = client.room, msg.get("type")
    if t == "PING":
        # Echo the client's timestamp so it can compute RTT; piggyback live server/room statistics.
        reply = {"type": "PONG", "t": msg.get("t"), "stats": stats.snapshot()}
        if room is not None:
            with room.lock:
                if client.user in room.members:
                    room.members[client.user].rtt = msg.get("rtt")
                reply["peers"] = {n: mm.rtt for n, mm in room.members.items() if mm.client}
                reply["stats"]["room_seq"] = room.seq()
                reply["stats"]["room_clients"] = sum(1 for mm in room.members.values() if mm.client)
                reply["stats"]["chaos_in"], reply["stats"]["chaos_out"] = room.chaos_n["in"], room.chaos_n["out"]
                reply["stats"]["qos_shed"], reply["stats"]["qos_limited"] = room.qos["shed"], room.qos["limited"]
                reply["kinds"] = {n: mm.client.kind for n, mm in room.members.items() if mm.client}
        client.send(reply)
        return
    if room is None:
        return
    with room.lock:
        m = room.members.get(client.user)
        if m is None or m.client is not client:      # kicked, or replaced by a newer connection
            return
        mid = msg.get("msg_id")
        rn = msg.get("rn")
        if mid and isinstance(rn, int):           # numbered request: process strictly in rn order
            if rn > m.next_rn:                    # an earlier request was lost on the way: hold this one
                stats.add(out_of_order=1)         # back (no ACK yet) until the client's retransmit timer
                if len(m.held) < 256:             # has filled the gap - like TCP's out-of-order queue
                    m.held[rn] = msg
                return
            if rn == m.next_rn:
                m.next_rn += 1
        process(client, room, m, msg)
        while m.next_rn in m.held and room.members.get(client.user) is m:
            nxt = m.held.pop(m.next_rn)
            m.next_rn += 1
            process(client, room, m, nxt)


def process(client, room, m, msg):
    """Duplicate filter, then the request itself, then the ACK. Called with room.lock held."""
    mid = msg.get("msg_id")
    if mid:
        if mid in m.seen:
            stats.add(dups=1)
            client.send({"type": "ACK", "msg_id": mid, "dup": True})   # ack again so it stops resending
            return
        m.seen.append(mid)
    apply_request(client, room, m, msg.get("type"), msg, mid)
    if mid:
        client.send({"type": "ACK", "msg_id": mid})


def apply_request(client, room, m, t, msg, mid):
    """Everything that changes room state. Called with room.lock held."""
    can_edit = m.role == "editor"
    is_host = m.name == room.host
    if not can_edit and t in ("ADD", "ERASE", "UNDO", "REDO", "LIVE"):
        stats.add(rejected=1)

    if t == "ADD" and can_edit:
        obj = msg.get("obj", {})
        ok = valid_obj(obj) and obj["id"] not in room.objects
        if ok and not room.image_fits(obj):
            ok = False
            client.send({"type": "ERROR", "text": "Image not added: this room already holds "
                                                  f"{MAX_ROOM_IMAGE_B64 // 1_000_000} MB of images"})
        if not ok:
            stats.add(rejected=1)
            return
        obj = {k: obj[k] for k in ("id", "kind", "color", "width", "points") if k in obj}
        if "text" in msg["obj"]:
            obj["text"] = str(msg["obj"]["text"])
        if obj["kind"] == "image":
            obj.update(data=msg["obj"]["data"], w=int(msg["obj"]["w"]), h=int(msg["obj"]["h"]))
        elif obj["kind"] == "enc":
            obj.update(data=msg["obj"]["data"], color="#000000", width=1, points=[[0, 0]])
        obj["owner"] = m.name
        room.commit({"op": "ADD", "obj": obj, "by": m.name, "msg_id": mid})
        push_action(m, "add", [obj["id"]])
    elif t == "ERASE" and can_edit:
        ids = [i for i in msg.get("ids", []) if i in room.objects and room.objects[i]["visible"]]
        if ids:
            room.commit({"op": "VIS", "ids": ids, "visible": False, "by": m.name, "msg_id": mid})
            push_action(m, "erase", ids)
    elif t == "CLEAR" and is_host:
        ids = room.visible_ids()
        if ids:
            room.commit({"op": "VIS", "ids": ids, "visible": False, "by": m.name, "msg_id": mid})
            push_action(m, "erase", ids)
    elif t in ("UNDO", "REDO") and can_edit:
        src, dst = (m.undo, m.redo) if t == "UNDO" else (m.redo, m.undo)
        if src:
            act = src.pop()
            dst.append(act)
            # undo of ADD hides, undo of ERASE shows; redo is the reverse
            hide = (act["kind"] == "add") == (t == "UNDO")
            room.commit({"op": "VIS", "ids": act["ids"], "visible": not hide, "by": m.name, "msg_id": mid})
    elif t == "LIVE" and can_edit:             # transient stroke preview, not stored
        room.broadcast({"type": "LIVE", "user": m.name, "color": msg.get("color"),
                        "width": msg.get("width"), "points": msg.get("points", [])[-50:]}, skip=client)
    elif t == "CURSOR":
        room.broadcast({"type": "CURSOR", "user": m.name, "x": msg.get("x"), "y": msg.get("y")}, skip=client)
    elif t == "LASER":                         # laser pointer: transient, shown for a moment by everyone else
        room.broadcast({"type": "LASER", "user": m.name, "x": msg.get("x"), "y": msg.get("y")}, skip=client)
    elif t == "CHAOS_SET" and is_host:         # chaos lab: emulate a bad link for this room
        try:
            ch = {"loss": min(60.0, max(0.0, float(msg.get("loss", 0)))),
                  "delay": min(1000.0, max(0.0, float(msg.get("delay", 0)))),
                  "jitter": min(500.0, max(0.0, float(msg.get("jitter", 0)))),
                  "bw": min(2000.0, max(0.0, float(msg.get("bw", 0))))}     # kbit/s per client, 0 = no cap
            if 0 < ch["bw"] < 8:
                ch["bw"] = 8.0
        except (TypeError, ValueError):
            return
        room.chaos = ch if any(ch.values()) else None
        if msg.get("reset"):
            room.chaos_n = {"in": 0, "out": 0}
            room.qos = {"shed": 0, "limited": 0}
        event(f"[chaos] room {room.code}: {room.chaos or 'off'}", flush=True)
        room.broadcast({"type": "CHAOS", "chaos": room.chaos, "by": m.name})
    elif t == "FILE_OFFER":                    # peer-to-peer file transfer: we only introduce the two clients
        tgt = room.members.get(msg.get("to"))
        if not tgt or not tgt.client or tgt.client.kind != "tcp" or client.kind != "tcp" or tgt is m:
            client.send({"type": "ERROR", "text": "File not offered: pick a participant who is online in the "
                                                  "desktop client (browsers cannot receive files)"})
            return
        try:
            offer = {"type": "FILE_OFFER", "from": m.name, "id": str(msg["id"])[:64], "name": str(msg["name"])[:200],
                     "size": int(msg["size"]), "sha": str(msg["sha"])[:64], "port": int(msg["port"]),
                     "ip": client.addr[0]}                      # the sender's address as WE see it
        except (KeyError, TypeError, ValueError):
            return
        stats.add(file_offers=1)
        event(f"[file] {m.name} offers '{offer['name']}' ({offer['size']} bytes) to {tgt.name} - peer to peer")
        tgt.client.send(offer)
    elif t == "FILE_REPLY":                    # accepted / declined / received: passed back to the sender
        tgt = room.members.get(msg.get("to"))
        if tgt and tgt.client:
            tgt.client.send({"type": "FILE_REPLY", "from": m.name, "id": str(msg.get("id"))[:64],
                             "status": str(msg.get("status"))[:20], "text": str(msg.get("text", ""))[:300]})
        if msg.get("status") == "received":
            room.broadcast({"type": "INFO", "text": f"{m.name} received a file from {msg.get('to')} "
                                                    f"directly (peer to peer): {str(msg.get('text', ''))[:200]}"})
    elif t == "REPLAY_REQ":                    # time travel: the whole sequenced op log
        client.send({"type": "REPLAY", "ops": room.log})
    elif t == "INVITE_REQ":                    # a signed, short-lived link that lets a browser join this room
        client.send({"type": "INVITE", **make_invite(room)})
    elif t == "CHAT":
        text = str(msg.get("text", ""))[:1000].strip()
        if text:
            entry = {"type": "CHAT", "user": m.name, "text": text, "ts": time.strftime("%H:%M:%S")}
            room.chat.append(entry)
            persist("add_chat", room.code, entry, mid)
            room.broadcast(entry)
    elif t == "SET_ROLE" and is_host:
        tgt = room.members.get(msg.get("user"))
        if tgt and msg.get("role") in ("editor", "viewer") and tgt.name != room.host:
            tgt.role = msg["role"]
            persist("save_member", room.code, tgt)
            room.broadcast({"type": "USERS", "users": room.users_payload()})
    elif t == "KICK" and is_host:
        tgt = room.members.get(msg.get("user"))
        if tgt and tgt.name != room.host:
            room.banned.add(tgt.name)          # its saved token no longer gets it back in
            del room.members[tgt.name]
            persist("ban", room.code, tgt.name)
            if tgt.client:
                tgt.client.send({"type": "KICKED", "text": "You were removed from the room by the host"})
                tgt.client.room = None         # its connection no longer belongs to the room
                tgt.client.close_after_flush()
            room.broadcast({"type": "USERS", "users": room.users_payload()})
            room.broadcast({"type": "INFO", "text": f"{tgt.name} was removed by the host"})
    elif t == "VERSIONS_REQ":
        client.send({"type": "VERSIONS", "versions": room.versions_payload()})
    elif t == "VERSION_SAVE" and is_host:
        room.take_version(str(msg.get("label") or "manual")[:40])
        room.broadcast({"type": "VERSIONS", "versions": room.versions_payload()})
    elif t == "VERSION_RESTORE" and is_host:
        v = next((x for x in room.versions if x["id"] == msg.get("id")), None)
        if v:
            room.restoring = True
            target = set(v["visible"])
            hide = [i for i in room.visible_ids() if i not in target]
            show = [i for i in target if i in room.objects and not room.objects[i]["visible"]]
            if hide:
                room.commit({"op": "VIS", "ids": hide, "visible": False, "by": m.name})
            if show:
                room.commit({"op": "VIS", "ids": show, "visible": True, "by": m.name})
            room.restoring = False
            room.broadcast({"type": "INFO", "text": f"{m.name} restored version '{v['label']}'"})
    elif t == "RESYNC_REQ":
        since = max(0, int(msg.get("since", 0)))
        if room.seq() - 2000 <= since <= room.seq():
            client.send({"type": "OPS_SINCE", "ops": room.log[since:]})
        else:
            client.send({"type": "SNAPSHOT", **room.snapshot()})
    elif t == "SAVE" and is_host:
        os.makedirs(SAVE_DIR, exist_ok=True)
        path = os.path.join(SAVE_DIR, f"{room.code}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"objects": [o["obj"] for o in room.objects.values() if o["visible"]],
                       "chat": room.chat}, f)
        client.send({"type": "INFO", "text": f"Saved to server file {path}"})
    elif t == "LOAD" and is_host:
        path = os.path.join(SAVE_DIR, f"{room.code}.json")
        if not os.path.exists(path):
            client.send({"type": "ERROR", "text": "No saved board for this room"})
            return
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        ids = room.visible_ids()
        if ids:
            room.commit({"op": "VIS", "ids": ids, "visible": False, "by": m.name})
        skipped = 0
        for o in data["objects"]:
            o = dict(o, id="L" + uuid.uuid4().hex)      # fresh id (the old one may still exist, hidden)
            if valid_obj(o) and room.image_fits(o):
                room.commit({"op": "ADD", "obj": o, "by": m.name})
            else:
                skipped += 1
        if skipped:
            client.send({"type": "ERROR", "text": f"{skipped} saved object(s) could not be restored"})


def my_rooms(name):
    """Rooms this account belongs to (shown on the login screen)."""
    with rooms_lock:
        rs = list(rooms.values())
    out = []
    for r in rs:
        with r.lock:
            m = r.members.get(name)
            if m:
                out.append({"code": r.code, "host": r.host, "role": m.role, "password": bool(r.password),
                            "online": sum(1 for x in r.members.values() if x.client), "objects": len(r.objects)})
    return out


def account(client, msg):
    """REGISTER / LOGIN -> AUTH_OK with a JWT, or AUTH_ERR. MY_ROOMS (with a JWT) -> ROOMS."""
    t, ip = msg.get("type"), client.addr[0]

    def err(text):
        client.send({"type": "AUTH_ERR", "text": text})

    if not AUTH:
        return err("This server runs without accounts (--no-auth): just create or join a room")
    if t == "MY_ROOMS":
        try:
            claims = jwt_decode(str(msg.get("jwt", "")), jwt_secret)
        except TokenError as e:
            return err(f"Please log in again ({e})")
        return client.send({"type": "ROOMS", "rooms": my_rooms(claims["sub"])})
    name, pw = str(msg.get("user", "")).strip(), str(msg.get("password", ""))
    if limiter.blocked(ip):
        return err("Too many failed attempts from your computer - wait a minute and try again")
    if t == "REGISTER":
        if not USERNAME_RE.match(name):
            return err("Username must be 3-20 characters: letters, digits, . _ -")
        if len(pw) < MIN_PASSWORD:
            return err(f"Password must be at least {MIN_PASSWORD} characters")
        h = hash_password(pw)                 # slow on purpose (~0.1 s); done outside every lock
        with users_lock:
            if name.lower() in users:
                return err("That username is already registered - log in instead")
            users[name.lower()] = (name, h)
        persist("add_user", name, h)
        stats.add(registrations=1)
    else:
        rec = users.get(name.lower())
        ok = verify_password(pw, rec[1] if rec else DUMMY_HASH)
        if not (rec and ok):
            limiter.failed(ip)
            stats.add(login_fails=1)
            return err("Wrong username or password")
        name = rec[0]
    limiter.reset(ip)
    stats.add(logins=1)
    token, exp = issue_token(name, jwt_secret)
    client.send({"type": "AUTH_OK", "user": name, "jwt": token, "exp": exp, "rooms": my_rooms(name)})


def backups_payload():
    return [r.backup for r in list(replicas) if getattr(r, "ready", False)]


def announce_backups():
    """Tell every connected client where the standby servers are (they switch to one if we die)."""
    msg = {"type": "BACKUPS", "backups": backups_payload()}
    with rooms_lock:
        rs = list(rooms.values())
    for r in rs:
        with r.lock:
            r.broadcast(msg)


def voice_auth(room_code, user, token):
    """Voice relay: only an online member of the room, proving it with its member token."""
    r = rooms.get(str(room_code).upper())
    if r is None or ROLE != "primary":
        return False
    m = r.members.get(user)
    return bool(m and m.client and token and hmac.compare_digest(str(token), m.token))


def voice_loss(room_code):
    r = rooms.get(room_code)
    return r.chaos["loss"] if r is not None and r.chaos else 0


def make_invite(room):
    """Invite link for browsers: a JWT that names the room, signed with the server secret. Whoever
    holds it may join THAT room as a guest for one hour - no password travels over plain HTTP."""
    exp = int(time.time()) + 3600
    tok = jwt_encode({"kind": "invite", "room": room.code, "exp": exp, "iss": "lan-whiteboard"}, jwt_secret)
    url = f"http://{lan_ip()}:{WEB}/?room={room.code}&invite={tok}" if WEB else None
    return {"url": url, "exp": exp, "room": room.code, "invite": tok}


def guest_name(raw):
    name = re.sub(r"[^A-Za-z0-9_.-]", "", str(raw or ""))[:14] or "guest"
    return name + " (web)"        # accounts cannot contain a space or brackets, so a guest never clashes with one


def join(client, msg):
    """CREATE_ROOM / JOIN_ROOM. Returns True on success."""
    if ROLE != "primary":
        client.send({"type": "JOIN_ERR", "code": "STANDBY",
                     "text": "This server is a standby backup; it takes over only if the main server stops"})
        return False
    guest = False
    if msg.get("invite"):          # browser guest: the signed invite proves the right to enter one room
        try:
            claims = jwt_decode(str(msg["invite"]), jwt_secret)
            if claims.get("kind") != "invite" or msg["type"] != "JOIN_ROOM":
                raise TokenError("not an invite")
        except TokenError as e:
            client.send({"type": "JOIN_ERR", "code": "AUTH", "text": f"This invite link is not valid ({e})"})
            return False
        guest, user = True, guest_name(msg.get("user"))
        msg = dict(msg, room=claims["room"])
    elif AUTH:                     # identity comes from the verified token, never from the "user" field
        try:
            claims = jwt_decode(str(msg.get("jwt", "")), jwt_secret)
            if claims.get("kind") == "invite" or not claims.get("sub"):
                raise TokenError("not a login token")
        except TokenError as e:
            client.send({"type": "JOIN_ERR", "code": "AUTH", "text": f"Please log in first ({e})"})
            return False
        user = claims["sub"]
        if user.lower() not in users:
            client.send({"type": "JOIN_ERR", "code": "AUTH", "text": "This account no longer exists"})
            return False
    else:
        user = str(msg.get("user", "")).strip()[:20]
    if not user:
        client.send({"type": "JOIN_ERR", "text": "Username required"})
        return False
    with rooms_lock:
        if msg["type"] == "CREATE_ROOM":
            code = new_code()
            room = rooms[code] = Room(code, msg.get("password", ""), user)
            persist("add_room", room)
        else:
            room = rooms.get(str(msg.get("room", "")).upper())
            if room is None:
                client.send({"type": "JOIN_ERR", "code": "NO_ROOM", "text": "No such room"})
                return False
    with room.lock:
        if user in room.banned:
            client.send({"type": "JOIN_ERR", "code": "BANNED",
                         "text": "You were removed from this room by the host"})
            return False
        m = room.members.get(user)
        proven = AUTH and not guest                       # the JWT already proved who this is
        if m and (proven or m.token == msg.get("token")):   # same identity -> (re)connect
            if m.client:
                m.client.kill()
        else:
            if room.password and not guest and msg.get("password") != room.password:
                client.send({"type": "JOIN_ERR", "text": "Wrong room password"})
                return False
            if m:
                client.send({"type": "JOIN_ERR", "text": "Username already taken"})
                return False
            token = "".join(random.choices(string.ascii_letters + string.digits, k=16))
            m = room.members[user] = Member(user, token, USER_COLORS[len(room.members) % len(USER_COLORS)],
                                            "editor")
            persist("save_member", room.code, m)
        was_online = m.client is not None
        if m.token == msg.get("token") and msg.get("token"):
            stats.add(reconnects=1)
        m.client = client
        m.next_rn, m.held = 1, {}                         # the client numbers its requests from 1 again
        client.z = bool(msg.get("z")) and client.kind == "tcp"
        client.user, client.room = user, room
        client.send({"type": "JOIN_OK", "room": room.code, "user": user, "token": m.token,
                     "role": m.role, "color": m.color, "host": room.host,
                     "snapshot": room.snapshot(), "chat": room.chat[-200:],
                     "users": room.users_payload(), "chaos": room.chaos,
                     "backups": backups_payload(), "web": WEB, "voice": VOICE})
        event(f"[room {room.code}] {user} joined ({'browser' if client.kind == 'web' else 'desktop'}, {client.addr[0]})")
        room.broadcast({"type": "USERS", "users": room.users_payload()}, skip=client)
        if not was_online:
            room.broadcast({"type": "INFO", "text": f"{user} joined"}, skip=client)
    return True


def dispatch(client, msg):
    """One received message, whatever transport it arrived on (TCP frame or WebSocket frame)."""
    t = msg.get("type")
    if client.kind == "replica":
        if t == "PING":
            client.send({"type": "PONG", "t": msg.get("t")})
        return
    if client.room is None:
        if t in ("CREATE_ROOM", "JOIN_ROOM"):
            join(client, msg)
        elif t in ("REGISTER", "LOGIN", "MY_ROOMS"):
            if ROLE != "primary":
                client.send({"type": "AUTH_ERR", "text": "This server is a standby backup - use the main server"})
            else:
                account(client, msg)
        elif t == "REPL_HELLO":
            repl_hello(client, msg)
        elif t == "PING":
            handle(client, msg)
    else:
        handle(client, msg)


def incoming(client, msg):
    """Chaos lab hook for client -> server messages: maybe drop, maybe delay, then dispatch."""
    if not isinstance(msg, dict):
        return
    room, now, due = client.room, time.time(), 0.0
    if msg.get("type") in LOW_PRIO:                     # token bucket: at most TRANSIENT_RATE per second
        client.in_tokens = min(TRANSIENT_BURST, client.in_tokens + (now - client.in_at) * TRANSIENT_RATE)
        client.in_at = now
        if client.in_tokens < 1:
            stats.add(rate_limited=1)
            if room is not None:
                room.qos["limited"] += 1
            return
        client.in_tokens -= 1
    ch = room.chaos if room is not None else None
    if ch and msg.get("type") != "CHAOS_SET":           # the host must always be able to turn it off
        if (msg.get("type") in LOSSY_IN or msg.get("msg_id")) and random.random() * 100 < ch["loss"]:
            stats.add(chaos_drops=1)
            room.chaos_n["in"] += 1
            return
        due = now + chaos_delay(ch)
    if due > now or client.in_due > now:
        client.in_due = max(client.in_due, due)
        delayer.at(client.in_due, dispatch, client, msg)
    else:
        dispatch(client, msg)


def client_gone(client):
    room = client.room
    if room:
        with room.lock:
            m = room.members.get(client.user)
            if m and m.client is client:        # not already replaced by a reconnect
                m.client = None
                room.broadcast({"type": "USERS", "users": room.users_payload()})
                room.broadcast({"type": "INFO", "text": f"{client.user} left"})
                event(f"[room {room.code}] {client.user} left")
    if client in replicas:
        replicas.remove(client)
        event(f"[repl] standby {client.addr[0]} disconnected", flush=True)
        announce_backups()
    client.kill()


def serve_client(sock, addr):
    sock.settimeout(TIMEOUT_SEC)            # silent for 15s => treated as disconnected (also bounds sendall)
    if tls_ctx is not None:
        try:                                # TLS handshake here, not in the accept loop, so a slow peer
            sock = tls_ctx.wrap_socket(sock, server_side=True)   # cannot hold up other connections
        except (ssl.SSLError, OSError) as e:
            stats.add(tls_fails=1)
            event(f"[!] {addr} TLS handshake failed ({e}); is the client set to 'Encrypted'?")
            sock.close()
            return
    client = Client(sock, addr)
    try:
        while client.alive:
            msg, nbytes, _raw, _z = recv_frame(sock)
            stats.add(msgs_in=1, bytes_in=nbytes)
            incoming(client, msg)
    except socket.timeout:
        stats.add(timeouts=1)
    except (OSError, ValueError, KeyError, TypeError):
        pass
    finally:
        client_gone(client)
        sock.close()
        event(f"[-] {addr} disconnected")


def serve_websocket(sock, addr):
    """Called by web.py after the HTTP -> WebSocket handshake. Same loop as serve_client, but each
    message is one WebSocket frame."""
    stats.add(conns=1, web_conns=1)
    event(f"[+] {addr} connected (browser, WebSocket)")
    client = WebClient(sock, addr)
    try:
        while client.alive:
            data, nbytes = web.ws_recv(sock, client.send_frame)
            stats.add(msgs_in=1, bytes_in=nbytes)
            incoming(client, json.loads(data.decode("utf-8")))
    except socket.timeout:
        stats.add(timeouts=1)
    except (OSError, ValueError, KeyError, TypeError):
        pass
    finally:
        client_gone(client)
        event(f"[-] {addr} disconnected (browser)")


# ------------------------------------------------------------------ replication (hot standby)
def repl_hello(client, msg):
    """A standby server asks for the data. After checking the cluster key: register it (from now on it
    receives every change), then send it the current state room by room. A room is copied while holding
    its lock, and changes are forwarded while holding the same lock, so the standby can never miss or
    double-apply an op: whatever was queued for it before the copy is already inside the copy."""
    if not CLUSTER_KEY or not hmac.compare_digest(str(msg.get("key", "")).encode(), CLUSTER_KEY.encode()):
        client.send({"type": "REPL_ERR", "text": "wrong or missing cluster key (start both servers with "
                                                 "the same --cluster-key)"})
        event(f"[repl] {client.addr[0]} refused: wrong cluster key", flush=True)
        return
    host = lan_ip() if is_loopback(client.addr[0]) else client.addr[0]
    client.backup = {"host": host, "port": int(msg.get("port", DEFAULT_PORT)), "tls": bool(msg.get("tls")),
                     "fp": msg.get("fp"), "web": msg.get("web")}
    client.kind, client.z, client.ready = "replica", True, False
    replicas.append(client)
    with users_lock:
        us = [list(v) for v in users.values()]
    client.send({"type": "REPL_BEGIN", "users": us, "secret": jwt_secret.hex()})
    with rooms_lock:
        rs = list(rooms.values())
    for r in rs:
        with r.lock:
            client.send({"type": "REPL_ROOM", "code": r.code, "password": r.password, "host": r.host,
                         "members": [[m.name, m.token, m.color, m.role, list(m.seen)] for m in r.members.values()],
                         "banned": sorted(r.banned), "ops": r.log, "chat": r.chat, "versions": r.versions})
    client.send({"type": "REPL_READY", "rooms": len(rs)})
    client.ready = True
    event(f"[repl] standby {host}:{client.backup['port']} attached, {len(rs)} room(s) copied", flush=True)
    announce_backups()


def apply_repl(msg):
    """Standby side: apply one message of the replication stream to memory and to our own database."""
    global jwt_secret
    t = msg["type"]
    if t == "REPL_BEGIN":
        with rooms_lock:
            rooms.clear()
        with users_lock:
            users.clear()
            users.update({n.lower(): (n, h) for n, h in msg["users"]})
        jwt_secret = bytes.fromhex(msg["secret"])
        if store is not None:
            store.wipe()
            store.set_secret(msg["secret"])
            for n, h in msg["users"]:
                store.add_user(n, h)
    elif t == "REPL_ROOM":
        r = Room(msg["code"], msg["password"], msg["host"])
        for name, token, color, role, seen in msg["members"]:
            mm = r.members[name] = Member(name, token, color, role)
            mm.seen.extend(seen)
        r.banned = set(msg["banned"])
        for op in msg["ops"]:
            r.apply(op)
        r.chat, r.versions = msg["chat"], msg["versions"]
        r.next_version = max((v["id"] for v in r.versions), default=0) + 1
        with rooms_lock:
            rooms[r.code] = r
        if store is not None:
            store.add_room(r)
            for mm in r.members.values():
                store.save_member(r.code, mm)
            for b in r.banned:
                store.ban(r.code, b)
            for op in r.log:
                store.add_op(r.code, op)
            for c in r.chat:
                store.add_chat(r.code, c)
            for v in r.versions:
                store.add_version(r.code, v)
    elif t == "REPL":
        m, a = msg["m"], msg["a"]
        stats.add(repl_events=1)
        if m == "add_user":
            with users_lock:
                users[a[0].lower()] = (a[0], a[1])
            return persist(m, *a)
        if m == "add_room":
            r = Room(a[0]["code"], a[0]["password"], a[0]["host"])
            with rooms_lock:
                rooms[r.code] = r
            return persist(m, r)
        r = rooms.get(a[0])
        if r is None:                  # a room we have not been given yet: its full copy is on the way
            return
        with r.lock:
            if m == "add_op":
                op = a[1]
                if op["seq"] != r.seq() + 1:          # already inside the copy we received
                    return
                r.apply(op)
                if op.get("msg_id") and op.get("by") in r.members:
                    r.members[op["by"]].seen.append(op["msg_id"])
            elif m == "save_member":
                d = a[1]
                mm = r.members.get(d["name"])
                if mm is None:
                    mm = r.members[d["name"]] = Member(d["name"], d["token"], d["color"], d["role"])
                mm.token, mm.color, mm.role = d["token"], d["color"], d["role"]
                return persist(m, r.code, mm)
            elif m == "ban":
                r.banned.add(a[1])
                r.members.pop(a[1], None)
            elif m == "add_chat":
                r.chat.append(a[1])
                if len(a) > 2 and a[2] and a[1]["user"] in r.members:
                    r.members[a[1]["user"]].seen.append(a[2])
            elif m == "add_version":
                r.versions.append(a[1])
                r.next_version = a[1]["id"] + 1
            elif m == "delete_version":
                r.versions = [v for v in r.versions if v["id"] != a[1]]
            persist(m, *a)


def standby_loop(host, port, use_tls, my_port, my_fp):
    """Standby side: stay connected to the primary, apply its stream, and take over when it is gone.
    The primary counts as dead when the connection breaks (or stays silent for 4 s) AND two
    reconnect attempts in a row fail."""
    global ROLE
    synced, fails = False, 0
    while ROLE == "standby":
        s = None
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if use_tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                s = ctx.wrap_socket(s)
            send_msg(s, {"type": "REPL_HELLO", "key": CLUSTER_KEY, "port": my_port, "tls": tls_ctx is not None,
                         "fp": my_fp, "web": WEB})
            s.settimeout(1.0)
            fails, last, pinged = 0, time.time(), 0.0
            while True:
                if time.time() - pinged >= 1:                 # heartbeat, once a second
                    pinged = time.time()
                    send_msg(s, {"type": "PING", "t": pinged * 1000})
                try:
                    msg = recv_frame(s)[0]
                except socket.timeout:
                    if time.time() - last > 4:
                        raise ConnectionError("primary is silent")
                    continue
                last = time.time()
                if msg["type"] == "REPL_ERR":
                    event(f"[repl] primary refused us: {msg['text']}", flush=True)
                    time.sleep(5)
                    break
                if msg["type"] == "REPL_READY":
                    synced = True
                    event(f"[repl] in sync with primary {host}:{port} ({msg['rooms']} room(s)); "
                          "standing by", flush=True)
                elif msg["type"].startswith("REPL"):
                    apply_repl(msg)
        except (OSError, ValueError, KeyError) as e:
            fails += 1
            if synced:
                event(f"[repl] primary unreachable ({e}); attempt {fails}/2", flush=True)
            elif fails % 5 == 1:
                event(f"[repl] waiting for primary {host}:{port} ...", flush=True)
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        if synced and fails >= 2:
            break
        time.sleep(1)
    ROLE = "primary"
    with rooms_lock:
        n = len(rooms)
    print("=" * 62 + f"\n[repl] PRIMARY IS DOWN - this server has taken over ({n} room(s)).\n"
          "       Clients reconnect here on their own.\n" + "=" * 62, flush=True)


def restore_rooms():
    """Rebuild every saved room from the database by replaying its op log."""
    n_ops = 0
    for d in store.load():
        r = Room(d["code"], d["password"], d["host"])
        for name, token, color, role in d["members"]:
            r.members[name] = Member(name, token, color, role)
        r.banned = set(d["banned"])
        for op in d["ops"]:
            if op["seq"] != r.seq() + 1:          # never expected; stop rather than build a wrong board
                event(f"[db] room {r.code}: op log has a gap at seq {op['seq']}, stopping replay there")
                break
            r.apply(op)
            if op.get("msg_id") and op.get("by") in r.members:   # rebuild the duplicate filters, so a
                r.members[op["by"]].seen.append(op["msg_id"])    # client resending after the restart is ignored
        n_ops += r.seq()
        r.chat = []
        for ts, user, text, mid in d["chat"]:
            r.chat.append({"type": "CHAT", "user": user, "text": text, "ts": ts})
            if mid and user in r.members:
                r.members[user].seen.append(mid)
        r.versions = d["versions"]
        r.next_version = max((v["id"] for v in r.versions), default=0) + 1
        rooms[r.code] = r
    return len(rooms), n_ops


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))      # no packet sent; just picks the LAN interface
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def ipv6_addresses():
    """This machine's IPv6 addresses (for the startup banner)."""
    out = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6):
            ip = info[4][0]
            if ip not in out and ip != "::1":
                out.append(ip)
    except OSError:
        pass
    return out[:4]


def discovery_loop(udp_port, tcp_port, name):
    """UDP service discovery: answer every DISCOVER broadcast with our TCP port.
    The client learns our IP address from the source address of the reply datagram."""
    server_id = uuid.uuid4().hex[:8]
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # several servers on one PC (e.g. tests)
    try:
        u.bind(("", udp_port))
    except OSError as e:
        event(f"[!] LAN discovery disabled (UDP {udp_port}: {e}); clients can still type the IP")
        return
    while True:
        try:
            data, addr = u.recvfrom(1024)
        except OSError:
            continue
        if data.strip() != DISCOVER_MAGIC:
            continue
        with rooms_lock:
            rs = list(rooms.values())
        online = sum(1 for r in rs for m in list(r.members.values()) if m.client)
        reply = {"type": "WB_SERVER", "id": server_id, "name": name, "port": tcp_port,
                 "tls": tls_ctx is not None, "auth": AUTH, "role": ROLE, "web": WEB,
                 "ip": lan_ip(), "rooms": len(rs), "users": online}
        try:
            u.sendto(json.dumps(reply).encode("utf-8"), addr)    # unicast back to whoever asked
            stats.add(discovery=1)
        except OSError:
            pass


def stats_loop():
    """Console summary every 10 s: clients, traffic, per-user latency."""
    last = stats.snapshot()
    while True:
        time.sleep(10)
        cur = stats.snapshot()
        up = (cur["bytes_out"] - last["bytes_out"]) / 10
        down = (cur["bytes_in"] - last["bytes_in"]) / 10
        with rooms_lock:
            rs = list(rooms.values())
        parts = []
        for r in rs:
            with r.lock:
                users = ", ".join(f"{n}:{'%.0fms' % m.rtt if m.rtt is not None else '-'}"
                                  for n, m in r.members.items() if m.client)
                parts.append(f"{r.code}[{users}] seq={r.seq()}")
        print(f"[stats] up={cur['uptime']}s rooms={len(rs)} in={down/1024:.1f}KB/s out={up/1024:.1f}KB/s "
              f"msgs in/out={cur['msgs_in']}/{cur['msgs_out']} ops={cur['ops']} dup={cur['dups']} "
              f"rejected={cur['rejected']} timeouts={cur['timeouts']} reconnects={cur['reconnects']} "
              f"slow_drops={cur['slow_drops']} discovery={cur['discovery']} db_writes={cur['db_writes']} "
              f"z_saved={cur['z_saved'] // 1024}KB chaos_drops={cur['chaos_drops']} role={ROLE} | "
              + " ".join(parts), flush=True)
        last = cur


def _stop(*_):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)   # a second signal must not interrupt the final save
    raise KeyboardInterrupt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--name", default=socket.gethostname(), help="name shown in the clients' server list")
    ap.add_argument("--discovery-port", type=int, default=DISCOVERY_PORT, help="UDP port for LAN discovery")
    ap.add_argument("--no-discovery", action="store_true")
    ap.add_argument("--db", default="whiteboard.db", help="SQLite file that stores all rooms")
    ap.add_argument("--no-db", action="store_true", help="keep everything in memory only")
    ap.add_argument("--no-auth", action="store_true", help="no accounts: anyone joins with any name")
    ap.add_argument("--no-tls", action="store_true", help="plain TCP (readable in Wireshark)")
    ap.add_argument("--cert", default="server_cert.pem")
    ap.add_argument("--key", default="server_key.pem")
    ap.add_argument("--web-port", type=int, default=WEB_PORT, help="HTTP + WebSocket port for browsers/phones")
    ap.add_argument("--no-web", action="store_true", help="do not start the browser (WebSocket) listener")
    ap.add_argument("--no-compress", action="store_true", help="never compress frames (readable in Wireshark)")
    ap.add_argument("--admin-key", default="", help="key for the /admin dashboard (default: a random one)")
    ap.add_argument("--voice-port", type=int, default=VOICE_PORT, help="UDP port of the voice relay")
    ap.add_argument("--no-voice", action="store_true")
    ap.add_argument("--cluster-key", default="", help="shared secret that lets a standby server replicate us")
    ap.add_argument("--standby-of", default="", metavar="HOST[:PORT]",
                    help="run as a hot standby of that server and take over when it stops")
    a = ap.parse_args()
    global store, AUTH, jwt_secret, tls_ctx, COMPRESS, ROLE, CLUSTER_KEY, WEB, TCP_PORT, ADMIN_KEY, VOICE
    ADMIN_KEY = a.admin_key or secrets.token_urlsafe(6)
    AUTH = not a.no_auth
    COMPRESS, CLUSTER_KEY, TCP_PORT = not a.no_compress, a.cluster_key, a.port
    if a.standby_of:
        if not CLUSTER_KEY:
            ap.error("--standby-of needs --cluster-key (the same value as on the main server)")
        ROLE = "standby"
        if a.db == "whiteboard.db":
            a.db = "whiteboard-standby.db"     # never touch the main server's file when both run in one folder
    if not a.no_db:
        store = Store(a.db, on_write=lambda n: stats.add(db_writes=n))
        if ROLE == "standby":
            print(f"Database {os.path.abspath(a.db)}: will be overwritten with the primary's data", flush=True)
        else:
            nr, no = restore_rooms()
            print(f"Database {os.path.abspath(a.db)}: restored {nr} room(s), {no} op(s)", flush=True)
            users.update({n.lower(): (n, h) for n, h in store.load_users().items()})
        jwt_secret = store.secret(lambda: secrets.token_bytes(32))
    print(f"Accounts: {'ON (' + str(len(users)) + ' registered)' if AUTH else 'OFF (--no-auth)'}", flush=True)
    if not a.no_tls:
        try:
            print("TLS:", ensure_certificate(a.cert, a.key), flush=True)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(a.cert, a.key)
            with open(a.cert) as f:
                fp = fingerprint(ssl.PEM_cert_to_DER_cert(f.read()))
            tls_ctx = ctx
            print(f"TLS: ON. Certificate fingerprint (clients show the same one):\n     {fp}", flush=True)
        except (RuntimeError, OSError, ssl.SSLError, subprocess.CalledProcessError) as e:
            event(f"[!] TLS OFF - {e}", flush=True)
    else:
        print("TLS: OFF (--no-tls) - traffic is readable on the network", flush=True)
    srv, v6 = listen_socket(a.host, a.port)
    srv.listen(50)
    print(f"Whiteboard server '{a.name}' listening on {lan_ip()}:{a.port}  (clients connect to this address)")
    if v6:
        six = ipv6_addresses()
        print("IPv6: ON (dual-stack socket, IPv4 clients arrive as ::ffff:a.b.c.d). "
              + ("Addresses: " + ", ".join(six) if six else "Loopback ::1 works; no other IPv6 address found"), flush=True)
    else:
        print("IPv6: not available on this machine - serving IPv4 only", flush=True)
    if not a.no_web:
        try:
            web.start(a.host, a.web_port, lambda: PAGE.encode("utf-8"),
                      lambda: {"name": a.name, "auth": AUTH, "role": ROLE}, serve_websocket, TIMEOUT_SEC,
                      extra=web_extra)
            WEB = a.web_port
            print(f"Admin dashboard: http://{lan_ip()}:{a.web_port}/admin?key={ADMIN_KEY}", flush=True)
            print(f"Browser clients (HTTP + WebSocket): http://{lan_ip()}:{a.web_port}/  "
                  "(or use 'Phone join' in the desktop client for a QR code)", flush=True)
        except OSError as e:
            event(f"[!] Browser listener disabled (port {a.web_port}: {e}); try --web-port", flush=True)
    if not a.no_voice:
        try:
            voice.Relay(a.host, a.voice_port, voice_auth, voice_loss,
                        lambda k: stats.add(voice_pkts=1) if k == "relay" else stats.add(voice_drops=1))
            VOICE = a.voice_port
            print(f"Voice relay: UDP {a.voice_port}", flush=True)
        except OSError as e:
            event(f"[!] Voice relay disabled (UDP {a.voice_port}: {e}); try --voice-port")
    print(f"Compression: {'ON (zlib, frames >= 256 bytes)' if COMPRESS else 'OFF (--no-compress)'}", flush=True)
    if CLUSTER_KEY and ROLE == "primary":
        print("Replication: a standby may attach with --standby-of and the same --cluster-key", flush=True)
    if ROLE == "standby":
        h, _, pt = a.standby_of.partition(":")
        fp = None
        if tls_ctx is not None:
            with open(a.cert) as f:
                fp = fingerprint(ssl.PEM_cert_to_DER_cert(f.read()))
        print(f"Role: STANDBY of {h}:{pt or DEFAULT_PORT} - clients are refused until the primary stops", flush=True)
        threading.Thread(target=standby_loop, args=(h, int(pt or DEFAULT_PORT), not a.no_tls, a.port, fp),
                         daemon=True).start()
    threading.Thread(target=stats_loop, daemon=True).start()
    if not a.no_discovery:
        threading.Thread(target=discovery_loop, args=(a.discovery_port, a.port, a.name), daemon=True).start()
        print(f"LAN discovery: answering on UDP {a.discovery_port} (clients can press 'Find servers')")
    srv.settimeout(1.0)                        # wake up every second so Ctrl+C works on Windows too
    signal.signal(signal.SIGTERM, _stop)       # "kill" / terminate() also saves cleanly
    try:
        while True:
            try:
                s, addr = srv.accept()
            except socket.timeout:
                continue
            addr = norm_addr(addr)
            s.settimeout(None)
            stats.add(conns=1)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            event(f"[+] {addr} connected")
            threading.Thread(target=serve_client, args=(s, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("Stopping server...")
    finally:
        if store is not None:
            store.flush()                      # make sure the last writes reach the disk


if __name__ == "__main__":
    main()
