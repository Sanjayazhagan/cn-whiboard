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

Undo/redo is per user: it only affects that user's own latest action, so one
person's undo never destroys another person's work. (Undo stacks are not stored in
the database, so they start empty after a server restart.)
"""
import argparse
import json
import os
import queue
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
                  hash_password, issue_token, jwt_decode, verify_password)
from db import Store
from protocol import (DEFAULT_PORT, DISCOVER_MAGIC, DISCOVERY_PORT, TIMEOUT_SEC,
                      encode_msg, recv_msg_ex)

COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
KINDS = {"stroke", "line", "rect", "oval", "text", "sticky", "image"}
MAX_IMAGE_B64 = 700_000           # ~500 KB image after base64
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
                      logins=0, login_fails=0, registrations=0, tls_fails=0)

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


def persist(method, *args):
    """Queue a database write (never blocks; see db.py)."""
    if store is not None:
        getattr(store, method)(*args)
_CLOSE = object()   # writer-queue marker: flush everything before this, then close the connection


class Client:
    """One TCP connection. send() only enqueues; a dedicated writer thread does the blocking sendall."""
    def __init__(self, sock, addr):
        self.sock, self.addr = sock, addr
        self.user = None
        self.room = None
        self.alive = True
        self.outq = queue.Queue()
        self.qlock = threading.Lock()
        self.queued = 0          # bytes waiting in outq
        threading.Thread(target=self._writer, daemon=True).start()

    def send(self, msg):
        self.send_frame(encode_msg(msg))

    def send_frame(self, frame):
        if not self.alive:
            return
        with self.qlock:
            self.queued += len(frame)
            too_slow = self.queued > MAX_QUEUED_BYTES
        if too_slow:
            stats.add(slow_drops=1)
            print(f"[!] {self.addr} is not keeping up ({self.queued // 1024} KB queued) - dropping it")
            self.kill()
            return
        self.outq.put(frame)

    def close_after_flush(self):
        """Used for KICK: the goodbye message is sent first, then the socket is shut down."""
        self.outq.put(_CLOSE)

    def kill(self):
        self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)    # also wakes up the reader thread
        except OSError:
            pass
        self.outq.put(None)

    def _writer(self):
        while True:
            frame = self.outq.get()
            if frame is None:
                return
            if frame is _CLOSE:
                self.kill()
                return
            try:
                self.sock.sendall(frame)      # may block (receiver's TCP window full) - only this thread waits
            except socket.timeout:            # receiver accepted nothing for TIMEOUT_SEC: give up on it
                stats.add(slow_drops=1)
                print(f"[!] {self.addr} stopped reading - dropping it")
                self.kill()
                return
            except OSError:                   # connection closed / reset
                self.kill()
                return
            with self.qlock:
                self.queued -= len(frame)
            stats.add(msgs_out=1, bytes_out=len(frame))


class Member:
    """A participant record that survives disconnects (for reconnection)."""
    def __init__(self, name, token, color, role):
        self.name, self.token, self.color, self.role = name, token, color, role
        self.client = None                 # current live connection or None
        self.undo, self.redo = [], []      # per-user action stacks
        self.seen = deque(maxlen=500)      # recent msg_ids -> duplicate filter
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
        frame = encode_msg(msg)                # encode once, queue the same bytes for everyone
        for m in self.members.values():
            if m.client and m.client is not skip:
                m.client.send_frame(frame)

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
            if op["obj"]["kind"] == "image":
                self.image_bytes += len(op["obj"]["data"])
        elif op["op"] == "VIS":
            for i in op["ids"]:
                if i in self.objects:
                    self.objects[i]["visible"] = op["visible"]
        self.log.append(op)

    def visible_ids(self):
        return [i for i, o in self.objects.items() if o["visible"]]

    def image_fits(self, obj):
        return obj["kind"] != "image" or self.image_bytes + len(obj["data"]) <= MAX_ROOM_IMAGE_B64


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
        client.send(reply)
        return
    if room is None:
        return
    with room.lock:
        m = room.members.get(client.user)
        if m is None or m.client is not client:      # kicked, or replaced by a newer connection
            return
        mid = msg.get("msg_id")
        if mid:                                   # duplicate suppression
            if mid in m.seen:
                stats.add(dups=1)
                client.send({"type": "ACK", "msg_id": mid, "dup": True})   # ack again so it stops resending
                return
            m.seen.append(mid)
        apply_request(client, room, m, t, msg, mid)
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


def join(client, msg):
    """CREATE_ROOM / JOIN_ROOM. Returns True on success."""
    if AUTH:                       # identity comes from the verified token, never from the "user" field
        try:
            claims = jwt_decode(str(msg.get("jwt", "")), jwt_secret)
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
        if m and (AUTH or m.token == msg.get("token")):   # same identity (token-proven) -> (re)connect
            if m.client:
                m.client.kill()
        else:
            if room.password and msg.get("password") != room.password:
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
        client.user, client.room = user, room
        client.send({"type": "JOIN_OK", "room": room.code, "user": user, "token": m.token,
                     "role": m.role, "color": m.color, "host": room.host,
                     "snapshot": room.snapshot(), "chat": room.chat[-200:],
                     "users": room.users_payload()})
        room.broadcast({"type": "USERS", "users": room.users_payload()}, skip=client)
        if not was_online:
            room.broadcast({"type": "INFO", "text": f"{user} joined"}, skip=client)
    return True


def serve_client(sock, addr):
    sock.settimeout(TIMEOUT_SEC)            # silent for 15s => treated as disconnected (also bounds sendall)
    if tls_ctx is not None:
        try:                                # TLS handshake here, not in the accept loop, so a slow peer
            sock = tls_ctx.wrap_socket(sock, server_side=True)   # cannot hold up other connections
        except (ssl.SSLError, OSError) as e:
            stats.add(tls_fails=1)
            print(f"[!] {addr} TLS handshake failed ({e}); is the client set to 'Encrypted'?")
            sock.close()
            return
    client = Client(sock, addr)
    try:
        while client.alive:
            msg, nbytes = recv_msg_ex(sock)
            stats.add(msgs_in=1, bytes_in=nbytes)
            if not isinstance(msg, dict):
                continue
            if client.room is None:
                if msg.get("type") in ("CREATE_ROOM", "JOIN_ROOM"):
                    join(client, msg)
                elif msg.get("type") in ("REGISTER", "LOGIN", "MY_ROOMS"):
                    account(client, msg)
                elif msg.get("type") == "PING":
                    handle(client, msg)
            else:
                handle(client, msg)
    except socket.timeout:
        stats.add(timeouts=1)
    except (OSError, ValueError, KeyError, TypeError):
        pass
    finally:
        room = client.room
        if room:
            with room.lock:
                m = room.members.get(client.user)
                if m and m.client is client:        # not already replaced by a reconnect
                    m.client = None
                    room.broadcast({"type": "USERS", "users": room.users_payload()})
                    room.broadcast({"type": "INFO", "text": f"{client.user} left"})
        client.kill()
        sock.close()
        print(f"[-] {addr} disconnected")


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
                print(f"[db] room {r.code}: op log has a gap at seq {op['seq']}, stopping replay there")
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


def discovery_loop(udp_port, tcp_port, name):
    """UDP service discovery: answer every DISCOVER broadcast with our TCP port.
    The client learns our IP address from the source address of the reply datagram."""
    server_id = uuid.uuid4().hex[:8]
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # several servers on one PC (e.g. tests)
    try:
        u.bind(("", udp_port))
    except OSError as e:
        print(f"[!] LAN discovery disabled (UDP {udp_port}: {e}); clients can still type the IP")
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
                 "tls": tls_ctx is not None, "auth": AUTH,
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
              f"slow_drops={cur['slow_drops']} discovery={cur['discovery']} db_writes={cur['db_writes']} | "
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
    a = ap.parse_args()
    global store, AUTH, jwt_secret, tls_ctx
    AUTH = not a.no_auth
    if not a.no_db:
        store = Store(a.db, on_write=lambda n: stats.add(db_writes=n))
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
            print(f"[!] TLS OFF - {e}", flush=True)
    else:
        print("TLS: OFF (--no-tls) - traffic is readable on the network", flush=True)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.host, a.port))
    srv.listen(50)
    print(f"Whiteboard server '{a.name}' listening on {lan_ip()}:{a.port}  (clients connect to this address)")
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
            s.settimeout(None)
            stats.add(conns=1)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            print(f"[+] {addr} connected")
            threading.Thread(target=serve_client, args=(s, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("Stopping server...")
    finally:
        if store is not None:
            store.flush()                      # make sure the last writes reach the disk


if __name__ == "__main__":
    main()
