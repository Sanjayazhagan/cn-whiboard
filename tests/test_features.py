"""Socket-level tests for the extra features (no Tkinter needed):
WebSocket handshake + browser guest join by invite, frame compression, ordered requests with a reorder buffer,
chaos lab (loss + delay), time-travel replay log, and hot-standby replication with failover."""
import sys, time, socket, subprocess, os, json, struct, base64, tempfile, shutil
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from protocol import send_msg, recv_msg, recv_frame, simplify
import web

PORT, WEBP, PORT2, WEBP2 = 5096, 8096, 5097, 8097
tmp = tempfile.mkdtemp()


def server(*extra):
    return subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py"), "--no-auth", "--no-tls", "--no-discovery",
                             *extra], cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def conn(first, port=PORT, z=False):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    send_msg(s, dict(first, z=1) if z else first)
    return s


def drain(s, t=0.4):
    out = []
    s.settimeout(t)
    try:
        while True:
            out.append(recv_msg(s))
    except (socket.timeout, OSError):
        pass
    return out


def stroke(i, n=2, **kw):
    return {"type": "ADD", "msg_id": f"m{i}", "obj": {"id": f"s{i}", "kind": "stroke", "color": "#ff0000", "width": 3,
                                                      "points": [[j, (j * 7) % 50] for j in range(n)]}, **kw}


class WS:
    """Minimal WebSocket client (what a browser does), to test the hand-written server side."""
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=5)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += self.s.recv(1)
        assert b"101 Switching Protocols" in head and web.ws_accept(key).encode() in head, head

    def send(self, obj, split=False):
        data, mask = json.dumps(obj).encode(), os.urandom(4)
        parts = [data[:5], data[5:]] if split else [data]           # split = fragmented message
        for i, part in enumerate(parts):
            b0 = (0x80 if i == len(parts) - 1 else 0) | (1 if i == 0 else 0)
            n = len(part)
            head = struct.pack(">BB", b0, 0x80 | n) if n < 126 else struct.pack(">BBH", b0, 0x80 | 126, n)
            self.s.sendall(head + mask + bytes(c ^ mask[j % 4] for j, c in enumerate(part)))

    def recv(self):
        b0, b1 = self.s.recv(1)[0], self.s.recv(1)[0]
        n = b1 & 0x7F
        assert not b1 & 0x80, "server frames must not be masked"
        if n == 126:
            n = struct.unpack(">H", self._exact(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", self._exact(8))[0]
        return json.loads(self._exact(n))

    def _exact(self, n):
        buf = b""
        while len(buf) < n:
            buf += self.s.recv(n - len(buf))
        return buf

    def drain(self, t=0.4):
        out = []
        self.s.settimeout(t)
        try:
            while True:
                out.append(self.recv())
        except (socket.timeout, OSError, IndexError):
            pass
        return out


srv = server("--no-db", "--port", str(PORT), "--web-port", str(WEBP))
procs = [srv]
time.sleep(1.2)
try:
    # ---- 1. WebSocket handshake value from RFC 6455 section 1.3
    assert web.ws_accept("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    page = socket.create_connection(("127.0.0.1", WEBP)); page.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    html = b""
    while True:
        chunk = page.recv(65536)
        if not chunk:
            break
        html += chunk
    assert html.startswith(b"HTTP/1.1 200 OK") and b"<canvas" in html and b"WebSocket" in html
    print(f"ok  HTTP: GET / serves the web client ({len(html)} bytes); handshake matches the RFC 6455 example")

    # ---- 2. invite link -> browser guest joins over WebSocket; ops flow both ways
    a = conn({"type": "CREATE_ROOM", "user": "alice", "password": "secret"}, z=True); room = recv_msg(a)["room"]
    send_msg(a, {"type": "INVITE_REQ"}); inv = [m for m in drain(a) if m["type"] == "INVITE"][0]
    assert inv["url"].endswith(f":{WEBP}/?room={room}&invite={inv['invite']}"), inv["url"]
    w = WS(WEBP); w.send({"type": "JOIN_ROOM", "user": "Phone!", "invite": inv["invite"]}, split=True)
    j = w.recv()
    assert j["type"] == "JOIN_OK" and j["user"] == "Phone (web)" and j["room"] == room, j
    w.send(dict(stroke(1), rn=1)); got = w.drain()
    assert [m["type"] for m in got if m["type"] in ("OP", "ACK")] == ["OP", "ACK"], got
    assert [m for m in drain(a) if m["type"] == "OP"][0]["obj"]["owner"] == "Phone (web)"
    send_msg(a, stroke(2)); assert any(m["type"] == "OP" and m["seq"] == 2 for m in w.drain())
    bad = WS(WEBP); bad.send({"type": "JOIN_ROOM", "user": "x", "invite": inv["invite"][:-2] + "AA"})
    assert bad.recv()["type"] == "JOIN_ERR"
    bad2 = WS(WEBP); bad2.send({"type": "JOIN_ROOM", "user": "x", "room": room})      # no invite, no room password
    assert bad2.recv()["text"] == "Wrong room password"
    print("ok  WebSocket: guest joined with a signed invite (fragmented + masked frames), draws both ways; "
          "a tampered invite and a missing password are refused")

    # ---- 3. compression: flag bit set on big frames only, content identical
    send_msg(a, stroke(3, n=1500)); drain(a)
    b = conn({"type": "JOIN_ROOM", "user": "bob", "room": room, "password": "secret"}, z=True)
    msg, wire, raw, z = recv_frame(b)
    assert msg["type"] == "JOIN_OK" and z and wire < raw / 2, (wire, raw, z)
    c = conn({"type": "JOIN_ROOM", "user": "carl", "room": room, "password": "secret"})     # did not ask for it
    msg2, wire2, raw2, z2 = recv_frame(c)
    assert not z2 and msg2["snapshot"] == msg["snapshot"]
    assert len(simplify([[i, 5] for i in range(200)])) == 2 and len(simplify([[0, 0], [5, 9], [10, 0]])) == 3
    print(f"ok  compression: JOIN_OK {raw} -> {wire} bytes for a client that asked, plain for one that did not; "
          "RDP keeps corners, drops collinear points")

    # ---- 4. ordered requests: one that arrives ahead of a lost one is held back, then applied in order
    drain(b)
    send_msg(b, dict(stroke(11), rn=2)); assert not [m for m in drain(b) if m["type"] in ("OP", "ACK")]
    send_msg(b, dict(stroke(10), rn=1))
    got = drain(b)
    assert [m["obj"]["id"] for m in got if m["type"] == "OP"] == ["s10", "s11"], got
    assert [m["msg_id"] for m in got if m["type"] == "ACK"] == ["m10", "m11"], got
    send_msg(b, dict(stroke(10), rn=1)); assert drain(b) == [{"type": "ACK", "msg_id": "m10", "dup": True}]
    print("ok  ordering: an early request is held without ACK and applied after the missing one arrives; "
          "a retransmission gets a duplicate ACK")

    # ---- 5. chaos lab: only the host; loss + delay; reliable resending still gets everything through once
    send_msg(b, {"type": "CHAOS_SET", "loss": 50}); assert not [m for m in drain(b) if m["type"] == "CHAOS"]
    send_msg(a, {"type": "CHAOS_SET", "loss": 40, "delay": 60, "jitter": 20}); drain(a, 0.6)
    pending = {f"m{i}": dict(stroke(i), rn=i - 17) for i in range(20, 40)}      # b's next rn is 3
    t0, rounds = time.time(), 0
    while pending and time.time() - t0 < 30:
        rounds += 1
        send_msg(a, {"type": "PING", "t": 1})              # keep the host's connection alive meanwhile
        for m in list(pending.values()):
            send_msg(b, m)
        for m in drain(b, 0.5):
            if m["type"] == "ACK":
                pending.pop(m["msg_id"], None)
    assert not pending, f"{len(pending)} never acknowledged"
    send_msg(a, {"type": "CHAOS_SET", "loss": 0, "delay": 0, "jitter": 0}); time.sleep(0.5); drain(a); drain(b)
    send_msg(b, {"type": "PING", "t": 1}); pong = [m for m in drain(b) if m["type"] == "PONG"][0]
    st = pong["stats"]
    send_msg(b, {"type": "RESYNC_REQ", "since": 0})
    log = [m for m in drain(b) if m["type"] == "OPS_SINCE"][0]["ops"]
    ids = [o["obj"]["id"] for o in log if o["op"] == "ADD"]
    assert ids[-20:] == [f"s{i}" for i in range(20, 40)], ids                       # each exactly once, in order
    assert st["chaos_in"] > 0 and st["chaos_out"] > 0 and rounds > 1
    print(f"ok  chaos lab: with 40% loss + delay, 20 requests needed {rounds} rounds; server dropped "
          f"{st['chaos_in']} in / {st['chaos_out']} out, yet every op was applied exactly once and in order")

    # ---- 5b. quality of service: rate limit on disposable traffic, and ops overtake cursors on a narrow link
    drain(a); drain(b)
    for i in range(400):
        send_msg(b, {"type": "CURSOR", "x": i, "y": i})
    n = len([m for m in drain(a, 0.8) if m["type"] == "CURSOR"])
    # burst of 80 + refill while sending, not 400. Fewer than 80 can arrive when the server's outgoing queue to
    # `a` sheds stale CURSORs (QoS), which happens on slower socket stacks (seen with 51 on Windows CI).
    assert 20 <= n <= 200, n
    time.sleep(1.2)                                         # let b's bucket refill
    send_msg(a, {"type": "CHAOS_SET", "bw": 16}); drain(a); drain(b)
    for i in range(70):
        send_msg(b, {"type": "CURSOR", "x": i, "y": i})
    send_msg(b, dict(stroke(50), rn=23))
    got, t0 = [], time.time()
    a.settimeout(0.5)
    while time.time() - t0 < 6:
        try:
            got.append(recv_msg(a)["type"])
        except (socket.timeout, OSError):
            if "OP" in got:
                break
    before = got.index("OP")
    send_msg(a, {"type": "CHAOS_SET", "bw": 0}); time.sleep(0.3); drain(a); drain(b)
    send_msg(b, {"type": "PING", "t": 1}); q = [m for m in drain(b) if m["type"] == "PONG"][0]["stats"]
    assert before < 45 and got.count("CURSOR") < 70 and q["qos_shed"] > 0 and q["qos_limited"] > 0, (before, got.count("CURSOR"), q)
    print(f"ok  QoS: 400 cursor messages in a burst -> {n} forwarded (token bucket); on a 16 kbit/s link the stroke "
          f"overtook the cursor backlog (only {before} of 70 cursors left before it), {q['qos_shed']} stale cursors shed")

    # ---- 6. replay: the full op log
    send_msg(b, {"type": "REPLAY_REQ"}); rp = [m for m in drain(b) if m["type"] == "REPLAY"][0]["ops"]
    assert [o["seq"] for o in rp] == list(range(1, len(rp) + 1)) and len(rp) == st["room_seq"] + 1
    print(f"ok  replay: REPLAY returns all {len(rp)} sequenced ops")
    srv.terminate(); srv.wait()

    # ---- 7. hot standby: replicate, refuse clients while standing by, take over when the primary dies
    p1 = server("--port", str(PORT), "--web-port", str(WEBP), "--db", "p.db", "--cluster-key", "k1"); procs.append(p1)
    time.sleep(1.2)
    a = conn({"type": "CREATE_ROOM", "user": "alice"}); ja = recv_msg(a); room, atok = ja["room"], ja["token"]
    for i in range(1, 4):
        send_msg(a, stroke(i))
    send_msg(a, {"type": "CHAT", "text": "before the standby", "msg_id": "c1"}); drain(a)
    wrong = server("--port", str(PORT2), "--web-port", str(WEBP2), "--db", "w.db", "--cluster-key", "nope",
                   "--standby-of", f"127.0.0.1:{PORT}"); procs.append(wrong)
    time.sleep(1.5)
    assert not [m for m in drain(a) if m["type"] == "BACKUPS" and m["backups"]]
    wrong.terminate(); wrong.wait()
    p2 = server("--port", str(PORT2), "--web-port", str(WEBP2), "--db", "s.db", "--cluster-key", "k1",
                "--standby-of", f"127.0.0.1:{PORT}"); procs.append(p2)
    time.sleep(2)
    bk = [m for m in drain(a) if m["type"] == "BACKUPS"][-1]["backups"]
    assert bk and bk[0]["port"] == PORT2 and bk[0]["web"] == WEBP2, bk
    for i in range(4, 7):                                   # changes made AFTER the standby attached
        send_msg(a, stroke(i))
    send_msg(a, {"type": "ERASE", "ids": ["s2"], "msg_id": "e1"})
    b = conn({"type": "JOIN_ROOM", "user": "bob", "room": room}); btok = recv_msg(b)["token"]
    drain(a); drain(b)
    s = conn({"type": "JOIN_ROOM", "user": "alice", "room": room, "token": atok}, PORT2)
    r = recv_msg(s); assert r["type"] == "JOIN_ERR" and r["code"] == "STANDBY", r
    p1.kill(); p1.wait(); t0 = time.time()
    while True:                                             # what the client's reconnect loop does
        try:
            s = conn({"type": "JOIN_ROOM", "user": "alice", "room": room, "token": atok}, PORT2)
            r = recv_msg(s)
            if r["type"] == "JOIN_OK":
                break
        except OSError:
            pass
        assert time.time() - t0 < 15, "standby never took over"
        time.sleep(0.3)
    took = time.time() - t0
    vis = sorted(o["id"] for o in r["snapshot"]["objects"] if o["visible"])
    assert vis == ["s1", "s3", "s4", "s5", "s6"] and r["snapshot"]["seq"] == 7, r["snapshot"]
    assert r["chat"][0]["text"] == "before the standby" and r["host"] == "alice"
    send_msg(s, stroke(6)); assert drain(s) == [{"type": "ACK", "msg_id": "m6", "dup": True}]   # resend is harmless
    b2 = conn({"type": "JOIN_ROOM", "user": "bob", "room": room, "token": btok}, PORT2)
    assert recv_msg(b2)["type"] == "JOIN_OK"
    send_msg(s, stroke(7)); assert any(m["type"] == "OP" and m["seq"] == 8 for m in drain(b2))
    print(f"ok  hot standby: wrong cluster key refused; clients refused while standing by; after killing the "
          f"primary the standby took over in {took:.1f} s with the identical board, chat, members and duplicate filter")
    print("ALL FEATURE TESTS PASSED")
finally:
    for p in procs:
        if p.poll() is None:
            p.kill()
    shutil.rmtree(tmp, ignore_errors=True)
