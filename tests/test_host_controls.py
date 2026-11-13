"""Host-only room controls and per-person phone limits (socket level, no Tkinter needed):

- voice chat and end-to-end encryption are room switches only the host can flip (ROOM_SET);
  while they are off the voice relay refuses everyone and the server refuses ciphertext
- the host sees who was removed and can let them back in (UNBAN), also after a restart
- an invite link belongs to the member who asked for it: at most 2 phones/browsers can be connected
  through one person's links at the same time; closing one frees its place"""
import sys, time, socket, subprocess, os, json, tempfile, shutil, base64, struct
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from protocol import send_msg, recv_msg
import voice
import e2e

PORT, WEBP, VPORT = 5151, 8151, 5152
tmp = tempfile.mkdtemp()
DB = os.path.join(tmp, "wb.db")


def server():
    return subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py"), "--no-auth", "--no-tls", "--no-discovery",
                             "--db", DB, "--port", str(PORT), "--web-port", str(WEBP), "--voice-port", str(VPORT)],
                            cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def conn(first):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    send_msg(s, first)
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


def wait_for(s, kind, t=3):
    end = time.time() + t
    s.settimeout(0.3)
    while time.time() < end:
        try:
            m = recv_msg(s)
        except (socket.timeout, OSError):
            continue
        if m.get("type") == kind:
            return m
    raise AssertionError(f"no {kind}")


def voice_hello(room, user, token):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(2)
    u.sendto(voice.MAGIC + bytes([voice.HELLO]) + json.dumps({"room": room, "user": user, "token": token}).encode(),
             ("127.0.0.1", VPORT))
    data = u.recv(2048)
    u.close()
    return json.loads(data[3:])["ok"]


class WS:
    """Minimal WebSocket client: what the phone's browser does."""
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=5)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += self.s.recv(1)
        assert b"101" in head, head

    def send(self, obj):
        data, mask = json.dumps(obj).encode(), os.urandom(4)
        n = len(data)
        head = struct.pack(">BB", 0x81, 0x80 | n) if n < 126 else struct.pack(">BBH", 0x81, 0x80 | 126, n)
        self.s.sendall(head + mask + bytes(c ^ mask[j % 4] for j, c in enumerate(data)))

    def _exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.s.recv(n - len(buf))
            if not chunk:
                raise OSError("closed")
            buf += chunk
        return buf

    def recv(self):
        b0, b1 = self._exact(2)
        n = b1 & 0x7F
        if n == 126:
            n = struct.unpack(">H", self._exact(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", self._exact(8))[0]
        return json.loads(self._exact(n))

    def drain(self, t=0.4):
        out = []
        self.s.settimeout(t)
        try:
            while True:
                out.append(self.recv())
        except (socket.timeout, OSError, ValueError):
            pass
        return out


def guest(invite, name):
    w = WS(WEBP)
    w.send({"type": "JOIN_ROOM", "user": name, "invite": invite})
    return w, w.recv()


procs = [server()]
try:
    time.sleep(1.5)
    h = conn({"type": "CREATE_ROOM", "user": "host", "password": ""})
    j = recv_msg(h)
    room, htok = j["room"], j["token"]
    assert j["cfg"] == {"voice": False, "e2e": False} and j["banned"] == [], j
    b = conn({"type": "JOIN_ROOM", "user": "bob", "room": room, "password": ""})
    jb = recv_msg(b)
    btok = jb["token"]
    c = conn({"type": "JOIN_ROOM", "user": "carol", "room": room, "password": ""})
    recv_msg(c)
    drain(h); drain(b); drain(c)

    # ---------------------------------------------------------------- 1. voice: only the host switches it
    assert not voice_hello(room, "bob", btok)                        # off by default: relay refuses
    send_msg(b, {"type": "ROOM_SET", "voice": True})
    assert "Only the host" in wait_for(b, "ERROR")["text"]
    assert not voice_hello(room, "bob", btok)
    send_msg(h, {"type": "ROOM_SET", "voice": True})
    assert wait_for(b, "ROOM")["cfg"]["voice"] is True
    assert voice_hello(room, "bob", btok) and voice_hello(room, "host", htok)
    send_msg(h, {"type": "ROOM_SET", "voice": False})
    wait_for(b, "ROOM")
    assert not voice_hello(room, "bob", btok)
    print("ok  voice chat: only the host can turn it on/off; while off the relay refuses everyone")

    # ---------------------------------------------------------------- 2. E2E: only the host switches it
    enc = {"type": "ADD", "msg_id": "e1", "obj": {"id": "x1", "kind": "enc", "color": "#000000", "width": 1,
                                                    "points": [[0, 0]],
                                                    "data": e2e.seal(e2e.derive("pw", room), b'{"kind":"stroke"}')}}
    send_msg(b, enc)
    assert "end-to-end encryption is off" in wait_for(b, "ERROR")["text"]
    send_msg(b, {"type": "CHAT", "msg_id": "c1", "text": e2e.PREFIX + e2e.seal(e2e.derive("pw", room), b"hi")})
    assert "end-to-end encryption is off" in wait_for(b, "ERROR")["text"]
    send_msg(b, {"type": "ROOM_SET", "e2e": True})
    assert "Only the host" in wait_for(b, "ERROR")["text"]
    drain(c)
    send_msg(h, {"type": "ROOM_SET", "e2e": True})
    assert wait_for(c, "ROOM")["cfg"] == {"voice": False, "e2e": True}
    drain(b)
    send_msg(b, dict(enc, msg_id="e2"))
    op = wait_for(c, "OP")
    assert op["op"] == "ADD" and op["obj"]["kind"] == "enc"
    print("ok  end-to-end encryption: only the host can turn it on; while off the server refuses ciphertext")

    # ---------------------------------------------------------------- 3. kick, see the removed, let back in
    send_msg(b, {"type": "KICK", "user": "carol"})
    assert "Only the host" in wait_for(b, "ERROR")["text"]
    send_msg(h, {"type": "KICK", "user": "carol"})
    assert wait_for(c, "KICKED")
    u = wait_for(h, "USERS")
    assert u["banned"] == ["carol"] and "carol" not in [x["name"] for x in u["users"]], u
    c2 = conn({"type": "JOIN_ROOM", "user": "carol", "room": room, "password": ""})
    assert recv_msg(c2)["code"] == "BANNED"
    send_msg(b, {"type": "UNBAN", "user": "carol"})
    assert "Only the host" in wait_for(b, "ERROR")["text"]
    send_msg(h, {"type": "UNBAN", "user": "carol"})
    assert wait_for(h, "USERS")["banned"] == []
    c3 = conn({"type": "JOIN_ROOM", "user": "carol", "room": room, "password": ""})
    assert recv_msg(c3)["type"] == "JOIN_OK"
    print("ok  the host sees who was removed and can let them back in")

    # ---------------------------------------------------------------- 4. at most 2 phones per person's link
    send_msg(b, {"type": "INVITE_REQ"})
    inv_b = wait_for(b, "INVITE")
    send_msg(h, {"type": "INVITE_REQ"})
    inv_h = wait_for(h, "INVITE")
    assert inv_b["by"] == "bob" and inv_b["max"] == 2 and inv_b["invite"] != inv_h["invite"]
    p1, r1 = guest(inv_b["invite"], "phone1")
    p2, r2 = guest(inv_b["invite"], "phone2")
    assert r1["type"] == r2["type"] == "JOIN_OK", (r1, r2)
    p3, r3 = guest(inv_b["invite"], "phone3")                  # third device on bob's link: refused
    assert r3["type"] == "JOIN_ERR" and r3["code"] == "INVITE_LIMIT", r3
    assert "at most 2" in r3["text"] and "phone1 (web)" in r3["text"]
    send_msg(b, {"type": "INVITE_REQ"})                        # a fresh link from bob does not reset the count
    p4, r4 = guest(wait_for(b, "INVITE")["invite"], "phone4")
    assert r4["code"] == "INVITE_LIMIT"
    p5, r5 = guest(inv_h["invite"], "phone5")                  # the host's own link has its own 2 places
    assert r5["type"] == "JOIN_OK"
    p1.send({"type": "INVITE_REQ"})                            # a guest cannot mint links to get round it
    assert any(m.get("type") == "ERROR" and "cannot invite" in m["text"] for m in p1.drain(1))
    p2.s.close()                                                # one phone closes its page ...
    time.sleep(0.5)
    p6, r6 = guest(inv_b["invite"], "phone6")                  # ... and its place is free again
    assert r6["type"] == "JOIN_OK", r6
    send_msg(b, {"type": "INVITE_REQ"})
    assert wait_for(b, "INVITE")["used"] == ["phone1 (web)", "phone6 (web)"]
    print("ok  each person's invite link connects at most 2 phones at a time; closing one frees its place")

    send_msg(h, {"type": "KICK", "user": "bob"})               # bob removed: his links stop working
    wait_for(h, "USERS")
    p7, r7 = guest(inv_b["invite"], "phone7")
    assert r7["type"] == "JOIN_ERR" and "not a member" in r7["text"], r7
    print("ok  a removed person's invite links stop letting new phones in")

    # ---------------------------------------------------------------- 5. survives a restart (database)
    send_msg(h, {"type": "ROOM_SET", "voice": True})
    wait_for(h, "ROOM")
    time.sleep(1.5)                                            # let the database writer catch up
    procs[0].kill(); procs[0].wait()
    procs.append(server())
    time.sleep(1.5)
    h2 = conn({"type": "JOIN_ROOM", "user": "host", "room": room, "password": "", "token": htok})
    j2 = recv_msg(h2)
    assert j2["type"] == "JOIN_OK" and j2["cfg"] == {"voice": True, "e2e": True} and j2["banned"] == ["bob"], j2
    print("ok  room switches and the removed list survive a server restart")
    print("ALL HOST CONTROL TESTS PASSED")
finally:
    for p in procs:
        if p.poll() is None:
            p.kill()
    shutil.rmtree(tmp, ignore_errors=True)
