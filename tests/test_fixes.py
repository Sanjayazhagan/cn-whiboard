"""Socket-level tests for: kick ban, image budget / big snapshots, slow client isolation,
ACK + duplicate re-ACK, and UDP LAN discovery. No Tkinter needed."""
import sys, time, socket, subprocess, os, json
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # the project folder
sys.path.insert(0, ROOT)
from protocol import send_msg, recv_msg, recv_msg_ex, DISCOVER_MAGIC

PORT, UDP = 5093, 5193
srv = subprocess.Popen([sys.executable, "server.py", "--no-auth", "--no-tls", "--no-db", "--port", str(PORT), "--discovery-port", str(UDP),
                        "--name", "test-server"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
time.sleep(1)


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


def image(i, size=690_000):
    return {"type": "ADD", "msg_id": "img" + str(i), "obj": {"id": "img" + str(i), "kind": "image", "color": "#000000",
            "width": 1, "points": [[0, 0]], "data": "A" * size, "w": 10, "h": 10}}


try:
    a = conn({"type": "CREATE_ROOM", "user": "alice"}); room = recv_msg(a)["room"]
    b = conn({"type": "JOIN_ROOM", "user": "bob", "room": room}); tok = recv_msg(b)["token"]
    drain(a)

    # 1. ACK and duplicate re-ACK
    send_msg(a, {"type": "ADD", "msg_id": "x1", "obj": {"id": "s1", "kind": "stroke", "color": "#ff0000",
                                                         "width": 3, "points": [[1, 1], [9, 9]]}})
    got = drain(a)
    assert [m["type"] for m in got] == ["OP", "ACK"] and got[1]["msg_id"] == "x1", got
    send_msg(a, {"type": "ADD", "msg_id": "x1", "obj": {"id": "s1", "kind": "stroke", "color": "#ff0000",
                                                         "width": 3, "points": [[1, 1], [9, 9]]}})
    got = drain(a)
    assert got == [{"type": "ACK", "msg_id": "x1", "dup": True}], got
    print("ok  ACK, and a resent duplicate is ACKed again but not applied twice")

    # 2. kick really removes the user: the saved token no longer works
    drain(b)
    send_msg(a, {"type": "KICK", "user": "bob"})
    kb = drain(b)
    assert kb and kb[0]["type"] == "KICKED", kb
    users = [m for m in drain(a) if m["type"] == "USERS"][-1]["users"]
    assert "bob" not in [u["name"] for u in users]
    b2 = conn({"type": "JOIN_ROOM", "user": "bob", "room": room, "token": tok}); r = recv_msg(b2)
    assert r["type"] == "JOIN_ERR" and r["code"] == "BANNED", r
    print("ok  kicked user cannot come back with its token:", r["text"])

    # 3. slow client: 'slow' joins and never reads. alice keeps drawing big images; others must not stall.
    slow = conn({"type": "JOIN_ROOM", "user": "slow", "room": room})
    slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    t0 = time.time()
    for i in range(12):                       # ~8 MB pushed towards a client that reads nothing
        send_msg(a, image(i))
    drain(a, 1.5)
    c = conn({"type": "JOIN_ROOM", "user": "carol", "room": room})
    c.settimeout(5)
    m, n = recv_msg_ex(c)
    took = time.time() - t0
    assert m["type"] == "JOIN_OK" and took < 5, (m["type"], took)
    print(f"ok  room keeps working while one client is stalled (carol joined in {took:.1f}s, snapshot {n/1e6:.1f} MB)")

    # 4. image budget: a room never holds more than 20 MB of images, so snapshots stay under MAX_MSG
    errs = []
    for i in range(12, 32):
        send_msg(a, image(i))
        errs += [x for x in drain(a, 0.15) if x["type"] == "ERROR"]
    assert errs and "MB of images" in errs[0]["text"], errs
    d = conn({"type": "JOIN_ROOM", "user": "dave", "room": room}); d.settimeout(10)
    m, n = recv_msg_ex(d)
    assert m["type"] == "JOIN_OK" and n < 32 * 1024 * 1024
    print(f"ok  image limit enforced ({errs[0]['text']!r}); new joiner snapshot {n/1e6:.1f} MB")

    # 5. UDP discovery (unicast to localhost here; real clients broadcast)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(2)
    u.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    u.sendto(DISCOVER_MAGIC, ("127.0.0.1", UDP))
    info = json.loads(u.recvfrom(2048)[0])
    assert info["type"] == "WB_SERVER" and info["port"] == PORT and info["name"] == "test-server", info
    print("ok  discovery reply:", info)
    try:
        u.sendto(DISCOVER_MAGIC, ("255.255.255.255", UDP))
        info = json.loads(u.recvfrom(2048)[0]); print("ok  discovery via broadcast also answered")
    except OSError as e:
        print("--  broadcast not available in this environment:", e)
    print("ALL FIX TESTS PASSED")
finally:
    srv.terminate()
