"""Persistence test: everything survives a server restart (no Tkinter needed)."""
import sys, time, socket, subprocess, os, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # the project folder
sys.path.insert(0, ROOT)
from protocol import send_msg, recv_msg

PORT = 5095
DB = os.path.join(tempfile.mkdtemp(), "test.db")


def start():
    p = subprocess.Popen([sys.executable, "server.py", "--no-auth", "--no-tls", "--port", str(PORT), "--db", DB, "--no-discovery"],
                         cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    first = p.stdout.readline()          # "Database ...: restored N room(s), M op(s)"
    time.sleep(0.5)
    return p, first.strip()


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


def stroke(i):
    return {"type": "ADD", "msg_id": "m" + str(i), "obj": {"id": "o" + str(i), "kind": "stroke", "color": "#ff0000",
                                                            "width": 3, "points": [[i, i], [i + 5, i + 5]]}}


srv, line = start()
print(line)
try:
    a = conn({"type": "CREATE_ROOM", "user": "alice", "password": "pw"}); ja = recv_msg(a); room = ja["room"]
    b = conn({"type": "JOIN_ROOM", "user": "bob", "room": room, "password": "pw"}); jb = recv_msg(b)
    c = conn({"type": "JOIN_ROOM", "user": "carol", "room": room, "password": "pw"}); recv_msg(c)
    for i in range(30):
        send_msg(a if i % 2 else b, stroke(i))
    drain(a)
    send_msg(b, {"type": "ERASE", "msg_id": "e1", "ids": ["o0"]})
    send_msg(a, {"type": "CHAT", "msg_id": "c1", "text": "saved in sqlite"})
    send_msg(a, {"type": "SET_ROLE", "user": "bob", "role": "viewer"})
    send_msg(a, {"type": "VERSION_SAVE", "label": "before restart"})
    send_msg(a, {"type": "KICK", "user": "carol"})
    drain(a, 0.8)
    send_msg(a, {"type": "RESYNC_REQ", "since": 0}); before = [m for m in drain(a) if m["type"] == "OPS_SINCE"][0]["ops"]

    srv.terminate(); srv.wait()                          # stop the server (all rooms are only on disk now)
    srv, line = start()
    print(line)
    assert "restored 1 room(s), 31 op(s)" in line, line

    # alice reconnects with her token: same board, chat, history; seq continues
    a2 = conn({"type": "JOIN_ROOM", "user": "alice", "room": room, "token": ja["token"]}); j = recv_msg(a2)
    assert j["type"] == "JOIN_OK" and j["snapshot"]["seq"] == 31, j.get("text")
    vis = {o["id"]: o["visible"] for o in j["snapshot"]["objects"]}
    assert len(vis) == 30 and vis["o0"] is False and all(vis[f"o{i}"] for i in range(1, 30))
    assert any(m["text"] == "saved in sqlite" for m in j["chat"])
    assert {u["name"]: u["role"] for u in j["users"]} == {"alice": "editor", "bob": "viewer"}
    send_msg(a2, {"type": "RESYNC_REQ", "since": 0}); after = [m for m in drain(a2) if m["type"] == "OPS_SINCE"][0]["ops"]
    assert after == before, "replayed op log differs from the original"
    send_msg(a2, {"type": "VERSIONS_REQ"}); vs = [m for m in drain(a2) if m["type"] == "VERSIONS"][0]["versions"]
    assert any(v["label"] == "before restart" for v in vs), vs
    send_msg(a2, stroke(99)); op = [m for m in drain(a2) if m["type"] == "OP"][0]
    assert op["seq"] == 32
    print("ok  board, op log, chat, roles and versions came back; seq continues at", op["seq"])

    # password and kick survive too; requests resent after the restart are recognised as duplicates
    x = conn({"type": "JOIN_ROOM", "user": "eve", "room": room, "password": "bad"}); assert recv_msg(x)["type"] == "JOIN_ERR"
    k = conn({"type": "JOIN_ROOM", "user": "carol", "room": room, "password": "pw"}); r = recv_msg(k)
    assert r.get("code") == "BANNED", r
    send_msg(a2, stroke(5)); r = drain(a2); assert r == [{"type": "ACK", "msg_id": "m5", "dup": True}], r
    send_msg(a2, {"type": "CHAT", "msg_id": "c1", "text": "saved in sqlite"}); r = drain(a2)
    assert r == [{"type": "ACK", "msg_id": "c1", "dup": True}], r
    print("ok  room password and kick ban were restored; a resent stroke is not drawn twice")

    out = subprocess.run([sys.executable, "db_tool.py", "--db", DB], cwd=ROOT, capture_output=True, text=True).stdout
    print(out); assert room in out
    out = subprocess.run([sys.executable, "db_tool.py", room, "--db", DB], cwd=ROOT, capture_output=True, text=True).stdout
    assert "saved in sqlite" in out and "(kicked)" in out
    print("ALL DB TESTS PASSED")
finally:
    srv.terminate()
