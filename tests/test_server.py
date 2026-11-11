import sys, time, socket, threading, subprocess, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # the project folder
sys.path.insert(0, ROOT)
from protocol import send_msg, recv_msg

srv = subprocess.Popen([sys.executable, "server.py", "--no-auth", "--no-tls", "--no-db", "--port", "5077"], cwd=ROOT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
time.sleep(1)

def conn(first):
    s = socket.create_connection(("127.0.0.1", 5077), timeout=3)
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

def stroke(i, pts=[[1, 1], [5, 5]]):
    return {"type": "ADD", "msg_id": "m" + i, "obj": {"id": "o" + i, "kind": "stroke", "color": "#ff0000", "width": 3, "points": pts}}

a = conn({"type": "CREATE_ROOM", "user": "alice", "password": "pw"})
ok = recv_msg(a); assert ok["type"] == "JOIN_OK", ok
room = ok["room"]; print("room", room, "host", ok["host"])
# wrong password / unknown room / duplicate name
b = conn({"type": "JOIN_ROOM", "user": "bob", "room": room, "password": "bad"}); assert recv_msg(b)["type"] == "JOIN_ERR"
b = conn({"type": "JOIN_ROOM", "user": "alice", "room": room, "password": "pw"}); assert recv_msg(b)["text"] == "Username already taken"
b = conn({"type": "JOIN_ROOM", "user": "bob", "room": "ZZZZZ", "password": "pw"}); assert recv_msg(b)["text"] == "No such room"
b = conn({"type": "JOIN_ROOM", "user": "bob", "room": room, "password": "pw"}); jb = recv_msg(b); assert jb["type"] == "JOIN_OK"
btok = jb["token"]
drain(a); drain(b)

# concurrent drawing from both clients
def spam(s, tag):
    for i in range(50):
        send_msg(s, stroke(f"{tag}{i}"))
ts = [threading.Thread(target=spam, args=(a, "a")), threading.Thread(target=spam, args=(b, "b"))]
[t.start() for t in ts]; [t.join() for t in ts]
ma, mb = drain(a, 1), drain(b, 1)
opsa = [m for m in ma if m["type"] == "OP"]; opsb = [m for m in mb if m["type"] == "OP"]
assert len(opsa) == len(opsb) == 100, (len(opsa), len(opsb))
assert [o["seq"] for o in opsa] == list(range(1, 101)) == [o["seq"] for o in opsb]
assert [o["obj"]["id"] for o in opsa] == [o["obj"]["id"] for o in opsb]   # same total order
print("concurrent: 100 ops, identical order on both clients")

# duplicate msg_id ignored
send_msg(a, stroke("a0")); assert not [m for m in drain(a) if m["type"] == "OP"]
# undo only touches own work
send_msg(b, {"type": "UNDO"}); u = [m for m in drain(a) if m["type"] == "OP"]
assert len(u) == 1 and u[0]["ids"] == ["ob49"] and u[0]["visible"] is False, u
send_msg(b, {"type": "REDO"}); r = [m for m in drain(a) if m["type"] == "OP"]; assert r[0]["visible"] is True
# non-host cannot clear
send_msg(b, {"type": "CLEAR"}); assert not [m for m in drain(a) if m["type"] == "OP"]
# viewer role blocks drawing
send_msg(a, {"type": "SET_ROLE", "user": "bob", "role": "viewer"}); drain(b)
send_msg(b, stroke("zz")); assert not [m for m in drain(a) if m["type"] == "OP"]
send_msg(a, {"type": "SET_ROLE", "user": "bob", "role": "editor"}); drain(b); drain(a)
# invalid object rejected
bad = stroke("bad"); bad["obj"]["color"] = "red"; send_msg(b, bad); assert not [m for m in drain(a) if m["type"] == "OP"]
# chat
send_msg(a, {"type": "CHAT", "text": "hello"}); c = [m for m in drain(b) if m["type"] == "CHAT"]; assert c[0]["user"] == "alice"
# host clears
send_msg(a, {"type": "CLEAR"}); cl = [m for m in drain(b) if m["type"] == "OP"]; assert cl and not cl[0]["visible"]

# reconnect: bob drops, alice draws, bob returns with token -> gets full current state
b.close(); time.sleep(0.3)
users = [m for m in drain(a) if m["type"] == "USERS"][-1]["users"]; assert not next(u for u in users if u["name"] == "bob")["online"]
send_msg(a, stroke("late"))
b2 = conn({"type": "JOIN_ROOM", "user": "bob", "room": room, "token": btok}); jb2 = recv_msg(b2)
assert jb2["type"] == "JOIN_OK" and jb2["snapshot"]["seq"] == 104
assert any(o["id"] == "olate" and o["visible"] for o in jb2["snapshot"]["objects"])
# gap resync
send_msg(b2, {"type": "RESYNC_REQ", "since": 100}); r = [m for m in drain(b2) if m["type"] == "OPS_SINCE"]
assert len(r[0]["ops"]) == jb2["snapshot"]["seq"] - 100
# heartbeat
send_msg(a, {"type": "PING"}); assert any(m["type"] == "PONG" for m in drain(a))
print("ALL SERVER TESTS PASSED")
srv.terminate()
