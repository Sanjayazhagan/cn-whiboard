"""Accounts, password hashing, JWT and TLS (no Tkinter needed)."""
import sys, time, socket, ssl, subprocess, os, tempfile, sqlite3, json, base64, hmac, hashlib
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # the project folder
sys.path.insert(0, ROOT)
from protocol import send_msg, recv_msg
from auth import fingerprint, jwt_encode

PORT = 5096
TMP = tempfile.mkdtemp()
DB, CERT, KEY = (os.path.join(TMP, n) for n in ("auth.db", "cert.pem", "key.pem"))


def start():
    p = subprocess.Popen([sys.executable, "server.py", "--port", str(PORT), "--db", DB, "--cert", CERT, "--key", KEY,
                          "--no-discovery"], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    lines = [p.stdout.readline().strip() for _ in range(5)]   # database, accounts, TLS x2, fingerprint
    time.sleep(0.3)
    return p, lines


def tls(first=None):
    raw = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw)
    if first:
        send_msg(s, first)
    return s


def ask(s, msg):
    send_msg(s, msg)
    return recv_msg(s)


def drain(s, t=0.4):
    out = []
    s.settimeout(t)
    try:
        while True:
            out.append(recv_msg(s))
    except (socket.timeout, OSError):
        pass
    return out


def claims(token):
    p = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


srv, lines = start()
print("\n".join(lines))
try:
    assert any("TLS: ON" in l for l in lines), lines
    fp1 = lines[-1].strip()

    # TLS: a plain-TCP client gets nothing; a TLS client sees the fingerprint the server printed
    p = socket.create_connection(("127.0.0.1", PORT), timeout=3)
    send_msg(p, {"type": "LOGIN", "user": "x", "password": "y"})
    try:
        got = recv_msg(p)
    except (ConnectionError, OSError, ValueError):
        got = None
    assert got is None, got
    s = tls()
    assert fingerprint(s.getpeercert(binary_form=True)) == fp1 and s.version() in ("TLSv1.2", "TLSv1.3")
    print("ok  plain TCP refused; TLS works,", s.version(), s.cipher()[0])

    # register / login
    r = ask(s, {"type": "REGISTER", "user": "alice", "password": "s3cret-pw"})
    assert r["type"] == "AUTH_OK" and claims(r["jwt"])["sub"] == "alice", r
    c = claims(r["jwt"]); assert 23 * 3600 < c["exp"] - c["iat"] <= 24 * 3600
    alice_jwt = r["jwt"]
    assert ask(s, {"type": "REGISTER", "user": "ALICE", "password": "other"})["type"] == "AUTH_ERR"
    assert ask(s, {"type": "REGISTER", "user": "x", "password": "longenough"})["type"] == "AUTH_ERR"   # name too short
    assert ask(s, {"type": "LOGIN", "user": "alice", "password": "wrong"})["text"] == "Wrong username or password"
    assert ask(s, {"type": "LOGIN", "user": "nobody", "password": "wrong"})["text"] == "Wrong username or password"
    r = ask(s, {"type": "LOGIN", "user": "Alice", "password": "s3cret-pw"}); assert r["type"] == "AUTH_OK" and r["user"] == "alice"
    print("ok  register, duplicate names refused (case-insensitive), login, same error for unknown user / wrong password")

    time.sleep(0.5)
    con = sqlite3.connect(DB)
    h = con.execute("SELECT pw_hash FROM users WHERE name='alice'").fetchone()[0]
    secret = bytes.fromhex(con.execute("SELECT value FROM meta WHERE key='jwt_secret'").fetchone()[0])
    con.close()
    assert "s3cret-pw" not in h and h.startswith("pbkdf2_sha256$200000$"), h
    print("ok  database stores only the PBKDF2 hash:", h[:40] + "...")

    # joining needs a valid token; the name comes from the token, not from the "user" field
    a = tls({"type": "CREATE_ROOM", "user": "alice", "password": "rpw"}); r = recv_msg(a)
    assert r["type"] == "JOIN_ERR" and r["code"] == "AUTH", r
    a = tls({"type": "CREATE_ROOM", "user": "mallory", "password": "rpw", "jwt": alice_jwt}); j = recv_msg(a)
    assert j["type"] == "JOIN_OK" and j["user"] == "alice" and j["host"] == "alice"
    room = j["room"]
    hdr, pl, sig = alice_jwt.split(".")
    forged_pl = base64.urlsafe_b64encode(json.dumps(dict(claims(alice_jwt), sub="bob")).encode()).rstrip(b"=").decode()
    bad = {
        "edited payload": f"{hdr}.{forged_pl}.{sig}",
        "alg none": base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode() + f".{forged_pl}.",
        "wrong secret": jwt_encode(dict(claims(alice_jwt)), b"guess"),
        "expired": jwt_encode(dict(claims(alice_jwt), exp=int(time.time()) - 1), secret),
    }
    for what, tok in bad.items():
        x = tls({"type": "JOIN_ROOM", "room": room, "password": "rpw", "jwt": tok}); r = recv_msg(x)
        assert r["type"] == "JOIN_ERR" and r["code"] == "AUTH", (what, r)
        print(f"ok  rejected token ({what}): {r['text']}")

    # bob: register, join with the room password; later he reconnects with only his token
    b = tls(); bob_jwt = ask(b, {"type": "REGISTER", "user": "bob", "password": "bobpw"})["jwt"]
    assert ask(b, {"type": "JOIN_ROOM", "room": room, "password": "bad", "jwt": bob_jwt})["text"] == "Wrong room password"
    b = tls(); r = ask(b, {"type": "JOIN_ROOM", "room": room, "password": "rpw", "jwt": bob_jwt})
    assert r["type"] == "JOIN_OK" and r["user"] == "bob"
    send_msg(b, {"type": "ADD", "msg_id": "m1", "obj": {"id": "o1", "kind": "stroke", "color": "#ff0000", "width": 3,
                                                         "points": [[1, 1], [9, 9]]}})
    assert any(m["type"] == "OP" and m["by"] == "bob" for m in drain(a))
    b.close(); time.sleep(0.3)
    b = tls(); r = ask(b, {"type": "JOIN_ROOM", "room": room, "jwt": bob_jwt})
    assert r["type"] == "JOIN_OK", r
    rooms = ask(tls(), {"type": "MY_ROOMS", "jwt": bob_jwt})["rooms"]
    assert [x["code"] for x in rooms] == [room] and rooms[0]["role"] == "editor" and rooms[0]["password"]
    print("ok  room password checked once; rejoin with the token alone; 'your rooms' list:", rooms)

    # restart: accounts, secret and certificate are kept -> old tokens still work, same fingerprint
    srv.terminate(); srv.wait()
    srv, lines = start()
    assert lines[-1].strip() == fp1 and "2 registered" in lines[1], lines
    a = tls({"type": "JOIN_ROOM", "room": room, "jwt": alice_jwt}); assert recv_msg(a)["type"] == "JOIN_OK"
    assert ask(tls(), {"type": "LOGIN", "user": "bob", "password": "bobpw"})["type"] == "AUTH_OK"
    print("ok  after a restart: same certificate, accounts kept, existing JWT still valid")

    # rate limit: 5 failures from one address -> blocked, even with the right password
    s = tls()
    for _ in range(5):
        assert ask(s, {"type": "LOGIN", "user": "bob", "password": "guess"})["type"] == "AUTH_ERR"
    r = ask(s, {"type": "LOGIN", "user": "bob", "password": "bobpw"})
    assert r["type"] == "AUTH_ERR" and "Too many" in r["text"], r
    print("ok  rate limit:", r["text"])
    print("ALL AUTH TESTS PASSED")
finally:
    srv.terminate()
