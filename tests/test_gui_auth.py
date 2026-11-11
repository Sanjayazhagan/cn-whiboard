"""GUI test: register / login / JWT join over TLS, trust-on-first-use certificate check, reconnect with the
token, and the warning when the server certificate changes."""
import sys, time, subprocess, os, shutil, socket, tempfile, json
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # the project folder
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp()
os.environ["WB_KNOWN_SERVERS"] = os.path.join(TMP, "known.json")
import client
import tkinter.messagebox as mb

PORT, PLAIN_PORT = 5097, 5098
DB, CERT, KEY = (os.path.join(TMP, n) for n in ("gui.db", "cert.pem", "key.pem"))
answers, errors = [], []
mb.askyesno = lambda title, *a, **k: answers.pop(0) if answers else False
mb.showerror = lambda title, text="", **k: errors.append(text)
mb.showwarning = mb.showinfo = lambda *a, **k: None


def start_server(*extra, port=PORT):
    return subprocess.Popen([sys.executable, "server.py", "--port", str(port), "--db", DB, "--cert", CERT, "--key", KEY,
                             "--no-discovery", *extra], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def spin(*apps, secs=0.6):
    end = time.time() + secs
    while time.time() < end:
        for a in apps:
            a.update()
        time.sleep(0.01)


def app(user, pw):
    a = client.App()
    for k, v in dict(host="127.0.0.1", port=str(PORT), user=user, apw=pw).items():
        a.vars[k].set(v)
    return a


def shot(w, name):
    if shutil.which("import"):
        w.lift(); w.update(); time.sleep(0.3); w.update()
        geo = f"{w.winfo_width()}x{w.winfo_height()}+{w.winfo_rootx()}+{w.winfo_rooty()}"
        subprocess.run(["import", "-window", "root", "-crop", geo, os.path.join(ROOT, name)])


class E:
    def __init__(s, x, y): s.x, s.y = x, y


srv = start_server(); time.sleep(1.5)
plain = start_server("--no-tls", "--no-auth", "--no-db", port=PLAIN_PORT); time.sleep(0.5)
try:
    # alice registers (first TLS connection: certificate is remembered), then creates a room
    a = app("alice", "alice-pw"); a.geometry("+0+0"); spin(a, secs=1.5)
    a.vars["host"].set("127.0.0.1"); a.vars["port"].set(str(PORT)); a.tls_var.set(True)
    a.auth("REGISTER"); spin(a, secs=1.5)
    assert a.jwt and a.jwt_user == "alice" and a.vars["apw"].get() == "", (a.jwt, errors)
    known = json.load(open(os.environ["WB_KNOWN_SERVERS"]))
    assert known[f"127.0.0.1:{PORT}"] == a.net.tls_info[2]
    print("ok  registered; token received, password field cleared; certificate pinned", a.net.tls_info[:2])
    a.vars["pw"].set("roompw"); a.start("CREATE_ROOM"); spin(a)
    assert hasattr(a, "canvas") and "encrypted" in a.sec_label.cget("text"), a.sec_label.cget("text")
    room = a.room

    # bob registers in one window; in a second window he just types name+password and clicks Join
    b0 = app("bob", "bob-pw"); b0.vars["port"].set(str(PORT)); b0.tls_var.set(True); spin(b0, secs=1.5)
    b0.vars["host"].set("127.0.0.1"); b0.vars["port"].set(str(PORT)); b0.tls_var.set(True)
    b0.auth("REGISTER"); spin(b0, secs=1.5); assert b0.jwt; b0.on_close()
    b = app("bob", "bob-pw"); b.geometry("+0+760"); spin(b, a, secs=1.5)
    b.vars["host"].set("127.0.0.1"); b.vars["port"].set(str(PORT)); b.tls_var.set(True)
    b.vars["room"].set(room); b.vars["pw"].set("roompw")
    b.start("JOIN_ROOM"); spin(a, b, secs=2)
    assert hasattr(b, "canvas") and b.room == room and b.me == "bob", errors
    b.tool = "pen"; b.on_press(E(30, 30)); b.on_drag(E(90, 60)); b.on_release(E(120, 40)); spin(a, b)
    assert any(o["obj"]["owner"] == "bob" for o in a.objs.values())
    print("ok  bob logged in + joined in one click; his drawing reached alice over TLS")

    # reconnect after a network error uses the token (no password needed)
    b.net.sock.shutdown(socket.SHUT_RDWR); spin(a, b, secs=4)
    assert not b.reconnecting and b.reconnects == 1 and b.room == room
    a.open_network(); spin(a, b)
    txt = a.net_text.get("1.0", "end"); assert "SECURITY" in txt and "fingerprint" in txt and "logged in as alice" in txt
    a.chat_entry.insert(0, "everything here is encrypted"); a.send_chat(None); spin(a, b)
    shot(a, "screenshot_secure.png")
    a.netwin.destroy()
    print("ok  reconnect over TLS with the JWT; Network window shows TLS version, cipher and fingerprint")

    # a client with 'Encrypted' ticked against a plain server gets a clear message
    c = app("carol", ""); spin(c, secs=1.5)
    c.vars["host"].set("127.0.0.1"); c.vars["port"].set(str(PLAIN_PORT)); c.tls_var.set(True)
    c.start("CREATE_ROOM"); spin(c)
    assert errors and "untick 'Encrypted connection'" in errors[-1], errors
    c.tls_var.set(False); c.start("CREATE_ROOM"); spin(c)
    assert hasattr(c, "canvas") and "not encrypted" in c.sec_label.cget("text")
    c.on_close()
    print("ok  TLS/plain mismatch explained; --no-auth --no-tls server still works (marked 'not encrypted')")

    # the server gets a NEW certificate: automatic reconnect refuses it (possible man-in-the-middle)
    srv.terminate(); srv.wait(); os.remove(CERT); os.remove(KEY)
    srv = start_server(); answers.append(False)                 # "go back to login?" -> no
    spin(a, b, secs=6)
    assert b.offline and "certificate changed" in b.status.cget("text"), b.status.cget("text")
    print("ok  changed certificate stopped the auto-reconnect:", b.status.cget("text")[:70], "...")
    answers.append(True)                                        # warning dialog: trust the new certificate
    b.back_to_login(); spin(b, secs=2)
    assert [r["code"] for r in b.my_rooms] == [room] and b.jwt, (b.my_rooms, errors)
    b.geometry("+0+0"); shot(b, "screenshot_login.png")
    print("ok  after accepting the new certificate, the login screen shows bob's rooms:", b.my_rooms)
    a.on_close(); b.on_close()
    print("ALL GUI AUTH TESTS PASSED")
finally:
    srv.terminate(); plain.terminate()
