"""GUI tests for: resend of unacknowledged actions after a reconnect, kick (no auto-rejoin),
server restart (room gone -> clear message, back to login), and the LAN discovery list."""
import sys, time, subprocess, os, shutil, socket
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # the project folder
sys.path.insert(0, ROOT)
import client
client.DEFAULT_TLS = False      # these tests use a plain-TCP, no-accounts server
import tkinter.messagebox as mb

PORT = 5094
answers = []                                   # what the "Go back to login?" dialog should answer
mb.askyesno = lambda *a, **k: answers.pop(0) if answers else False
mb.showerror = mb.showwarning = mb.showinfo = lambda *a, **k: None


def start_server():
    return subprocess.Popen([sys.executable, "server.py", "--no-auth", "--no-tls", "--no-db", "--port", str(PORT), "--name", "lab-pc"], cwd=ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def spin(*apps, secs=0.6):
    end = time.time() + secs
    while time.time() < end:
        for a in apps:
            a.update()
        time.sleep(0.01)


class E:
    def __init__(s, x, y): s.x, s.y = x, y


srv = start_server(); time.sleep(1)
try:
    a = client.App(); a.vars["user"].set("alice"); a.vars["port"].set(str(PORT)); spin(a, secs=2)
    a.vars["host"].set("127.0.0.1"); a.start("CREATE_ROOM"); spin(a)
    b = client.App(); b.vars["user"].set("bob"); b.vars["port"].set(str(PORT)); b.vars["room"].set(a.room)
    spin(a, b, secs=2); b.vars["host"].set("127.0.0.1"); b.start("JOIN_ROOM"); spin(a, b)
    assert b.room == a.room

    # 1. bob's connection dies, he keeps drawing; the stroke is sent again after the reconnect
    b.net.sock.shutdown(socket.SHUT_RDWR)          # connection lost (like a cable pulled + reset)
    b.tool = "pen"; b.on_press(E(10, 10)); b.on_drag(E(60, 60)); b.on_release(E(90, 40))
    assert len(b.outbox) == 1
    spin(a, b, secs=5)
    assert not b.reconnecting and not b.outbox and b.resent == 1, (b.reconnecting, b.outbox, b.resent)
    assert any(o["obj"].get("owner") == "bob" for o in a.objs.values()), "resent stroke never reached alice"
    print("ok  stroke drawn while offline was resent after reconnect and reached alice")

    # 2. kick: bob goes offline and does NOT reconnect by himself
    a.net.send({"type": "KICK", "user": "bob"}); spin(a, b, secs=3)
    assert b.offline and not b.reconnecting, (b.offline, b.reconnecting)
    assert "bob" not in [u["name"] for u in a.users]
    assert not b.can_draw()
    print("ok  kicked client stays out:", b.status.cget("text"))
    # (bob is closed at the end)

    # 3. server restart: alice's room is gone -> clear message, then back to the login screen
    srv.terminate(); srv.wait(); srv = start_server(); time.sleep(1)
    answers.append(True)
    spin(a, secs=6)
    assert not hasattr(a, "canvas") and a.login.winfo_exists(), "alice should be back on the login screen"
    assert a.vars["user"].get() == "alice" and a.vars["port"].get() == str(PORT)
    a.vars["host"].set("127.0.0.1"); a.start("CREATE_ROOM"); spin(a)
    assert hasattr(a, "canvas") and a.room
    print("ok  after a server restart alice got a clear message, went back to login and made a new room", a.room)

    # 4. LAN discovery fills the server list (and the IP/port fields) on the login screen
    c = client.App(); c.geometry("+0+0"); spin(c, a, secs=2.5)
    names = c.srv_list.get(0, "end")
    print("    server list:", names)
    assert c.found and any(s["port"] == PORT and s["name"] == "lab-pc" for s in c.found), c.found
    assert c.vars["port"].get() == str(PORT)
    c.vars["user"].set("carol"); c.lift(); c.update(); time.sleep(0.3); c.update()
    if shutil.which("import"):
        geo = f"{c.winfo_width()}x{c.winfo_height()}+{c.winfo_rootx()}+{c.winfo_rooty()}"
        subprocess.run(["import", "-window", "root", "-crop", geo, os.path.join(ROOT, "screenshot_discovery.png")])
    print("ok  discovery found", c.vars["host"].get() + ":" + c.vars["port"].get())
    c.on_close(); a.on_close(); b.on_close()

    # 5. with the database on, a server restart is invisible: the client reconnects into the same room
    srv.terminate(); srv.wait()
    import tempfile
    dbfile = os.path.join(tempfile.mkdtemp(), "gui.db")
    dbsrv = lambda: subprocess.Popen([sys.executable, "server.py", "--no-auth", "--no-tls", "--port", str(PORT), "--db", dbfile],
                                     cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    srv = dbsrv(); time.sleep(1)
    d = client.App(); d.vars["user"].set("dan"); d.vars["port"].set(str(PORT)); spin(d, secs=2)
    d.vars["host"].set("127.0.0.1"); d.start("CREATE_ROOM"); spin(d)
    d.tool = "rect"; d.on_press(E(20, 20)); d.on_drag(E(80, 80)); d.on_release(E(80, 80)); spin(d)
    d.send_reliable({"type": "CHAT", "text": "still here after restart"}); spin(d)
    code = d.room
    srv.terminate(); srv.wait(); srv = dbsrv(); spin(d, secs=6)
    assert hasattr(d, "canvas") and d.room == code and not d.offline and not d.reconnecting
    assert len(d.objs) == 1 and d.reconnects == 1
    assert "still here after restart" in d.chat.get("1.0", "end")
    d.tool = "oval"; d.on_press(E(120, 20)); d.on_drag(E(180, 80)); d.on_release(E(180, 80)); spin(d)
    assert len(d.objs) == 2 and d.last_seq == 2
    print("ok  with the database, the client resumed the same room after a server restart")
    d.on_close()
    print("ALL GUI FIX TESTS PASSED")
finally:
    srv.terminate()
