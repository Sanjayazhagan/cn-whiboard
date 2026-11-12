"""Remote cursors of browser users: a guest's name contains a space ("Sanjay (web)"), which Tk splits into
two canvas tags, so canvas.delete() never matched and every cursor move left a dot behind on the desktop
client. A real GUI client and a WebSocket guest: the guest's cursor stays one dot + label while it moves,
and it disappears when the guest leaves."""
import sys, time, socket, subprocess, os, json, tempfile, base64, struct
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
tmp = tempfile.mkdtemp()
os.environ["WB_KNOWN_SERVERS"] = os.path.join(tmp, "known.json")
import web
import client
client.DEFAULT_TLS = False
import tkinter.messagebox as mb
mb.askyesno = lambda *a, **k: False
mb.showerror = mb.showwarning = mb.showinfo = lambda *a, **k: None

PORT, WEBP = 5112, 8112
GUEST = "Sanjay (web)"


class WS:
    """Minimal WebSocket client (what a browser does)."""
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=5)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += self.s.recv(1)
        assert b"101 Switching Protocols" in head and web.ws_accept(key).encode() in head, head

    def send(self, obj):
        data, mask = json.dumps(obj).encode(), os.urandom(4)
        n = len(data)
        head = struct.pack(">BB", 0x81, 0x80 | n) if n < 126 else struct.pack(">BBH", 0x81, 0x80 | 126, n)
        self.s.sendall(head + mask + bytes(c ^ mask[j % 4] for j, c in enumerate(data)))


def spin(*apps, secs=0.6):
    end = time.time() + secs
    while time.time() < end:
        for a in apps:
            a.update()
        time.sleep(0.01)


def cursor_items(app, user):
    return len(app.canvas.find_withtag(app.cursor_tag(user)))


srv = subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py"), "--no-auth", "--no-tls", "--no-db", "--no-discovery",
                        "--no-voice", "--port", str(PORT), "--web-port", str(WEBP)], cwd=tmp,
                       stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
time.sleep(1.5)
try:
    a = client.App(); a.vars["user"].set("alice"); a.vars["port"].set(str(PORT)); spin(a, secs=1)
    a.vars["host"].set("127.0.0.1"); a.start("CREATE_ROOM"); spin(a)
    assert a.room, "alice did not get a room"

    g = WS(WEBP)
    g.send({"type": "JOIN_ROOM", "user": GUEST, "room": a.room, "password": ""})
    spin(a, secs=1)
    assert any(u["name"] == GUEST and u["online"] for u in a.users), a.users
    before = len(a.canvas.find_all())
    for i in range(15):                          # a phone drawing a shape: cursor moves while the finger is down
        g.send({"type": "CURSOR", "x": 100 + i * 10, "y": 120 + i * 5})
        spin(a, secs=0.08)
    spin(a, secs=0.5)
    left = len(a.canvas.find_all()) - before
    assert left == 2, f"expected one dot + label, found {left} cursor items (old dots left on the canvas)"
    assert cursor_items(a, GUEST) == 2
    x0, y0, _, _ = a.canvas.coords(a.canvas.find_withtag(a.cursor_tag(GUEST))[0])
    assert (x0 + 4, y0 + 4) == (240, 190), "the cursor dot is not at the last position"
    print("PASS guest cursor moves as one dot + label (no trail)")

    g.s.close()                                  # guest leaves: its cursor must go away
    spin(a, secs=2.5)
    assert any(u["name"] == GUEST and not u["online"] for u in a.users), a.users
    assert cursor_items(a, GUEST) == 0, "the guest's cursor stayed after it left"
    print("PASS guest cursor removed when the guest goes offline")
    a.destroy()
    print("ALL CURSOR TESTS PASSED")
finally:
    srv.terminate()
