"""Select-and-drag (MOVE op): socket-level server rules, then two real GUI clients and a browser guest.

Server: a MOVE shifts objects for everyone as one sequenced op; viewers and bad requests are refused;
undo / redo move back and forth; the op log keeps the original ADD (replay stays exact); a restart rebuilds
moved positions from the database. GUI: bob drags alice's rectangle and image with the Select tool, both
boards agree, undo moves it back; an end-to-end encrypted object moves too; the browser guest sees it."""
import sys, time, socket, subprocess, os, json, shutil, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from protocol import send_msg, recv_msg
tmp = tempfile.mkdtemp()
os.environ["WB_KNOWN_SERVERS"] = os.path.join(tmp, "known.json")
import web, base64, struct

PORT, WEBP, PORT2 = 5106, 8106, 5107


def server(port, *extra):
    return subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py"), "--no-auth", "--no-tls", "--no-discovery",
                             "--port", str(port), *extra], cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def conn(first, port=PORT):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
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


def ops(msgs):
    return [m for m in msgs if m["type"] == "OP"]


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


procs = []
try:
    # ------------------------------------------------------------ 1. server rules
    p = server(PORT, "--web-port", str(WEBP), "--db", "move.db"); procs.append(p)
    time.sleep(2)
    a = conn({"type": "CREATE_ROOM", "user": "alice", "password": ""}); ja = recv_msg(a); room = ja["room"]
    b = conn({"type": "JOIN_ROOM", "user": "bob", "room": room, "password": ""}); drain(b)
    v = conn({"type": "JOIN_ROOM", "user": "viv", "room": room, "password": ""}); drain(v); drain(a)
    send_msg(a, {"type": "SET_ROLE", "user": "viv", "role": "viewer"}); drain(a); drain(v)
    send_msg(a, {"type": "ADD", "msg_id": "a1", "obj": {"id": "r1", "kind": "rect", "color": "#ff0000", "width": 2,
                                                        "points": [[10, 10], [60, 40]]}})
    drain(a); drain(b)
    send_msg(b, {"type": "MOVE", "msg_id": "b1", "ids": ["r1"], "dx": 100, "dy": 50})       # anyone may move
    got = drain(b)
    mv = ops(got)[0]
    assert mv["op"] == "MOVE" and mv["ids"] == ["r1"] and (mv["dx"], mv["dy"]) == (100, 50) and mv["by"] == "bob", got
    assert any(m["type"] == "ACK" and m["msg_id"] == "b1" for m in got)
    assert ops(drain(a))[0]["seq"] == mv["seq"] == 2
    for bad in ({"ids": ["r1"], "dx": 0, "dy": 0}, {"ids": ["nope"], "dx": 5, "dy": 5},
                {"ids": ["r1"], "dx": "x", "dy": 1}, {"ids": ["r1"], "dx": 1e9, "dy": 1},
                {"ids": ["r1"], "dx": float("inf"), "dy": 1}):
        send_msg(b, {"type": "MOVE", **bad}); assert not ops(drain(b, 0.25)), bad
    drain(v); send_msg(v, {"type": "MOVE", "ids": ["r1"], "dx": 5, "dy": 5}); assert not ops(drain(v, 0.25))
    print("ok  MOVE: any editor moves any object as ONE sequenced op; viewers, zero / huge / bad shifts refused")

    send_msg(b, {"type": "UNDO", "msg_id": "b2"}); u = ops(drain(b))[0]
    assert u["op"] == "MOVE" and (u["dx"], u["dy"]) == (-100, -50), u
    send_msg(b, {"type": "REDO", "msg_id": "b3"}); r = ops(drain(b))[0]
    assert (r["dx"], r["dy"]) == (100, 50), r
    drain(a); send_msg(a, {"type": "UNDO", "msg_id": "a2"}); u = ops(drain(a))[0]      # alice's own undo: her ADD, not bob's move
    assert u["op"] == "VIS" and u["visible"] is False
    send_msg(a, {"type": "REDO", "msg_id": "a3"}); drain(a); drain(b)
    send_msg(b, {"type": "RESYNC_REQ", "since": 0}); snap = [m for m in drain(b) if m["type"] in ("OPS_SINCE", "SNAPSHOT")][0]
    send_msg(b, {"type": "REPLAY_REQ"}); log = [m for m in drain(b) if m["type"] == "REPLAY"][0]["ops"]
    assert log[0]["op"] == "ADD" and log[0]["obj"]["points"] == [[10, 10], [60, 40]], log[0]   # log keeps the original
    assert [o["op"] for o in log] == ["ADD", "MOVE", "MOVE", "MOVE", "VIS", "VIS"]
    print("ok  undo / redo of a move shifts back / again; the op log keeps the original ADD, so replay stays exact")

    # restart from the database: the moved position survives
    for s in (a, b, v):
        s.close()
    p.terminate(); p.wait()
    p = server(PORT, "--web-port", str(WEBP), "--db", "move.db"); procs.append(p)
    time.sleep(2)
    a = conn({"type": "JOIN_ROOM", "user": "alice", "room": room, "token": ja["token"]})
    j = [m for m in drain(a, 1) if m["type"] == "JOIN_OK"]
    assert j, "rejoin after restart failed"
    j = j[0]
    o = [x for x in j["snapshot"]["objects"] if x["id"] == "r1"][0]
    assert o["points"] == [[110, 60], [160, 90]] and o["visible"], o
    print("ok  server restart: the room is rebuilt from the database with the object at its moved position")

    # browser guest sees moves (same JSON over WebSocket)
    send_msg(a, {"type": "INVITE_REQ"}); inv = [m for m in drain(a) if m["type"] == "INVITE"][0]
    w = WS(WEBP); w.send({"type": "JOIN_ROOM", "user": "phone", "invite": inv["invite"]}); w.recv()
    w.send({"type": "MOVE", "msg_id": "w1", "rn": 1, "ids": ["r1"], "dx": -10, "dy": 0})
    assert [m["type"] for m in w.drain() if m["type"] in ("OP", "ACK")] == ["OP", "ACK"]
    assert ops(drain(a))[0]["by"] == "phone (web)"
    print("ok  a browser guest moves objects over WebSocket too")
    a.close(); p.terminate(); p.wait()

    # ------------------------------------------------------------ 2. GUI: drag with the Select tool
    import client
    import tkinter.messagebox as mb
    mb.askyesno = lambda *a, **k: False
    mb.showerror = mb.showwarning = mb.showinfo = lambda *a, **k: None
    client.DEFAULT_TLS = False
    p = server(PORT2, "--no-web", "--no-db"); procs.append(p)
    time.sleep(2)

    def spin(*apps, secs=0.6, until=None):
        end = time.time() + secs
        while time.time() < end:
            for x in apps:
                x.update()
            if until and until():
                return True
            time.sleep(0.01)
        return until is None

    class E:
        def __init__(s, x, y): s.x, s.y = x, y

    def drag(app, x0, y0, x1, y1):
        app.tool_var.set("select"); app.set_tool()
        app.on_press(E(x0, y0))
        for k in range(1, 6):
            app.on_drag(E(x0 + (x1 - x0) * k // 5, y0 + (y1 - y0) * k // 5))
        app.on_release(E(x1, y1))

    ga = client.App(); ga.use_tls = False
    ga.vars["user"].set("alice"); ga.vars["port"].set(str(PORT2)); ga.vars["host"].set("127.0.0.1")
    ga.start("CREATE_ROOM"); spin(ga, secs=5, until=lambda: ga.room)
    gb = client.App(); gb.use_tls = False
    gb.vars["user"].set("bob"); gb.vars["port"].set(str(PORT2)); gb.vars["host"].set("127.0.0.1")
    gb.vars["room"].set(ga.room); gb.start("JOIN_ROOM"); spin(ga, gb, secs=5, until=lambda: gb.room)
    assert ga.room and gb.room == ga.room

    ga.tool = "rect"; ga.on_press(E(100, 100)); ga.on_drag(E(200, 160)); ga.on_release(E(200, 160))
    spin(ga, gb, secs=3, until=lambda: len(gb.objs) == 1)
    rid = next(iter(gb.objs))
    drag(gb, 100, 130, 400, 330)                     # grab the rectangle's left edge, move it by (300, 200)
    assert gb.canvas.coords("o_" + rid)[:2] == [400.0, 300.0]       # local preview while waiting for the server
    spin(ga, gb, secs=3, until=lambda: ga.last_seq == gb.last_seq == 2 and not gb.outbox)
    for g in (ga, gb):
        assert g.objs[rid]["obj"]["points"] == [[400, 300], [500, 360]], g.objs[rid]
        assert g.canvas.coords("o_" + rid) == [400.0, 300.0, 500.0, 360.0], g.canvas.coords("o_" + rid)
    print("ok  GUI: bob dragged alice's rectangle with the Select tool; both boards show it at the new position")

    gb.send_reliable({"type": "UNDO"})
    spin(ga, gb, secs=3, until=lambda: ga.last_seq == 3)
    assert ga.canvas.coords("o_" + rid) == [100.0, 100.0, 200.0, 160.0]
    drag(gb, 600, 600, 700, 600)                     # empty spot: nothing selected, nothing sent
    spin(ga, gb, secs=0.5); assert ga.last_seq == 3 and not gb.outbox
    print("ok  GUI: undo moves it back for everyone; dragging empty space does nothing")

    # an image: the reason this tool exists
    import base64, zlib, struct as st

    def png(w, h):
        raw = b"".join(b"\x00" + b"\xff\x00\x00" * w for _ in range(h))
        chunk = lambda t, d: st.pack(">I", len(d)) + t + d + st.pack(">I", zlib.crc32(t + d) & 0xffffffff)
        return base64.b64encode(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", st.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                                + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")).decode()
    ga.send_reliable({"type": "ADD", "obj": {"id": "img1", "kind": "image", "color": "#000000", "width": 1,
                                             "points": [[300, 50]], "data": png(40, 30), "w": 40, "h": 30}})
    spin(ga, gb, secs=3, until=lambda: "img1" in gb.objs)
    drag(ga, 320, 65, 520, 465)
    spin(ga, gb, secs=3, until=lambda: gb.objs["img1"]["obj"]["points"] == [[500, 450]])
    assert gb.canvas.coords("o_img1") == [500.0, 450.0] and ga.canvas.coords("o_img1") == [500.0, 450.0]
    print("ok  GUI: an inserted image is dragged to a new spot and moves on the other board too")

    # end-to-end encrypted object: the server only shifts its offset, the clients shift the decrypted shape
    ga.set_e2e("pw"); gb.set_e2e("pw")
    ga.tool = "rect"; ga.on_press(E(50, 400)); ga.on_drag(E(90, 440)); ga.on_release(E(90, 440))
    spin(ga, gb, secs=3, until=lambda: len(gb.objs) == 3)
    eid = [i for i in gb.objs if i not in (rid, "img1")][0]
    drag(gb, 50, 420, 150, 520)
    spin(ga, gb, secs=3, until=lambda: ga.objs[eid]["obj"]["points"] == [[150, 500], [190, 540]])
    gc = client.App(); gc.use_tls = False            # joins later, gets the moved ciphertext in the snapshot
    gc.vars["user"].set("carol"); gc.vars["port"].set(str(PORT2)); gc.vars["host"].set("127.0.0.1")
    gc.vars["room"].set(ga.room); gc.start("JOIN_ROOM"); spin(gc, secs=5, until=lambda: gc.room)
    assert gc.objs[eid]["obj"]["kind"] == "enc"
    gc.set_e2e("pw")
    assert gc.objs[eid]["obj"]["points"] == [[150, 500], [190, 540]], gc.objs[eid]
    print("ok  GUI: an end-to-end encrypted rectangle moves too; a late joiner decrypts it at the moved position")

    ga.open_replay(); spin(ga, secs=3, until=lambda: ga.replaywin is not None)
    assert ga.rp_canvas.coords("o_" + rid) == [100.0, 100.0, 200.0, 160.0]
    assert ga.rp_canvas.coords("o_img1") == [500.0, 450.0]
    ga.rp_goto(2); assert ga.rp_canvas.coords("o_" + rid) == [400.0, 300.0, 500.0, 360.0]
    assert "moved 1 object" in ga.rp_label.cget("text")
    print("ok  replay shows each move step by step")
    print("ALL MOVE TESTS PASSED")
finally:
    for p in procs:
        if p.poll() is None:
            p.kill()
    shutil.rmtree(tmp, ignore_errors=True)
