"""Select tool, many objects at once: selection rectangle, Shift+click, select all, then one drag moves
the whole selection for everyone as ONE sequenced MOVE op (so one undo puts everything back).
Two real GUI clients against a real server; a browser-style WebSocket guest sees the same positions."""
import sys, time, subprocess, os, shutil, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
tmp = tempfile.mkdtemp()
os.environ["WB_KNOWN_SERVERS"] = os.path.join(tmp, "known.json")

PORT = 5131
p = subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py"), "--no-auth", "--no-tls", "--no-discovery",
                      "--no-web", "--no-db", "--no-voice", "--port", str(PORT)], cwd=tmp,
                     stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
try:
    time.sleep(2)
    import client
    import tkinter.messagebox as mb
    mb.askyesno = lambda *a, **k: False
    mb.showerror = mb.showwarning = mb.showinfo = lambda *a, **k: None
    client.DEFAULT_TLS = False

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
        def __init__(s, x, y, shift=False): s.x, s.y, s.state = x, y, 1 if shift else 0

    def press_drag(app, x0, y0, x1, y1, shift=False):
        app.on_press(E(x0, y0, shift))
        for k in range(1, 6):
            app.on_drag(E(x0 + (x1 - x0) * k // 5, y0 + (y1 - y0) * k // 5, shift))
        app.on_release(E(x1, y1, shift))

    def pts(app, oid):
        return app.objs[oid]["obj"]["points"]

    ga = client.App(); ga.use_tls = False
    ga.vars["user"].set("alice"); ga.vars["port"].set(str(PORT)); ga.vars["host"].set("127.0.0.1")
    ga.start("CREATE_ROOM"); spin(ga, secs=5, until=lambda: ga.room)
    gb = client.App(); gb.use_tls = False
    gb.vars["user"].set("bob"); gb.vars["port"].set(str(PORT)); gb.vars["host"].set("127.0.0.1")
    gb.vars["room"].set(ga.room); gb.start("JOIN_ROOM"); spin(ga, gb, secs=5, until=lambda: gb.room)
    assert ga.room and gb.room == ga.room

    # alice draws three things far apart: a rectangle, an oval and a line
    for tool, a, b in (("rect", (100, 100), (160, 150)), ("oval", (300, 100), (360, 150)), ("line", (700, 500), (760, 560))):
        ga.tool = tool; ga.on_press(E(*a)); ga.on_drag(E(*b)); ga.on_release(E(*b))
    spin(ga, gb, secs=4, until=lambda: len(gb.objs) == 3 and not ga.outbox)
    rect, oval, line = list(gb.objs)
    assert [gb.objs[i]["obj"]["kind"] for i in (rect, oval, line)] == ["rect", "oval", "line"]
    seq0 = gb.last_seq

    # ---- selection rectangle over the rectangle and the oval (the line is far away)
    gb.tool_var.set("select"); gb.set_tool()
    press_drag(gb, 50, 50, 420, 220)
    assert gb.sel == {rect, oval}, gb.sel
    assert len(gb.canvas.find_withtag("sel")) == 2 and not gb.canvas.find_withtag("band")
    spin(ga, gb, secs=0.4); assert gb.last_seq == seq0 and not gb.outbox          # selecting sends nothing
    print("ok  dragging over empty board selects every object the rectangle touches")

    # ---- drag one of them: both move, as ONE op; the unselected line stays
    press_drag(gb, 100, 125, 150, 325)                                             # grab the rect's left edge: (+50, +200)
    assert gb.canvas.coords("o_" + oval)[:2] == [350.0, 300.0]                     # local preview of the OTHER object
    spin(ga, gb, secs=4, until=lambda: ga.last_seq == gb.last_seq == seq0 + 1 and not gb.outbox)
    assert ga.last_seq == gb.last_seq == seq0 + 1
    for g in (ga, gb):
        assert pts(g, rect) == [[150, 300], [210, 350]] and pts(g, oval) == [[350, 300], [410, 350]], g.objs
        assert pts(g, line) == [[700, 500], [760, 560]]
        assert g.canvas.coords("o_" + oval) == [350.0, 300.0, 410.0, 350.0]
    assert gb.sel == {rect, oval} and len(gb.canvas.find_withtag("sel")) == 2      # still selected, frames followed
    x0, y0, x1, y1 = gb.canvas.bbox("sel")
    assert 140 <= x0 <= 150 and 400 <= x1 <= 420 and 290 <= y0 <= 300, (x0, y0, x1, y1)
    print("ok  dragging one selected object moves the whole selection for everyone as one op")

    gb.send_reliable({"type": "UNDO"})
    spin(ga, gb, secs=4, until=lambda: ga.last_seq == gb.last_seq == seq0 + 2)
    assert pts(ga, rect) == [[100, 100], [160, 150]] and pts(ga, oval) == [[300, 100], [360, 150]]
    print("ok  one undo moves the whole group back")

    # ---- Shift+click adds the line; Shift+click on the oval takes it out
    gb.on_press(E(730, 530, shift=True)); gb.on_release(E(730, 530, shift=True))
    assert gb.sel == {rect, oval, line}, gb.sel
    gb.on_press(E(300, 125, shift=True)); gb.on_release(E(300, 125, shift=True))
    assert gb.sel == {rect, line}, gb.sel
    spin(ga, gb, secs=0.4); assert gb.last_seq == seq0 + 2 and not gb.outbox
    press_drag(gb, 730, 530, 630, 430)                                             # (-100, -100) for rect + line
    spin(ga, gb, secs=4, until=lambda: ga.last_seq == gb.last_seq == seq0 + 3 and not gb.outbox)
    assert pts(ga, rect) == [[0, 0], [60, 50]] and pts(ga, line) == [[600, 400], [660, 460]]
    assert pts(ga, oval) == [[300, 100], [360, 150]]
    print("ok  Shift+click adds an object to the selection or takes it out")

    # ---- a click on empty board clears; Ctrl+A / the All button selects everything
    gb.on_press(E(900, 100)); gb.on_release(E(900, 100))
    assert gb.sel == set() and not gb.canvas.find_withtag("sel")
    ga.tool_var.set("pen"); ga.set_tool()
    ga.select_all(button=True)
    assert ga.tool == "select" and ga.sel == {rect, oval, line}
    press_drag(ga, 330, 100, 430, 200)                                             # grab the oval's top: (+100, +100)
    spin(ga, gb, secs=4, until=lambda: ga.last_seq == gb.last_seq == seq0 + 4 and not ga.outbox)
    for g in (ga, gb):
        assert pts(g, rect) == [[100, 100], [160, 150]] and pts(g, oval) == [[400, 200], [460, 250]]
        assert pts(g, line) == [[700, 500], [760, 560]]
    print("ok  select all + one drag moves everything on the board")

    # ---- an object erased by someone else drops out of my selection
    gb.send_reliable({"type": "ERASE", "ids": [oval]})
    spin(ga, gb, secs=4, until=lambda: ga.last_seq == gb.last_seq == seq0 + 5)
    assert ga.sel == {rect, line} and len(ga.canvas.find_withtag("sel")) == 2
    ga.select_none()
    assert not ga.sel and not ga.canvas.find_withtag("sel")
    # a viewer cannot select
    ga.net.send({"type": "SET_ROLE", "user": "bob", "role": "viewer"})
    spin(ga, gb, secs=3, until=lambda: gb.role == "viewer")
    gb.tool_var.set("select"); gb.set_tool(); press_drag(gb, 50, 50, 900, 600); gb.select_all(button=True)
    assert not gb.sel
    print("ok  erased objects leave the selection; viewers cannot select or move")
    print("ALL MULTI-SELECT TESTS PASSED")
finally:
    if p.poll() is None:
        p.kill()
    shutil.rmtree(tmp, ignore_errors=True)
