"""GUI tests for the extra features: chaos lab (two real clients repair a lossy, slow link), packet
inspector, time-travel replay, phone-join QR window, laser pointer, and automatic failover to a
standby server over TLS (the standby's certificate is trusted through the primary)."""
import sys, time, subprocess, os, shutil, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
tmp = tempfile.mkdtemp()
os.environ["WB_KNOWN_SERVERS"] = os.path.join(tmp, "known.json")
import client
import tkinter.messagebox as mb
mb.askyesno = lambda *a, **k: False
mb.showerror = mb.showwarning = mb.showinfo = lambda *a, **k: None
SHOTS = os.environ.get("WB_SHOTS")            # folder for screenshots (optional)

P1, P2 = 5098, 5099


def server(*extra):
    return subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py"), "--no-auth", "--no-discovery",
                             "--cluster-key", "lab", *extra], cwd=tmp, stdout=subprocess.DEVNULL,
                            stderr=subprocess.STDOUT)


def spin(*apps, secs=0.6, until=None):
    end = time.time() + secs
    while time.time() < end:
        for a in apps:
            a.update()
        if until and until():
            return True
        time.sleep(0.01)
    return until is None


def shot(win, name):
    if not SHOTS:
        return
    try:
        from PIL import ImageGrab
        win.lift(); win.update()
        x, y, w, h = win.winfo_rootx(), win.winfo_rooty(), win.winfo_width(), win.winfo_height()
        ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(os.path.join(SHOTS, name))
    except Exception as e:
        print("   (no screenshot:", e, ")")


class E:
    def __init__(s, x, y): s.x, s.y = x, y


def draw(app, i, n=40):
    app.tool = "pen"
    app.on_press(E(20 + i * 9, 30 + i * 13))
    for k in range(1, n):
        app.on_drag(E(20 + i * 9 + k * 7, 30 + i * 13 + (k * 5) % 23))
    app.on_release(E(0, 0))


def visible(app):
    return sorted(i for i, r in app.objs.items() if r["visible"])


p1 = server("--port", str(P1), "--web-port", "8098", "--cert", "c1.pem", "--key", "k1.pem", "--db", "p.db")
time.sleep(2.5)
p2 = server("--port", str(P2), "--web-port", "8099", "--cert", "c2.pem", "--key", "k2.pem", "--db", "s.db",
            "--standby-of", f"127.0.0.1:{P1}")
procs = [p1, p2]
time.sleep(2.5)
try:
    a = client.App(); a.vars["user"].set("alice"); a.vars["port"].set(str(P1)); a.vars["host"].set("127.0.0.1")
    a.start("CREATE_ROOM"); spin(a, secs=5, until=lambda: a.room)
    b = client.App(); b.vars["user"].set("bob"); b.vars["port"].set(str(P1)); b.vars["host"].set("127.0.0.1")
    b.vars["room"].set(a.room); b.start("JOIN_ROOM"); spin(a, b, secs=5, until=lambda: b.room)
    assert a.room and b.room == a.room and a.net.tls_info
    assert a.backups and a.backups[0]["port"] == P2 and a.backups[0]["fp"], a.backups
    assert a.load_known().get(f"{a.backups[0]['host']}:{P2}") == a.backups[0]["fp"]
    print("ok  joined over TLS; the primary announced its standby and its certificate fingerprint was remembered")

    # ---- chaos lab
    a.open_lab(); b.open_lab(); a.open_inspector(); a.open_network()
    a.send_chaos((30, 120, 40, 0)); spin(a, b, secs=1.5)
    assert b.chaos and b.chaos["loss"] == 30 and "chaos" in b.chaos_label.cget("text")
    for i in range(12):
        draw(a, i); spin(a, b, secs=0.15)
        draw(b, i + 20); spin(a, b, secs=0.15)
    shot(a.labwin, "screenshot_chaos_lab.png")
    ok = spin(a, b, secs=40, until=lambda: a.last_seq == b.last_seq == 24 and not a.outbox and not b.outbox)
    assert ok, (a.last_seq, b.last_seq, len(a.outbox), len(b.outbox))
    assert visible(a) == visible(b) and len(visible(a)) == 24
    repaired = a.retx + b.retx + a.gaps + b.gaps + a.hb_resyncs + b.hb_resyncs
    assert repaired > 0 and a.srv_stats.get("chaos_in", 0) + a.srv_stats.get("chaos_out", 0) > 0
    a.draw_lab(); shot(a.labwin, "screenshot_chaos_repaired.png")
    print(f"ok  chaos lab (30% loss, 120+-40 ms): 24 strokes from two clients all arrived exactly once. "
          f"alice: {a.retx} retransmissions, {a.dup_acks} dup ACKs, {a.gaps} gap resyncs, {a.hb_resyncs} heartbeat resyncs; "
          f"bob: {b.retx}/{b.dup_acks}/{b.gaps}/{b.hb_resyncs}; server dropped {a.srv_stats.get('chaos_in')} in, "
          f"{a.srv_stats.get('chaos_out')} out")
    a.send_chaos((0, 0, 0, 0)); spin(a, b, secs=1.5); assert b.chaos is None and a.chaos_label.cget("text") == ""

    # ---- inspector
    a.insp_fill(); a.insp_draw_seq()
    rows = a.insp_tree.get_children()
    types = {a.insp_tree.item(r, "values")[3] for r in rows}
    assert {"ADD", "OP", "ACK"} <= types and "PING" not in types, types
    assert any("RETX" in a.insp_tree.item(r, "values")[2] for r in rows) or a.retx == 0
    big = next(r for r in rows if "zlib" in str(a.insp_tree.item(r, "values")[6]))
    a.insp_tree.selection_set(big); a.insp_select()
    assert "zlib-compressed" in a.insp_detail.get("1.0", "end")
    a.insp_opts["beat"].set(False); a.insp_rebuild()
    assert "PONG" in {a.insp_tree.item(r, "values")[3] for r in a.insp_tree.get_children()}
    shot(a.inspwin, "screenshot_inspector.png")
    a.inspwin.winfo_children()[1].select(1); a.insp_draw_seq(); shot(a.inspwin, "screenshot_sequence.png")
    assert a.pts_sent < a.pts_raw and a.net.tx_bytes < a.net.tx_raw
    a.draw_network(); assert "BANDWIDTH OPTIMIZER" in a.net_text.get("1.0", "end")
    print(f"ok  inspector lists frames, retransmissions and compressed frames; optimizer: {a.pts_raw} points -> "
          f"{a.pts_sent}, sent {a.net.tx_raw} -> {a.net.tx_bytes} bytes, received {a.net.rx_raw} -> {a.net.rx_bytes}")

    # ---- replay
    a.send_reliable({"type": "UNDO"}); spin(a, b, secs=0.6)
    a.open_replay(); spin(a, b, secs=3, until=lambda: a.replaywin is not None)
    assert len(a.rp_ops) == 25 and a.rp_pos == 25
    hidden = lambda: sum(1 for i in a.rp_canvas.find_all() if a.rp_canvas.itemcget(i, "state") == "hidden")
    assert len(a.rp_canvas.find_all()) == 24 and hidden() == 1
    a.rp_goto(5); assert len(a.rp_canvas.find_all()) == 5 and "op 5/25" in a.rp_label.cget("text")
    a.rp_speed.set("120 ops/s"); a.rp_toggle(); spin(a, secs=3, until=lambda: not a.rp_playing)
    assert a.rp_pos == 25 and hidden() == 1
    a.rp_goto(12); shot(a.replaywin, "screenshot_replay.png")
    print("ok  replay: scrub back to op 5, play forward to the end, the undo shows up as a hidden stroke")

    # ---- phone join window + laser
    a.net.send({"type": "INVITE_REQ"}); spin(a, secs=3, until=lambda: a.qrwin is not None)
    assert a.qrwin.winfo_exists(); shot(a.qrwin, "screenshot_phone_join.png")
    a.tool = "laser"; a.on_press(E(300, 300)); spin(a, b, secs=0.3)
    assert b.canvas.find_withtag("laser"); spin(a, b, secs=1.0); assert not b.canvas.find_withtag("laser")
    print("ok  phone-join window opens" + (" with a QR code" if client.qrcode else " (qrcode package missing: link only)")
          + "; laser pointer shows on the other client and fades")

    # ---- failover
    draw(b, 40); spin(a, b, secs=1)
    before = visible(a)
    p1.kill(); p1.wait(); t0 = time.time()
    b.tool = "pen"; draw(b, 41)                    # drawn while the server is dead: waits in the outbox
    spin(a, b, secs=0.3)
    assert "OFFLINE" in b.status.cget("text") and "1 action(s) saved" in b.status.cget("text"), b.status.cget("text")
    assert b.canvas.find_withtag("preview")       # the offline stroke stays visible
    ok = spin(a, b, secs=25, until=lambda: a.failovers and b.failovers and not b.outbox and a.last_seq == b.last_seq == 27)
    assert ok, (a.failovers, b.failovers, len(b.outbox), a.last_seq, b.last_seq, a.conn, a.offline)
    took = time.time() - t0
    assert a.conn[1] == P2 and b.conn[1] == P2 and a.net.tls_info
    assert set(before) < set(visible(a)) and visible(a) == visible(b) and len(visible(a)) == 25
    draw(a, 42); spin(a, b, secs=3, until=lambda: b.last_seq == 28); assert b.last_seq == 28
    shot(a, "screenshot_failover.png")
    print(f"ok  failover: primary killed, both clients moved to the standby in {took:.1f} s (TLS, no certificate "
          "prompt), nothing lost, the stroke drawn in offline mode stayed visible and was delivered, drawing continues")
    print("ALL GUI FEATURE TESTS PASSED")
finally:
    for p in procs:
        if p.poll() is None:
            p.kill()
    shutil.rmtree(tmp, ignore_errors=True)
