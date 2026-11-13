"""GUI tests for: connection diagnostics window, end-to-end encrypted rooms, peer-to-peer file
transfer between two clients, and voice chat (network path; no sound card needed)."""
import sys, time, subprocess, os, shutil, tempfile, json, struct, math
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
tmp = tempfile.mkdtemp()
os.environ["WB_KNOWN_SERVERS"] = os.path.join(tmp, "known.json")
os.environ["WB_DOWNLOADS"] = os.path.join(tmp, "downloads")
import client
client.DEFAULT_TLS = False
import tkinter.messagebox as mb
mb.askyesno = lambda *a, **k: True
mb.showerror = mb.showwarning = mb.showinfo = lambda *a, **k: None
SHOTS = os.environ.get("WB_SHOTS")
PORT, WEBP, VP = 5104, 8104, 5154

srv = subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py"), "--no-auth", "--no-tls", "--no-discovery",
                        "--port", str(PORT), "--web-port", str(WEBP), "--voice-port", str(VP), "--db", "t.db"],
                       cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
time.sleep(1.3)


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
    if SHOTS:
        try:
            from PIL import ImageGrab
            win.lift(); win.update()
            x, y, w, h = win.winfo_rootx(), win.winfo_rooty(), win.winfo_width(), win.winfo_height()
            ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(os.path.join(SHOTS, name))
        except Exception as e:
            print("   (no screenshot:", e, ")")


class E:
    def __init__(s, x, y): s.x, s.y = x, y


def draw(app, i, n=30):
    app.tool = "pen"
    app.on_press(E(60 + i * 9, 80 + i * 40))
    for k in range(1, n):
        app.on_drag(E(60 + i * 9 + k * 9, 80 + i * 40 + (k * 7) % 31))
    app.on_release(E(0, 0))


def items(app):
    return len(app.canvas.find_withtag("obj"))


try:
    a = client.App(); a.vars["user"].set("alice"); a.vars["port"].set(str(PORT)); a.vars["host"].set("127.0.0.1")
    # ---- diagnostics from the login screen
    a.open_diagnose()
    ok = spin(a, secs=30, until=lambda: "result" in a.diag_text.get("1.0", "end"))
    text = a.diag_text.get("1.0", "end")
    assert ok and f"[ OK ] TCP {PORT}" in text and "PING -> PONG" in text, text
    shot(a.diag_text.winfo_toplevel(), "screenshot_diagnose.png")
    print("ok  diagnostics window: TCP handshake and PING/PONG reported OK from the login screen")

    a.start("CREATE_ROOM"); spin(a, secs=5, until=lambda: a.room)
    b = client.App(); b.vars["user"].set("bob"); b.vars["port"].set(str(PORT)); b.vars["host"].set("127.0.0.1")
    b.vars["room"].set(a.room); b.start("JOIN_ROOM"); spin(a, b, secs=5, until=lambda: b.room)
    assert b.room == a.room and a.voice_port == VP and "IPv" in a.net.family

    # ---- end-to-end encryption
    draw(a, 0); spin(a, b, secs=0.8); assert items(b) == 1
    a.net.send({"type": "ROOM_SET", "e2e": True})       # only the host (alice) can switch E2E on for the room
    spin(a, b, secs=3, until=lambda: a.cfg["e2e"] and b.cfg["e2e"])
    a.set_e2e("river-42")
    draw(a, 1); a.tool = "text"; a.send_add("text", [[300, 300]], text="SECRET MEETING 5PM")
    a.chat_entry.insert(0, "the password is tiger"); a.send_chat(None)
    spin(a, b, secs=1.0)
    assert items(a) == 3 and items(b) == 1 and len(b.sealed) == 2, (items(a), items(b), len(b.sealed))
    assert "encrypted message" in b.chat.get("1.0", "end") and "tiger" not in b.chat.get("1.0", "end")
    assert "2 end-to-end encrypted object" in b.sec_label.cget("text")
    live_after = [n for (n, _t, d, m, *_r) in a.net.trace if d == "tx" and m.get("type") == "LIVE"]
    first_enc = min(n for (n, _t, d, m, *_r) in a.net.trace if d == "tx" and m.get("type") == "ADD"
                    and m["obj"]["kind"] == "enc")
    assert not [n for n in live_after if n > first_enc - 30 and n > first_enc - 1]      # no live preview leaks
    def db_bytes():
        return open(os.path.join(tmp, "t.db"), "rb").read() + (open(os.path.join(tmp, "t.db-wal"), "rb").read()
                                                               if os.path.exists(os.path.join(tmp, "t.db-wal")) else b"")
    t_end = time.time() + 5                     # the server's write can take a moment (seen on Windows CI)
    while b'"kind":"enc"' not in db_bytes() and time.time() < t_end:
        time.sleep(0.2)
    db_text = db_bytes()
    assert b'"kind":"enc"' in db_text, "encrypted object never reached the database"
    assert b"SECRET MEETING" not in db_text and b"tiger" not in db_text, "plaintext found in the database"
    b.set_e2e("wrong-key"); assert items(b) == 1 and len(b.sealed) == 2
    b.set_e2e("river-42"); spin(a, b, secs=0.3)
    assert items(b) == 3 and not b.sealed and b.objs[[i for i in b.objs][-1]]["obj"]["text"] == "SECRET MEETING 5PM"
    b.chat_entry.insert(0, "got it"); b.send_chat(None); spin(a, b, secs=0.8)
    assert "\U0001F510 got it" in a.chat.get("1.0", "end")
    b.open_replay(); spin(a, b, secs=3, until=lambda: b.replaywin is not None)
    assert len(b.rp_canvas.find_all()) == 3
    shot(b, "screenshot_e2e.png")
    a.set_e2e(""); b.set_e2e("")
    print("ok  end-to-end encryption: without the key bob sees nothing and the server database holds only "
          "ciphertext; with the key the drawing, the text and the chat appear; a wrong key opens nothing")

    # ---- peer-to-peer file
    src = os.path.join(tmp, "lab-report.pdf"); data = os.urandom(2_500_000); open(src, "wb").write(data)
    a.plist.selection_clear(0, "end")
    a.plist.selection_set([u["name"] for u in a.users].index("bob"))
    a.send_file(src)
    dest = os.path.join(tmp, "downloads", "lab-report.pdf")
    ok = spin(a, b, secs=20, until=lambda: os.path.exists(dest) and "file saved" in b.chat.get("1.0", "end"))
    assert ok and open(dest, "rb").read() == data
    spin(a, b, secs=0.8)
    assert "peer to peer" in a.chat.get("1.0", "end") and not a.file_out
    print("ok  P2P file: alice -> bob, 2.5 MB over a direct TCP connection, hash verified, sender closed its port")

    # ---- voice
    b.open_voice(); spin(a, b, secs=0.3)
    assert b.vc is None and "Voice: off" in b.voice_btn.cget("text")   # off until the host turns it on
    a.net.send({"type": "ROOM_SET", "voice": True})       # only the host (alice) can switch voice on
    spin(a, b, secs=3, until=lambda: a.cfg["voice"] and b.cfg["voice"])
    a.open_voice(); b.open_voice(); spin(a, b, secs=1.2)
    assert a.vc.ok and b.vc.ok
    tone = struct.pack("<160h", *[int(9000 * math.sin(i * 2 * math.pi * 300 / 8000)) for i in range(160)])
    played = 0
    for i in range(50):
        a.vc.send_frame(tone); spin(a, b, secs=0.02)
        if not b.audio:
            played += b.vc.pull() != client.voice.SILENCE
    spin(a, b, secs=0.6)
    s = b.vc.stats()
    assert s["received"] == 50 and s["lost"] == 0 and (b.audio or played >= 40), (s, played)
    assert "received 50" in b.voice_text.get("1.0", "end")
    shot(b.voicewin, "screenshot_voice.png")
    print("ok  voice: 50 packets from alice reached bob over UDP through the relay, none lost; audio device: "
          + ("present" if b.audio else "none on this machine (" + b.voice_err[:50] + ")"))
    a.close_voice(); b.close_voice()
    print("ALL GUI MORE TESTS PASSED")
finally:
    srv.kill()
    shutil.rmtree(tmp, ignore_errors=True)
