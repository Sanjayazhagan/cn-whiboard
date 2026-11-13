"""Desktop client: Exit room button, host-only voice / E2E switches as a non-host sees them,
and the host's "Let back in" for a removed person. Two real GUI clients against a real server."""
import sys, time, subprocess, os, shutil, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
tmp = tempfile.mkdtemp()
os.environ["WB_KNOWN_SERVERS"] = os.path.join(tmp, "known.json")

PORT, VPORT = 5161, 5162
p = subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py"), "--no-auth", "--no-tls", "--no-discovery",
                      "--no-web", "--no-db", "--port", str(PORT), "--voice-port", str(VPORT)], cwd=tmp,
                     stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
try:
    time.sleep(2)
    import client
    import tkinter.messagebox as mb
    import tkinter.simpledialog as sd
    answers = {"yes": False, "info": []}
    mb.askyesno = lambda *a, **k: answers["yes"]
    mb.showinfo = lambda title, text, **k: answers["info"].append(text)
    mb.showerror = mb.showwarning = lambda *a, **k: None
    client.DEFAULT_TLS = False

    def spin(*apps, secs=0.6, until=None):
        end = time.time() + secs
        while time.time() < end:
            for x in apps:
                if x.winfo_exists():
                    x.update()
            if until and until():
                return True
            time.sleep(0.01)
        return until is None

    def app(name, room=None):
        g = client.App(); g.use_tls = False
        g.vars["user"].set(name); g.vars["port"].set(str(PORT)); g.vars["host"].set("127.0.0.1")
        if room:
            g.vars["room"].set(room)
        g.start("JOIN_ROOM" if room else "CREATE_ROOM")
        return g

    ga = app("alice"); spin(ga, secs=5, until=lambda: ga.room)
    gb = app("bob", ga.room); spin(ga, gb, secs=5, until=lambda: gb.room)
    assert ga.cfg == gb.cfg == {"voice": False, "e2e": False}
    assert gb.voice_btn.cget("text") == "Voice: off"

    # ---- a non-host cannot switch voice or E2E on: they are told who can
    answers["info"].clear()
    gb.open_voice(); gb.ask_e2e(); spin(ga, gb, secs=0.4)
    assert gb.vc is None and gb.e2e_keys is None and gb.cfg["voice"] is False
    assert len(answers["info"]) == 2 and all("Only the host (alice)" in t for t in answers["info"]), answers["info"]
    print("ok  a non-host cannot turn voice chat or end-to-end encryption on (told that only the host can)")

    # ---- the host turns E2E on with a passphrase; bob is asked for the same one
    sd.askstring = lambda *a, **k: "river-42"
    ga.ask_e2e(); spin(ga, gb, secs=3, until=lambda: gb.cfg["e2e"])
    assert ga.e2e_keys and gb.e2e_btn.cget("text") == "E2E: key?"
    gb.ask_e2e(); spin(ga, gb, secs=0.3)
    assert gb.e2e_keys and gb.e2e_btn.cget("text") == "E2E: ON"
    sd.askstring = lambda *a, **k: ""                    # host clears it: off for everyone
    ga.ask_e2e(); spin(ga, gb, secs=3, until=lambda: not gb.cfg["e2e"])
    assert gb.e2e_btn.cget("text") == "E2E key"
    print("ok  the host switches end-to-end encryption on and off for the whole room")

    # ---- the host turns voice on (confirms the question); bob can join, then the host turns it off
    answers["yes"] = True
    ga.open_voice(); spin(ga, gb, secs=3, until=lambda: gb.cfg["voice"] and ga.vc is not None)
    gb.open_voice(); spin(ga, gb, secs=2, until=lambda: ga.vc.ok and gb.vc and gb.vc.ok)
    assert ga.vc.ok and gb.vc.ok
    ga.net.send({"type": "ROOM_SET", "voice": False})
    spin(ga, gb, secs=3, until=lambda: gb.vc is None and ga.vc is None)
    assert gb.vc is None and ga.vc is None and gb.voice_btn.cget("text") == "Voice: off"
    print("ok  the host switches voice chat on and off; everyone is hung up when it goes off")

    # ---- kick bob, see him as removed, let him back in
    answers["yes"] = False                               # bob: stay on the board after being removed
    ga.plist.selection_clear(0, "end"); ga.plist.selection_set([u["name"] for u in ga.users].index("bob"))
    ga.kick(); spin(ga, gb, secs=3, until=lambda: gb.offline and ga.banned == ["bob"])
    assert gb.offline and ga.banned == ["bob"]
    rows = ga.plist.get(0, "end")
    assert rows[-1] == "✕ bob (removed)", rows
    ga.plist.selection_clear(0, "end"); ga.plist.selection_set(len(rows) - 1)
    assert ga.selected_removed() == "bob" and ga.selected_user() is None
    ga.unban(); spin(ga, secs=3, until=lambda: not ga.banned)
    assert ga.banned == [] and not any("removed" in r for r in ga.plist.get(0, "end"))
    gb.destroy()
    gb = app("bob", ga.room); spin(ga, gb, secs=5, until=lambda: gb.room)
    assert gb.room == ga.room and not gb.offline
    print("ok  the host sees who was removed and lets them back in; they can join again")

    # ---- Exit room: back to the join screen, no reconnect, the others see bob leave
    answers["yes"] = True
    gb.exit_room(); spin(ga, gb, secs=3, until=lambda: not next(u for u in ga.users if u["name"] == "bob")["online"])
    assert not hasattr(gb, "canvas") and gb.login.winfo_exists() and not gb.reconnecting
    assert not next(u for u in ga.users if u["name"] == "bob")["online"]
    spin(ga, gb, secs=2.5)
    assert not hasattr(gb, "canvas") and not gb.net.open        # stayed out: no automatic reconnect
    print("ok  Exit room leaves the room and goes back to the join screen (no automatic reconnect)")
    print("ALL HOST GUI TESTS PASSED")
finally:
    if p.poll() is None:
        p.kill()
    shutil.rmtree(tmp, ignore_errors=True)
