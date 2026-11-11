import sys, time, subprocess, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # the project folder
sys.path.insert(0, ROOT)
import client
client.DEFAULT_TLS = False      # these tests use a plain-TCP, no-accounts server
srv = subprocess.Popen([sys.executable, "server.py", "--no-auth", "--no-tls", "--no-db", "--port", "5078"], cwd=ROOT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
time.sleep(1)

def spin(*apps, secs=0.6):
    end = time.time() + secs
    while time.time() < end:
        for a in apps:
            a.update()
        time.sleep(0.01)

class E:  # fake mouse event
    def __init__(s, x, y): s.x, s.y = x, y

a = client.App(); a.vars["user"].set("alice"); a.vars["port"].set("5078"); a.start("CREATE_ROOM"); spin(a)
assert a.room, "alice did not get a room"
b = client.App(); b.vars.update(); b.vars["user"].set("bob"); b.vars["port"].set("5078"); b.vars["room"].set(a.room); b.start("JOIN_ROOM"); spin(a, b)
assert b.room == a.room and len(b.users) == 2

# alice draws a stroke via real handlers
a.tool = "pen"; a.on_press(E(10, 10)); a.on_drag(E(40, 40)); a.on_drag(E(80, 50)); a.on_release(E(80, 50)); spin(a, b)
a.tool = "rect"; a.on_press(E(100, 100)); a.on_drag(E(160, 150)); a.on_release(E(160, 150)); spin(a, b)
assert len(a.objs) == len(b.objs) == 2, (len(a.objs), len(b.objs))
assert len(b.canvas.find_withtag("obj")) == 2 and not a.canvas.find_withtag("preview")
# bob erases the rect, alice sees it hidden
b.tool = "eraser"; b.on_press(E(100, 125)); spin(a, b)
assert [o["visible"] for o in a.objs.values()].count(False) == 1
# undo by alice restores nothing (her last action was the rect, now erased -> undo hides it: no-op visible) ; chat
b.chat_entry.insert(0, "hi alice"); b.send_chat(None); spin(a, b)
assert "hi alice" in a.chat.get("1.0", "end")
# connection loss -> auto reconnect with snapshot
b.net.sock.close(); spin(a, b, secs=4)
assert not b.reconnecting and len(b.objs) == 2, (b.reconnecting, len(b.objs))
a.net.send({"type": "CLEAR"}); spin(a, b)
assert all(not o["visible"] for o in b.objs.values())
print("GUI SMOKE TEST PASSED")
a.on_close(); b.on_close(); srv.terminate()
