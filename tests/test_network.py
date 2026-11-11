import sys, time, subprocess, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # the project folder
sys.path.insert(0, ROOT)
import client
client.DEFAULT_TLS = False      # these tests use a plain-TCP, no-accounts server
srv = subprocess.Popen([sys.executable, "server.py", "--no-auth", "--no-tls", "--no-db", "--port", "5082"], cwd=ROOT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
time.sleep(1)
def spin(*apps, secs=0.5):
    end = time.time() + secs
    while time.time() < end:
        for a in apps: a.update()
        time.sleep(0.01)
class E:
    def __init__(s, x, y): s.x, s.y = x, y
a = client.App(); a.vars["user"].set("alice"); a.vars["port"].set("5082"); a.start("CREATE_ROOM"); spin(a)
b = client.App(); b.vars["user"].set("bob"); b.vars["port"].set("5082"); b.vars["room"].set(a.room); b.start("JOIN_ROOM"); spin(a, b)
a.geometry("+0+0"); b.geometry("+0+800")
a.tool, a.color, a.width = "pen", "#1565c0", 4
for k in range(6):                     # generate some traffic over ~6 s
    a.on_press(E(50, 100 + k * 30))
    for i in range(1, 40): a.on_drag(E(50 + i * 10, 100 + k * 30 + (i % 5) * 6))
    a.on_release(E(440, 110 + k * 30)); spin(a, b, secs=0.9)
a.open_network(); spin(a, b, secs=1.2)
st = a.lat_stats(); print("lat", st)
assert st and st["now"] < 100 and len(a.rtts) >= 4
print("bytes tx", a.net.tx_bytes, "rx", a.net.rx_bytes); assert a.net.tx_bytes > 1000 and a.net.rx_bytes > 1000
assert a.srv_stats.get("room_clients") == 2 and "bob" in a.peers and "alice" in a.peers, (a.srv_stats, a.peers)
print("srv", a.srv_stats, len(a.objs)); assert a.srv_stats["ops"] == 6 and a.srv_stats["msgs_in"] > 6
print("peers", a.peers); print("server", a.srv_stats)
a.lift(); a.netwin.geometry("+1400+0"); a.update(); time.sleep(0.4); spin(a, b, secs=0.3)
import subprocess as sp
import shutil
if shutil.which("import"):   # screenshot only where ImageMagick exists (Linux)
    sp.run(["import", "-window", "root", os.path.join(ROOT, "screenshot_network.png")])
print("NETWORK TEST PASSED")
a.on_close(); b.on_close(); srv.terminate()
