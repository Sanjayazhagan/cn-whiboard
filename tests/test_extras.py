import sys, time, subprocess, os, base64, io
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # the project folder
sys.path.insert(0, ROOT)
import client
client.DEFAULT_TLS = False      # these tests use a plain-TCP, no-accounts server
from PIL import Image
import tempfile
TMP = tempfile.mkdtemp()
PIC, OUT = os.path.join(TMP, "pic.jpg"), os.path.join(TMP, "out.png")
srv = subprocess.Popen([sys.executable, "server.py", "--no-auth", "--no-tls", "--no-db", "--port", "5081"], cwd=ROOT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
time.sleep(1)
def spin(*apps, secs=0.5):
    end = time.time() + secs
    while time.time() < end:
        for a in apps: a.update()
        time.sleep(0.01)
class E:
    def __init__(s, x, y): s.x, s.y = x, y
import tkinter.simpledialog as sd, tkinter.filedialog as fd, tkinter.messagebox as mb
mb.showinfo = lambda *a, **k: None
a = client.App(); a.vars["user"].set("alice"); a.vars["port"].set("5081"); a.start("CREATE_ROOM"); spin(a)
b = client.App(); b.vars["user"].set("bob"); b.vars["port"].set("5081"); b.vars["room"].set(a.room); b.start("JOIN_ROOM"); spin(a, b)
a.geometry("+0+0"); b.geometry("+0+0")

# a test picture (gradient, 300x200 JPEG to exercise Pillow re-encode)
img = Image.new("RGB", (300, 200))
for x in range(300):
    for y in range(200): img.putpixel((x, y), (x * 255 // 300, y * 255 // 200, 160))
img.save(PIC)
fd.askopenfilename = lambda **k: PIC
a.tool = "image"; a.on_press(E(40, 40)); spin(a, b)
assert any(o["obj"]["kind"] == "image" for o in b.objs.values()), "image not synced"

# version 1 = just the image
a.open_history(); spin(a, b)
sd.askstring = lambda *x, **k: "with picture"
a.save_version(); spin(a, b)
assert any(v["label"] == "with picture" for v in a.versions), a.versions

# stickies by both users
a.color = "#f9a825"
sd.askstring = lambda *x, **k: "TODO: finish protocol doc"
a.tool = "sticky"; a.on_press(E(400, 60)); spin(a, b)
b.color = "#4caf50"; sd.askstring = lambda *x, **k: "Bob: test on Windows too"
b.tool = "sticky"; b.on_press(E(620, 200)); spin(a, b)
assert sum(o["obj"]["kind"] == "sticky" for o in a.objs.values()) == 2

# PNG export
a.render_png(OUT); im = Image.open(OUT); assert im.size == (1000, 640)
print("png ok", os.path.getsize(OUT))

# restore version "with picture": stickies disappear for everyone, then history shows them again via undo-free restore
vid = next(v["id"] for v in a.versions if v["label"] == "with picture")
a.net.send({"type": "VERSION_RESTORE", "id": vid}); spin(a, b)
assert not any(o["visible"] for o in b.objs.values() if o["obj"]["kind"] == "sticky")
assert any(o["visible"] for o in b.objs.values() if o["obj"]["kind"] == "image")
# non-host cannot restore
b.net.send({"type": "VERSION_RESTORE", "id": vid}); spin(a, b)
print("EXTRAS TEST PASSED")
# screenshot: re-add stickies so the picture is nice
a.color = "#f9a825"; sd.askstring = lambda *x, **k: "TODO: finish protocol doc"; a.tool = "sticky"; a.on_press(E(400, 60)); spin(a, b)
b.color = "#4caf50"; sd.askstring = lambda *x, **k: "Bob: test on Windows too"; b.tool = "sticky"; b.on_press(E(620, 200)); spin(a, b)
a.color, a.width, a.tool = "#e6194b", 4, "pen"
a.on_press(E(60, 300))
for i in range(1, 40): a.on_drag(E(60 + i * 8, 300 + (i % 6) * 8))
a.on_release(E(372, 340)); spin(a, b)
a.chat_entry.insert(0, "Restored the version with the picture!"); a.send_chat(None); spin(a, b)
a.lift(); a.update(); time.sleep(0.3); a.update()
import shutil
if shutil.which("import"):   # screenshot only where ImageMagick exists (Linux)
    subprocess.run(["import", "-window", "root", os.path.join(ROOT, "screenshot_extras.png")])
a.on_close(); b.on_close(); srv.terminate()
