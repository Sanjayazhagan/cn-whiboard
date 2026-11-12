"""The web port is taken by another program (seen in the lab: EDB Postgres' web server sits on 8080, so
phones that scanned the QR code got "Server is up and running" instead of the whiteboard).

The server must notice, move its browser listener to the next free port, and hand out that port
everywhere a client learns it: the Phone join link, the PING reply (diagnose.py) and LAN discovery."""
import sys, time, socket, subprocess, os, json, shutil, tempfile, threading, http.server, urllib.request
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from protocol import send_msg, recv_msg, listen_socket, port_taken
import diagnose

PORT, WEBP = 5121, 8121
tmp = tempfile.mkdtemp()
OTHER_PAGE = b"<h3>EDB POSTGRES</h3>Server is up and running."


class Other(http.server.BaseHTTPRequestHandler):
    """Stands in for the other program's web server."""
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(OTHER_PAGE)))
        self.end_headers()
        self.wfile.write(OTHER_PAGE)

    def log_message(self, *a):
        pass


def get(port, path="/"):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))      # never through a proxy
    with opener.open(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
        return r.read()


procs = []
other = http.server.HTTPServer(("0.0.0.0", WEBP), Other)
threading.Thread(target=other.serve_forever, daemon=True).start()
try:
    # ------------------------------------------------------------ 1. the socket helper refuses a used port
    assert port_taken("0.0.0.0", WEBP) and not port_taken("0.0.0.0", WEBP + 5)
    try:
        listen_socket("0.0.0.0", WEBP)
        raise AssertionError("listen_socket accepted a port another program listens on")
    except OSError as e:
        assert "already used" in str(e) or e.errno, e
    s, _ = listen_socket("0.0.0.0", WEBP + 5)
    s.close()
    print("ok  listen_socket refuses a port that another program already listens on")

    # ------------------------------------------------------------ 2. the server moves to the next free port
    log = open(os.path.join(tmp, "server.log"), "w")
    p = subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py"), "--no-auth", "--no-tls", "--no-discovery",
                          "--no-voice", "--no-db", "--port", str(PORT), "--web-port", str(WEBP)],
                         cwd=tmp, stdout=log, stderr=subprocess.STDOUT)
    procs.append(p)
    time.sleep(3)
    out = open(os.path.join(tmp, "server.log")).read()
    assert f"browsers/phones use port {WEBP + 1} instead" in out, out
    assert f":{WEBP + 1}/admin?key=" in out and "Browser listener disabled" not in out, out
    assert get(WEBP) == OTHER_PAGE                                   # the other program is left alone
    assert b"<title>LAN Whiteboard</title>" in get(WEBP + 1)         # and the whiteboard page is on the next port
    info = json.loads(get(WEBP + 1, "/info"))
    assert info["role"] == "primary" and info["id"], info
    print(f"ok  port {WEBP} is taken -> the server says so and serves browsers on {WEBP + 1}")

    # ------------------------------------------------------------ 3. every client learns the real port
    a = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    send_msg(a, {"type": "CREATE_ROOM", "user": "alice", "password": ""})
    j = recv_msg(a)
    assert j["type"] == "JOIN_OK" and j["web"] == WEBP + 1, j
    send_msg(a, {"type": "INVITE_REQ"})
    a.settimeout(3)
    inv = recv_msg(a)
    while inv.get("type") != "INVITE":
        inv = recv_msg(a)
    assert f":{WEBP + 1}/?room={j['room']}&invite=" in inv["url"], inv
    assert b"<title>LAN Whiteboard</title>" in get(WEBP + 1, "/?" + inv["url"].split("?", 1)[1])
    print("ok  the Phone join link (QR code) points at the port that really serves the whiteboard")

    lines = []
    diagnose.run("127.0.0.1", PORT, tls=False, emit=lambda v, n, t: lines.append((v, n, t)), route=False,
                 discovery_port=1)
    web = [l for l in lines if l[1].startswith("web")]
    assert web and web[0][0] == diagnose.OK and web[0][1] == f"web {WEBP + 1}", web
    print("ok  diagnose.py checks the web port the server reports, not a fixed 8080")

    # ------------------------------------------------------------ 4. the main port is never shared either
    p2 = subprocess.run([sys.executable, os.path.join(ROOT, "server.py"), "--no-auth", "--no-tls", "--no-discovery",
                         "--no-voice", "--no-db", "--no-web", "--port", str(PORT)],
                        cwd=tmp, capture_output=True, text=True, timeout=30)
    assert p2.returncode != 0 and f"Cannot listen on TCP port {PORT}" in p2.stderr + p2.stdout, p2
    print("ok  a second server on the same main port stops with a clear message instead of sharing the port")
    print("ALL WEB PORT TESTS PASSED")
finally:
    for p in procs:
        if p.poll() is None:
            p.kill()
    other.shutdown()
    shutil.rmtree(tmp, ignore_errors=True)
