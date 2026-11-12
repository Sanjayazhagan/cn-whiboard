"""LAN whiteboard client (Tkinter). Run: python client.py

Threads: a reader thread pushes server messages into a queue; a heartbeat thread
sends PING; the Tk main thread polls the queue (Tkinter is not thread-safe, so
sockets never touch widgets directly). LAN discovery runs in its own short-lived
thread and reports back through the same queue.

Reliability: requests that change the board (ADD, ERASE, MOVE, UNDO, REDO, CLEAR) and chat
carry a msg_id and stay in an "outbox" until the server ACKs them. After a reconnect
everything still in the outbox is sent again; the server ignores ids it has already
processed, so nothing is lost and nothing is applied twice.

The same outbox is also covered by a retransmit timer (ARQ): every request has a request
number `rn`; if the oldest one is not ACKed within the timeout (derived from the measured
round-trip time, doubled on every retry) all unACKed requests are sent again in order. The
server processes requests strictly in rn order and holds back any that arrive early. Together with the sequence-gap
resync and the heartbeat check ("the server is at seq N, am I?") the board repairs itself
when messages are lost - which the Chaos lab window lets the host do on purpose.
"""
import base64
import io
import json
import queue
import os
import socket
import ssl
import threading
import time
import tkinter as tk
import uuid
from tkinter import colorchooser, filedialog, messagebox, simpledialog, ttk

from collections import deque

from protocol import (DEFAULT_PORT, DISCOVER_MAGIC, DISCOVERY_PORT, HEARTBEAT_SEC, TIMEOUT_SEC,
                      compress_frame, encode_msg, is_loopback, recv_frame, simplify)
import diagnose
import e2e
import p2p
import voice

from auth import fingerprint

CANVAS_W, CANVAS_H = 1000, 640
MOVE_MAX_IDS = 500        # most object ids the server accepts in one MOVE request
DEFAULT_TLS = True        # "Encrypted connection" ticked by default (discovery sets it per server)
# fingerprints of servers seen before (trust on first use); override with WB_KNOWN_SERVERS for tests
KNOWN_SERVERS = os.environ.get("WB_KNOWN_SERVERS") or os.path.join(os.path.expanduser("~"),
                                                                    ".lan_whiteboard_known_servers.json")


class CertRejected(OSError):
    """The server's TLS certificate did not match the one we trusted before."""
try:                      # Pillow is optional: needed for PNG export and JPEG/large image insertion
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    Image = None
try:                      # optional: draws the QR code for "Phone join" (the link is shown either way)
    import qrcode
except ImportError:
    qrcode = None


def pastel(color):
    """Sticky-note fill: the chosen colour blended 70% toward white."""
    r, g, b = (int(color[i:i + 2], 16) for i in (1, 3, 5))
    return "#%02x%02x%02x" % tuple(int(v + (255 - v) * 0.7) for v in (r, g, b))


def discover_servers(q, wait=1.5, port=DISCOVERY_PORT):
    """UDP broadcast discovery (runs in a worker thread). Sends one DISCOVER datagram to the
    broadcast addresses and collects the servers' unicast replies for `wait` seconds."""
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(0.2)
        targets = {"255.255.255.255", "127.0.0.1"}
        try:   # also the /24 directed broadcast of every local address (helps PCs with several adapters)
            for ip in socket.gethostbyname_ex(socket.gethostname())[2] + [_local_ip()]:
                if not ip.startswith("127."):
                    targets.add(ip.rsplit(".", 1)[0] + ".255")
        except OSError:
            pass
        for t in targets:
            try:
                s.sendto(DISCOVER_MAGIC, (t, port))
            except OSError:
                pass
        end = time.time() + wait
        while time.time() < end:
            try:
                data, addr = s.recvfrom(2048)
                info = json.loads(data.decode("utf-8"))
            except socket.timeout:
                continue
            except (OSError, ValueError):
                continue
            if not isinstance(info, dict) or info.get("type") != "WB_SERVER":
                continue
            # the reply's source address is the server's IP as seen from here
            info["addr"] = info.get("ip", addr[0]) if addr[0].startswith("127.") else addr[0]
            key = info.get("id", addr[0])
            if key not in found or found[key]["addr"].startswith("127."):
                found[key] = info
    finally:
        s.close()
    q.put({"type": "_DISCOVERED", "servers": list(found.values())})


def _local_ip():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        u.connect(("10.255.255.255", 1))
        return u.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        u.close()


class Net:
    """Owns the socket. A 'generation' number lets stale threads from an old connection exit."""
    def __init__(self, q):
        self.q, self.sock, self.gen = q, None, 0
        self.open, self.target = False, None
        self.tls_info = None      # (TLS version, cipher, certificate fingerprint) or None for plain TCP
        self.family = "IPv4"
        self.lock = threading.Lock()
        # traffic counters (read by the Network window)
        self.tx_bytes = self.rx_bytes = self.tx_msgs = self.rx_msgs = 0
        self.pings_sent = 0
        self.last_rtt = None
        self.tx_raw = self.rx_raw = 0         # bytes before compression (to show what compression saved)
        self.trace = deque(maxlen=3000)       # every frame sent/received, for the packet inspector
        self.trace_n = 0

    def record(self, direction, msg, wire, raw, z, retx=False):
        self.trace_n += 1
        self.trace.append((self.trace_n, time.time(), direction, msg, wire, raw, z, retx))

    def _put(self, s, msg, retx=False):
        """Encode, compress if that helps, send. Caller holds self.lock (or is the only sender)."""
        plain = encode_msg(msg)
        frame = compress_frame(plain)
        s.sendall(frame)
        self.tx_bytes += len(frame)
        self.tx_raw += len(plain)
        self.tx_msgs += 1
        self.record("tx", msg, len(frame), len(plain), frame is not plain, retx)

    def connect(self, host, port, first_msg, tls=False, check=None, timeout=5):
        s = socket.create_connection((host, port), timeout=timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.check_hostname = False            # self-signed certificate: no CA can vouch for it, so we
            ctx.verify_mode = ssl.CERT_NONE       # check its fingerprint ourselves (check(), trust on first use)
            if os.environ.get("SSLKEYLOGFILE"):   # lets Wireshark decrypt the session (for the demo/report)
                ctx.keylog_filename = os.environ["SSLKEYLOGFILE"]
            try:
                s = ctx.wrap_socket(s)            # TLS handshake
            except (ssl.SSLError, OSError):
                s.close()
                raise
            fp = fingerprint(s.getpeercert(binary_form=True))
            self.tls_info = (s.version(), s.cipher()[0], fp)
            if check and not check(host, port, fp):
                s.close()
                raise CertRejected("server certificate not trusted")
        else:
            self.tls_info = None
        s.settimeout(TIMEOUT_SEC)       # server answers our PING every 1 s; 15 s of silence = dead link
        self.family = "IPv6" if s.family == socket.AF_INET6 else "IPv4"
        self.sock, self.gen = s, self.gen + 1
        self.open, self.target = True, ((host, port), tls)
        self._put(s, first_msg)
        threading.Thread(target=self._reader, args=(s, self.gen), daemon=True).start()
        threading.Thread(target=self._beat, args=(s, self.gen), daemon=True).start()

    def _reader(self, s, gen):
        try:
            while gen == self.gen:
                msg, n, raw, z = recv_frame(s)
                self.rx_bytes += n
                self.rx_raw += raw
                self.rx_msgs += 1
                self.record("rx", msg, n, raw, z)
                self.q.put(msg)
        except (OSError, ValueError):
            pass
        if gen == self.gen:
            self.open = False
            self.q.put({"type": "_DISCONNECTED"})

    def _beat(self, s, gen):
        while gen == self.gen:
            time.sleep(HEARTBEAT_SEC)
            self.pings_sent += 1
            # timestamp is echoed back by the server in PONG -> round-trip time; we also tell the
            # server our last RTT so every client can show everyone's latency
            self.send({"type": "PING", "t": time.time() * 1000, "rtt": self.last_rtt}, s)

    def send(self, msg, s=None, retx=False):
        s = s or self.sock
        try:
            with self.lock:
                self._put(s, msg, retx)
        except AttributeError:
            pass
        except OSError:            # broken connection: wake the reader so reconnecting starts right away
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self):
        self.gen += 1
        self.open = False
        try:
            self.sock.close()
        except (OSError, AttributeError):
            pass


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LAN Whiteboard")
        self.q = queue.Queue()
        self.net = Net(self.q)
        self.conn = None          # (host, port)
        self.me = self.password = ""
        self.use_tls = DEFAULT_TLS
        self.jwt, self.jwt_user, self.jwt_exp, self.jwt_server = None, "", 0, None   # login (JSON Web Token)
        self.my_rooms, self.pending, self.awaiting = [], None, False
        self.tick_gen = 0
        self.reset_session()
        self.build_login()
        self.after(20, self.pump)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def reset_session(self):
        """Per-session state (also used when going back to the login screen)."""
        self.objs = {}            # id -> {"obj", "visible"}
        self.last_seq = 0
        self.resyncing = False
        self.room = self.token = ""
        self.host_user = ""
        self.role = "editor"
        self.users = []
        self.reconnecting = False
        self.offline = False      # connection is gone for good (kicked / room no longer exists)
        self.outbox = {}          # msg_id -> request not yet ACKed by the server (insertion ordered)
        self.resent = self.acked = 0
        self.rn = 0               # request number of the newest reliable request
        self.sent_at, self.rto_tries, self.retx, self.dup_acks = 0.0, 0, 0, 0
        self.resync_at, self.seq_at_pong, self.hb_resyncs = 0.0, -1, 0
        self.chaos, self.backups, self.web_port, self.kinds = None, [], None, {}
        self.rc_target, self.failovers = None, 0
        self.pts_raw = self.pts_sent = 0      # stroke points before / after simplification
        self.labwin = self.inspwin = self.replaywin = self.qrwin = None
        self.e2e_keys, self.sealed, self.pending_plain = None, {}, {}   # end-to-end encryption
        self.file_out = {}                    # offer id -> p2p.Sender (files I am offering)
        if getattr(self, "vc", None):
            self.close_voice()
        self.voice_port, self.vc, self.audio, self.voicewin = None, None, None, None
        self.live, self.cursors, self.erased = {}, {}, set()
        self.rtts = deque(maxlen=60)          # recent round-trip samples (ms)
        self.pongs = 0
        self.srv_stats, self.peers = {}, {}
        self.dup_ops = self.gaps = self.reconnects = 0
        self.rate = (0.0, 0.0)               # (up B/s, down B/s)
        self.peak_down = self.peak_up = 0.0
        self._last_bytes = (self.net.tx_bytes, self.net.rx_bytes)
        self.t_start = time.time()
        self.netwin = None
        self.photos, self.hist = {}, None   # image cache (Tk drops unreferenced images), history window
        self.tool, self.color, self.width = "pen", "#000000", 3
        self.cur, self.cur_pts, self.last_live, self.last_cursor = None, [], 0, 0
        self.drag = None          # select tool: {"ids", "x0", "y0", "dx", "dy"} while the selection is being dragged
        self.sel = set()          # select tool: ids of the selected objects (dashed frames)
        self.band = None          # select tool: (x0, y0) while a selection rectangle is dragged over empty board
        self.moves = {}           # msg_id of my MOVE -> ids, redrawn from the server's state once ACKed

    # ------------------------------------------------------------ login screen
    def build_login(self):
        self.login = f = ttk.Frame(self, padding=16)
        f.pack()
        host, port = self.conn if self.conn else ("127.0.0.1", DEFAULT_PORT)
        self.vars = {k: tk.StringVar(self, value=v) for k, v in
                     dict(host=host, port=str(port), user=self.me, apw="", room="", pw="").items()}
        self.tls_var = tk.BooleanVar(self, value=self.use_tls)
        r = 0

        def head(text):
            nonlocal r
            ttk.Label(f, text=text, font=("Arial", 10, "bold")).grid(row=r, column=0, columnspan=2, sticky="w",
                                                                     pady=(8 if r else 0, 2))
            r += 1

        def field(label, key, show=""):
            nonlocal r
            ttk.Label(f, text=label).grid(row=r, column=0, sticky="w", pady=2)
            ttk.Entry(f, textvariable=self.vars[key], show=show, width=28).grid(row=r, column=1, pady=2, sticky="w")
            r += 1

        head("1. Server")
        self.find_btn = ttk.Button(f, text="Find servers on LAN", command=self.find_servers)
        self.find_btn.grid(row=r, column=0, sticky="w")
        row = ttk.Frame(f)
        row.grid(row=r, column=1, sticky="w")
        ttk.Label(row, text="(click a server to use it)", foreground="#666").pack(side="left")
        ttk.Button(row, text="Diagnose connection", command=self.open_diagnose).pack(side="left", padx=8)
        r += 1
        self.srv_list = tk.Listbox(f, height=3, width=52, exportselection=False)
        self.srv_list.grid(row=r, column=0, columnspan=2, pady=4)
        self.srv_list.bind("<<ListboxSelect>>", self.pick_server)
        r += 1
        field("Server IP", "host")
        field("Port", "port")
        ttk.Checkbutton(f, text="Encrypted connection (TLS)", variable=self.tls_var).grid(row=r, column=1, sticky="w")
        r += 1

        head("2. Account")
        field("Username", "user")
        field("Password", "apw", "*")
        row = ttk.Frame(f)
        row.grid(row=r, column=1, sticky="w", pady=4)
        ttk.Button(row, text="Log in", command=lambda: self.auth("LOGIN")).pack(side="left")
        ttk.Button(row, text="Register", command=lambda: self.auth("REGISTER")).pack(side="left", padx=4)
        r += 1
        self.auth_label = ttk.Label(f, text="", foreground="#666")
        self.auth_label.grid(row=r, column=0, columnspan=2, sticky="w")
        r += 1

        head("3. Room")
        ttk.Label(f, text="Your rooms (click to fill in the code):", foreground="#666").grid(
            row=r, column=0, columnspan=2, sticky="w")
        r += 1
        self.rooms_list = tk.Listbox(f, height=3, width=52, exportselection=False)
        self.rooms_list.grid(row=r, column=0, columnspan=2, pady=4)
        self.rooms_list.bind("<<ListboxSelect>>", self.pick_room)
        self.my_rooms = []
        r += 1
        field("Room code", "room")
        field("Room password (optional)", "pw", "*")
        ttk.Button(f, text="Create new room", command=lambda: self.start("CREATE_ROOM")).grid(row=r, column=0, pady=8)
        ttk.Button(f, text="Join room", command=lambda: self.start("JOIN_ROOM")).grid(row=r, column=1, sticky="w")
        self.found = []
        self.show_auth()
        self.after(100, self.find_servers)      # search once automatically

    def find_servers(self):
        if hasattr(self, "canvas") or not self.find_btn.winfo_exists():
            return                                  # already joined a room
        self.find_btn.config(state="disabled")
        self.srv_list.delete(0, "end")
        self.srv_list.insert("end", "Searching the LAN (UDP broadcast)...")
        threading.Thread(target=discover_servers, args=(self.q,), daemon=True).start()

    def show_servers(self, servers):
        if hasattr(self, "canvas") or not self.srv_list.winfo_exists():
            return
        self.find_btn.config(state="normal")
        self.found = sorted(servers, key=lambda x: x["addr"])
        self.srv_list.delete(0, "end")
        for sv in self.found:
            sec = ("TLS" if sv.get("tls") else "no TLS") + (", accounts" if sv.get("auth") else "")
            if sv.get("role") == "standby":
                sec += ", STANDBY"
            self.srv_list.insert("end", f"{sv.get('name', '?')}  {sv['addr']}:{sv['port']}  [{sec}]  "
                                        f"{sv.get('rooms', 0)} rooms, {sv.get('users', 0)} online")
        if not self.found:
            self.srv_list.insert("end", "No server answered. Check the firewall, or type the IP below.")
        elif len(self.found) == 1:
            self.srv_list.selection_set(0)
            self.pick_server()

    def pick_server(self, _e=None):
        sel = self.srv_list.curselection()
        if sel and sel[0] < len(self.found):
            sv = self.found[sel[0]]
            self.vars["host"].set(sv["addr"])
            self.vars["port"].set(str(sv["port"]))
            self.tls_var.set(bool(sv.get("tls", True)))

    def target(self):
        v = {k: x.get().strip() for k, x in self.vars.items()}
        return (v["host"], int(v["port"] or DEFAULT_PORT)), bool(self.tls_var.get()), v

    def send_first(self, msg):
        """Send a login-screen request, opening a connection first if there is none to this server."""
        conn, tls, _ = self.target()
        self.conn, self.use_tls = conn, tls
        self.awaiting = True
        if self.net.open and self.net.target == (conn, tls):
            self.net.send(msg)
            return
        self.net.close()
        try:
            self.net.connect(*conn, msg, tls=tls, check=self.check_cert)
        except CertRejected:
            self.awaiting = False
        except ssl.SSLError as e:
            self.awaiting = False
            messagebox.showerror("Cannot connect", f"TLS handshake failed ({e.reason}).\n\n"
                                 "If the server runs with --no-tls, untick 'Encrypted connection'.")
        except (ConnectionResetError, ConnectionAbortedError) as e:
            self.awaiting = False
            # a plain server closes the connection on a TLS ClientHello: Linux reports an SSLError, Windows a reset
            hint = ("\n\nIf the server runs with --no-tls, untick 'Encrypted connection'." if tls else
                    "\n\nIf the server uses TLS, tick 'Encrypted connection'.")
            messagebox.showerror("Cannot connect", f"{e}{hint}")
        except (OSError, ValueError) as e:
            self.awaiting = False
            messagebox.showerror("Cannot connect", str(e))

    def auth(self, kind):
        """Log in / register: the password goes to the server once (inside TLS); we get a JWT back."""
        conn, tls, v = self.target()
        if not v["user"] or not v["apw"]:
            return messagebox.showerror("Account", "Enter a username and a password")
        self.send_first({"type": kind, "user": v["user"], "password": v["apw"]})

    def start(self, kind):
        conn, tls, v = self.target()
        if kind == "JOIN_ROOM" and not v["room"]:
            return messagebox.showerror("Error", "Enter the room code")
        msg = {"type": kind, "user": v["user"], "room": v["room"], "password": v["pw"], "z": 1}
        self.password = v["pw"]
        if self.jwt and self.jwt_server == (conn, tls) and self.jwt_user.lower() == (v["user"] or self.jwt_user).lower():
            msg["jwt"] = self.jwt                   # already logged in on this server
            self.me = self.jwt_user
        elif v["apw"]:                              # not logged in yet: log in, then send this
            self.pending = msg
            return self.auth("LOGIN")
        else:                                       # servers started with --no-auth need no account
            if not v["user"]:
                return messagebox.showerror("Error", "Enter a username (and your password to log in)")
            self.me = v["user"]
        self.send_first(msg)

    def pick_room(self, _e=None):
        sel = self.rooms_list.curselection()
        if sel and sel[0] < len(self.my_rooms):
            self.vars["room"].set(self.my_rooms[sel[0]]["code"])

    def show_auth(self):
        if not hasattr(self, "auth_label") or not self.auth_label.winfo_exists():
            return
        if self.jwt:
            until = time.strftime("%H:%M", time.localtime(self.jwt_exp))
            self.auth_label.config(text=f"Logged in as {self.jwt_user} (token valid until {until})",
                                   foreground="#2e7d32")
        else:
            self.auth_label.config(text="Not logged in. New here? Choose a username and password and click Register.",
                                   foreground="#666")
        self.rooms_list.delete(0, "end")
        for rm in self.my_rooms:
            self.rooms_list.insert("end", f"{rm['code']}  host {rm['host']}  ({rm['role']}, {rm['objects']} objects, "
                                          f"{rm['online']} online{', password' if rm['password'] else ''})")
        if self.jwt and not self.my_rooms:
            self.rooms_list.insert("end", "No rooms yet - create one below.")

    # ---- TLS certificate check: trust on first use (like SSH's known_hosts)
    @staticmethod
    def load_known():
        try:
            with open(KNOWN_SERVERS, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    @staticmethod
    def save_known(known):
        try:
            with open(KNOWN_SERVERS, "w", encoding="utf-8") as f:
                json.dump(known, f, indent=1)
        except OSError:
            pass

    def check_cert(self, host, port, fp):
        """Called (in the Tk thread) right after the TLS handshake, before anything is sent."""
        known, key = self.load_known(), f"{host}:{port}"
        if known.get(key) == fp:
            return True
        if key not in known:
            known[key] = fp
            self.save_known(known)
            return True
        if messagebox.askyesno(
                "SECURITY WARNING - certificate changed",
                f"The server at {key} presents a DIFFERENT certificate than last time.\n\n"
                f"Before: {known[key]}\nNow:    {fp}\n\n"
                "This happens if the server was reinstalled or its certificate was deleted - "
                "or if someone on the network is intercepting the connection (man-in-the-middle).\n\n"
                "Compare the 'Now' value with the fingerprint printed by the server. Trust the new certificate?",
                icon="warning", parent=self):
            known[key] = fp
            self.save_known(known)
            return True
        return False

    def check_cert_silent(self, host, port, fp):
        """Same check for automatic reconnects (no dialog from a worker thread): only the known certificate."""
        return self.load_known().get(f"{host}:{port}") == fp

    # ------------------------------------------------------------ main UI
    def build_main(self):
        self.login.destroy()
        self.title(f"LAN Whiteboard - room {self.room} - {self.me}")
        bar = ttk.Frame(self)
        bar.pack(side="top", fill="x")
        self.tool_var = tk.StringVar(self, value="pen")
        for t in ("select", "pen", "eraser", "line", "rect", "oval", "text", "sticky", "image", "laser"):
            ttk.Radiobutton(bar, text=t.title(), value=t, variable=self.tool_var,
                            command=self.set_tool).pack(side="left", padx=2)
            if t == "select":                       # select everything, then drag any object to move the lot
                ttk.Button(bar, text="All", width=4, command=lambda: self.select_all(button=True)).pack(side="left")
        self.color_btn = tk.Button(bar, text="  Color  ", bg=self.color, fg="white", command=self.pick_color)
        self.color_btn.pack(side="left", padx=6)
        self.width_var = tk.IntVar(self, value=3)
        ttk.Scale(bar, from_=1, to=20, variable=self.width_var, length=90,
                  command=lambda _=0: setattr(self, "width", int(self.width_var.get()))).pack(side="left")
        for txt, cmd in (("Undo", lambda: self.send_reliable({"type": "UNDO"})),
                         ("Redo", lambda: self.send_reliable({"type": "REDO"})),
                         ("Export PNG", self.export),
                         ("History", self.open_history)):
            ttk.Button(bar, text=txt, command=cmd).pack(side="left", padx=2)
        self.host_btns = [ttk.Button(bar, text=t, command=c) for t, c in
                          (("Clear", lambda: self.send_reliable({"type": "CLEAR"})),
                           ("Save", lambda: self.net.send({"type": "SAVE"})),
                           ("Restore", lambda: self.net.send({"type": "LOAD"})))]
        if self.me == self.host_user:
            for b in self.host_btns:
                b.pack(side="left", padx=2)
        foot = ttk.Frame(self)               # status bar: room code, connection state, live latency
        foot.pack(side="bottom", fill="x")
        self.status = ttk.Label(foot, text=f"Room code: {self.room}", foreground="#006")
        self.status.pack(side="left", padx=8)
        self.sec_label = tk.Label(foot, text="")
        self.sec_label.pack(side="left", padx=8)
        self.show_security()
        self.lat_label = tk.Label(foot, text="● measuring...", fg="#888", cursor="hand2")
        self.lat_label.pack(side="right", padx=8)
        self.lat_label.bind("<Button-1>", lambda e: self.open_network())
        for txt, cmd in (("Network", self.open_network), ("Inspector", self.open_inspector),
                         ("Chaos lab", self.open_lab), ("Replay", self.open_replay),
                         ("Phone join", lambda: self.net.send({"type": "INVITE_REQ"}))):
            ttk.Button(foot, text=txt, command=cmd).pack(side="right")
        self.chaos_label = tk.Label(foot, text="", fg="#b26a00")
        self.chaos_label.pack(side="left", padx=8)

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(body, width=CANVAS_W, height=CANVAS_H, bg="white", highlightthickness=1)
        self.canvas.pack(side="left")
        side = ttk.Frame(body, padding=4)
        side.pack(side="left", fill="y")
        ttk.Label(side, text="Participants").pack(anchor="w")
        self.plist = tk.Listbox(side, width=28, height=9, exportselection=False)
        self.plist.pack()
        if self.me == self.host_user:
            r = ttk.Frame(side)
            r.pack(fill="x")
            ttk.Button(r, text="Toggle edit/view", command=self.toggle_role).pack(side="left")
            ttk.Button(r, text="Kick", command=self.kick).pack(side="left")
        r = ttk.Frame(side)
        r.pack(fill="x", pady=(2, 0))
        ttk.Button(r, text="Send file", width=9, command=self.send_file).pack(side="left")
        ttk.Button(r, text="Voice", width=6, command=self.open_voice).pack(side="left")
        self.e2e_btn = ttk.Button(r, text="E2E key", width=9, command=self.ask_e2e)
        self.e2e_btn.pack(side="left")
        self.file_label = ttk.Label(side, text="", foreground="#555")
        self.file_label.pack(anchor="w")
        ttk.Label(side, text="Chat").pack(anchor="w", pady=(8, 0))
        self.chat = tk.Text(side, width=32, height=22, state="disabled", wrap="word")
        self.chat.pack(fill="y", expand=True)
        self.chat_entry = ttk.Entry(side)
        self.chat_entry.pack(fill="x")
        self.chat_entry.bind("<Return>", self.send_chat)
        c = self.canvas
        c.bind("<ButtonPress-1>", self.on_press)
        c.bind("<B1-Motion>", self.on_drag)
        c.bind("<ButtonRelease-1>", self.on_release)
        c.bind("<Motion>", self.on_move)
        self.tick_gen += 1
        self.after(1000, self.net_tick, self.tick_gen)
        self.after(200, self.rto_tick, self.tick_gen)
        self.bind("<Control-z>", lambda e: self.send_reliable({"type": "UNDO"}))
        self.bind("<Control-y>", lambda e: self.send_reliable({"type": "REDO"}))
        self.bind("<Control-a>", self.select_all)
        self.bind("<Escape>", self.select_none)

    def send_reliable(self, msg):
        """Send a request that must not be lost: it keeps a msg_id and stays in the outbox until ACKed.
        If the connection is down, the send fails silently and the request goes out after reconnecting."""
        msg["msg_id"] = uuid.uuid4().hex
        if msg.get("type") == "ADD" and self.e2e_keys:      # end-to-end: replace the object by its ciphertext
            o = msg["obj"]
            self.pending_plain[o["id"]] = o
            body = json.dumps({k: v for k, v in o.items() if k != "id"}, separators=(",", ":")).encode("utf-8")
            msg["obj"] = {"id": o["id"], "kind": "enc", "color": "#000000", "width": 1, "points": [[0, 0]],
                          "data": e2e.seal(self.e2e_keys, body)}
        self.rn += 1
        msg["rn"] = self.rn                     # request number: the server handles requests in this order
        if not self.outbox:
            self.sent_at, self.rto_tries = time.time(), 0
        self.outbox[msg["msg_id"]] = msg
        self.net.send(msg)
        if self.reconnecting:                   # offline mode: show it locally and count it
            self.canvas.delete("preview")
            self.draw_pending()
            self.show_offline()

    def resend_outbox(self):
        for msg in list(self.outbox.values()):
            self.net.send(msg, retx=True)
            self.resent += 1

    def rto(self):
        """Retransmission timeout in seconds: 3 x the average measured round trip, within 0.6 .. 3 s."""
        r = list(self.rtts)
        return min(3.0, max(0.6, 3 * sum(r) / len(r) / 1000)) if r else 1.0

    def rto_tick(self, gen):
        """Retransmit timer, 5 times a second. When the oldest unACKed request times out, send ALL
        unACKed requests again in order, and wait twice as long before the next round."""
        if gen != self.tick_gen or not hasattr(self, "canvas"):
            return
        now = time.time()
        if self.net.open and not self.reconnecting and not self.offline:
            if self.outbox and now - self.sent_at > self.rto() * min(8, 2 ** self.rto_tries):
                for msg in list(self.outbox.values()):
                    self.net.send(msg, retx=True)
                    self.retx += 1
                self.sent_at, self.rto_tries = now, self.rto_tries + 1
            if self.resyncing and now - self.resync_at > max(1.5, self.rto()):
                self.resync_at = now               # the resync request or its answer was lost: ask again
                self.net.send({"type": "RESYNC_REQ", "since": self.last_seq})
        self.after(200, self.rto_tick, gen)

    def show_security(self):
        ti = self.net.tls_info
        extra = ""
        if self.e2e_keys:
            extra = "  +  end-to-end key" + (f" ({len(self.sealed)} object(s) unreadable)" if self.sealed else "")
        elif self.sealed:
            extra = f"  |  {len(self.sealed)} end-to-end encrypted object(s): set the E2E key to see them"
        if ti:
            self.sec_label.config(text=f"\U0001F512 {ti[0]} encrypted" + (f" - {self.me} (logged in)" if self.jwt else "")
                                  + extra, fg="#2e7d32")
        else:
            self.sec_label.config(text="\u26A0 not encrypted" + extra, fg="#c62828")

    def pick_color(self):
        c = colorchooser.askcolor(color=self.color)[1]
        if c:
            self.color = c
            lum = int(c[1:3], 16) * 0.3 + int(c[3:5], 16) * 0.59 + int(c[5:7], 16) * 0.11
            self.color_btn.config(bg=c, fg="black" if lum > 140 else "white")

    def send_chat(self, _e):
        t = self.chat_entry.get().strip()
        if t:
            if self.e2e_keys:                       # the server relays and stores only ciphertext
                t = e2e.PREFIX + e2e.seal(self.e2e_keys, t[:600].encode("utf-8"))
            self.send_reliable({"type": "CHAT", "text": t})
            self.chat_entry.delete(0, "end")

    def chat_text(self, t):
        if not t.startswith(e2e.PREFIX):
            return t
        plain = e2e.unseal(self.e2e_keys, t[len(e2e.PREFIX):]) if self.e2e_keys else None
        return ("\U0001F510 " + plain.decode("utf-8", "replace")) if plain is not None else \
            "[end-to-end encrypted message - set the same E2E key to read it]"

    def add_chat(self, line, tag=None):
        self.chat.config(state="normal")
        self.chat.insert("end", line + "\n", tag)
        self.chat.see("end")
        self.chat.config(state="disabled")

    def selected_user(self):
        sel = self.plist.curselection()
        return self.users[sel[0]]["name"] if sel else None

    def toggle_role(self):
        u = self.selected_user()
        if u:
            cur = next(x for x in self.users if x["name"] == u)["role"]
            self.net.send({"type": "SET_ROLE", "user": u, "role": "viewer" if cur == "editor" else "editor"})

    def kick(self):
        u = self.selected_user()
        if u:
            self.net.send({"type": "KICK", "user": u})

    def insert_image(self, x, y):
        path = filedialog.askopenfilename(filetypes=[("Images", "*.png *.gif *.jpg *.jpeg *.bmp")])
        if not path:
            return
        try:
            if Image:                                   # resize to <= 400px and re-encode as PNG
                im = Image.open(path).convert("RGBA")
                im.thumbnail((400, 400))
                buf = io.BytesIO()
                im.save(buf, "PNG")
                raw, w, h = buf.getvalue(), im.width, im.height
            else:                                       # no Pillow: Tk can only read PNG/GIF as-is
                raw = open(path, "rb").read()
                if not path.lower().endswith((".png", ".gif")):
                    return messagebox.showerror("Image", "Install Pillow (pip install pillow) for JPEG/BMP images")
                ph = tk.PhotoImage(master=self, data=base64.b64encode(raw))
                w, h = ph.width(), ph.height()
            data = base64.b64encode(raw).decode()
            if len(data) > 700_000:
                return messagebox.showerror("Image", "Image too large (limit about 500 KB after resizing)")
        except Exception as ex:
            return messagebox.showerror("Image", f"Cannot read image: {ex}")
        obj = {"id": uuid.uuid4().hex, "kind": "image", "color": "#000000", "width": 1,
               "points": [[x, y]], "data": data, "w": w, "h": h}
        self.send_reliable({"type": "ADD", "obj": obj})

    def export(self):
        """PNG export: redraw all visible objects with Pillow (PostScript fallback without it)."""
        if not Image:
            p = filedialog.asksaveasfilename(defaultextension=".ps", filetypes=[("PostScript", "*.ps")])
            if p:
                self.canvas.postscript(file=p, colormode="color")
            return
        p = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG image", "*.png")])
        if not p:
            return
        self.render_png(p)
        messagebox.showinfo("Export", f"Saved {p}")

    def render_png(self, path):
        im = Image.new("RGB", (CANVAS_W, CANVAS_H), "white")
        d = ImageDraw.Draw(im)

        def font(size):
            for name in ("DejaVuSans.ttf", "arial.ttf"):
                try:
                    return ImageFont.truetype(name, size)
                except OSError:
                    pass
            return ImageFont.load_default(size)
        for rec in self.objs.values():                  # dict order = creation order = z-order
            if not rec["visible"]:
                continue
            o, pts, col, w = rec["obj"], rec["obj"]["points"], rec["obj"]["color"], int(rec["obj"]["width"])
            k = o["kind"]
            if k == "stroke":
                if len(pts) == 1:
                    x, y = pts[0]
                    d.ellipse([x - w / 2, y - w / 2, x + w / 2, y + w / 2], fill=col)
                else:
                    d.line([tuple(p) for p in pts], fill=col, width=w, joint="curve")
            elif k == "line":
                d.line([tuple(pts[0]), tuple(pts[1])], fill=col, width=w)
            elif k in ("rect", "oval"):
                box = [min(pts[0][0], pts[1][0]), min(pts[0][1], pts[1][1]),
                       max(pts[0][0], pts[1][0]), max(pts[0][1], pts[1][1])]
                (d.rectangle if k == "rect" else d.ellipse)(box, outline=col, width=w)
            elif k == "text":
                d.text(tuple(pts[0]), o.get("text", ""), fill=col, font=font(w * 3 + 8))
            elif k == "sticky":
                x, y = pts[0]
                d.rectangle([x, y, x + 160, y + 120], fill=pastel(col), outline=col, width=2)
                d.multiline_text((x + 8, y + 8), self.wrap(o.get("text", ""), 18), fill="black", font=font(15))
            elif k == "image":
                src = Image.open(io.BytesIO(base64.b64decode(o["data"]))).convert("RGBA")
                im.paste(src, (int(pts[0][0]), int(pts[0][1])), src)
        im.save(path, "PNG")

    @staticmethod
    def wrap(text, n):
        import textwrap
        return "\n".join(textwrap.wrap(text, n)[:6])

    # ---- version history (host can save and restore; everyone can look)
    def open_history(self):
        if self.hist and self.hist.winfo_exists():
            self.hist.lift()
            return
        self.hist = w = tk.Toplevel(self)
        w.title("Version history")
        self.hist_list = tk.Listbox(w, width=44, height=14, exportselection=False)
        self.hist_list.pack(padx=6, pady=6)
        row = ttk.Frame(w)
        row.pack(pady=4)
        ttk.Button(row, text="Refresh", command=lambda: self.net.send({"type": "VERSIONS_REQ"})).pack(side="left")
        if self.me == self.host_user:
            ttk.Button(row, text="Save version now", command=self.save_version).pack(side="left", padx=4)
            ttk.Button(row, text="Restore selected", command=self.restore_version).pack(side="left")
        self.versions = []
        self.net.send({"type": "VERSIONS_REQ"})

    def save_version(self):
        label = simpledialog.askstring("Version", "Label for this version:", parent=self.hist)
        self.net.send({"type": "VERSION_SAVE", "label": label or "manual"})

    def restore_version(self):
        sel = self.hist_list.curselection()
        if sel and messagebox.askyesno("Restore", "Replace the current board with this version for everyone?",
                                       parent=self.hist):
            self.net.send({"type": "VERSION_RESTORE", "id": self.versions[sel[0]]["id"]})

    def show_versions(self, versions):
        self.versions = versions
        if self.hist and self.hist.winfo_exists():
            self.hist_list.delete(0, "end")
            for v in versions:
                self.hist_list.insert("end", f"{v['ts']}  {v['label']}  ({v['count']} objects)")

    # ------------------------------------------------------------ drawing input
    def set_tool(self):
        self.tool = self.tool_var.get()
        self.canvas.config(cursor="fleur" if self.tool == "select" else "")
        self.sel.clear()
        self.drag = self.band = None
        self.canvas.delete("sel", "band")

    def can_draw(self):
        return self.role == "editor" and not self.offline

    def on_move(self, e):
        now = time.time()
        if now - self.last_cursor > 0.07:          # throttle cursor traffic (~14/s)
            self.last_cursor = now
            self.net.send({"type": "CURSOR", "x": e.x, "y": e.y})

    def laser_at(self, x, y, user=None):
        """Laser pointer: a red dot that everyone sees for a moment; never stored."""
        if user is None:
            self.net.send({"type": "LASER", "x": x, "y": y})
        it = self.canvas.create_oval(x - 7, y - 7, x + 7, y + 7, fill="#ff1744", outline="#ff8a80", width=3, tags="laser")
        self.after(350, lambda: self.canvas.itemconfigure(it, fill="#ff8a80", outline=""))
        self.after(700, lambda: self.canvas.delete(it))

    def on_press(self, e):
        if self.tool == "laser" and not self.offline:     # viewers may point too
            return self.laser_at(e.x, e.y)
        if not self.can_draw():
            return
        if self.tool == "select":
            return self.select_at(e)
        self.cur_pts = [[e.x, e.y]]
        if self.tool == "text":
            s = simpledialog.askstring("Text", "Enter text:", parent=self)
            if s:
                self.send_add("text", [[e.x, e.y]], text=s)
        elif self.tool == "sticky":
            s = simpledialog.askstring("Sticky note", "Note text:", parent=self)
            if s:
                self.send_add("sticky", [[e.x, e.y]], text=s)
        elif self.tool == "image":
            self.insert_image(e.x, e.y)
        elif self.tool == "eraser":
            self.erase_at(e)

    def on_drag(self, e):
        if self.tool == "laser" and not self.offline:
            self.on_move(e)
            if time.time() - self.last_live > 0.03:
                self.last_live = time.time()
                self.laser_at(e.x, e.y)
            return
        if self.tool == "select" and (self.drag or self.band):
            self.on_move(e)
            return self.drag_to(e) if self.drag else self.band_to(e)
        if not self.can_draw() or not self.cur_pts:
            return
        self.on_move(e)
        if self.tool == "eraser":
            return self.erase_at(e)
        if self.tool == "pen":
            lx, ly = self.cur_pts[-1]
            if abs(e.x - lx) + abs(e.y - ly) < 2:
                return
            self.cur_pts.append([e.x, e.y])
            self.canvas.create_line(lx, ly, e.x, e.y, fill=self.color, width=self.width,
                                    capstyle="round", tags="preview")
            if time.time() - self.last_live > 0.04 and not self.e2e_keys:   # a live preview would leak the stroke
                self.last_live = time.time()
                self.net.send({"type": "LIVE", "color": self.color, "width": self.width,
                               "points": self.cur_pts[-50:]})
        elif self.tool in ("line", "rect", "oval"):
            self.canvas.delete("preview")
            x0, y0 = self.cur_pts[0]
            self.make_item(self.tool, [[x0, y0], [e.x, e.y]], self.color, self.width, None, ("preview",))
            self.cur_pts = [self.cur_pts[0], [e.x, e.y]]

    def on_release(self, e):
        if self.tool == "select" and (self.drag or self.band):
            return self.drop() if self.drag else self.band_done(e)
        if not self.can_draw() or not self.cur_pts:
            return
        if self.tool == "pen":
            pts = simplify(self.cur_pts, 1.0)      # Ramer-Douglas-Peucker: same shape, far fewer points
            self.pts_raw += len(self.cur_pts)
            self.pts_sent += len(pts)
            self.send_add("stroke", pts)
        elif self.tool in ("line", "rect", "oval") and len(self.cur_pts) == 2:
            self.send_add(self.tool, self.cur_pts)
        self.cur_pts = []

    def send_add(self, kind, pts, text=None):
        obj = {"id": uuid.uuid4().hex, "kind": kind, "color": self.color, "width": self.width, "points": pts}
        if text is not None:
            obj["text"] = text
        self.send_reliable({"type": "ADD", "obj": obj})

    # ---- select tool: pick one object or many, drag them, release -> one MOVE request (synced to everyone)
    #   click an object            select it (and drag it)
    #   Shift + click              add it to / take it out of the selection
    #   drag over empty board      selection rectangle: everything it touches is selected
    #   Ctrl + A                   select everything; Esc clears the selection
    #   drag any selected object   the whole selection moves together
    def object_at(self, x, y, r=4):
        """Id of the topmost visible object under (x, y), or None."""
        for item in reversed(self.canvas.find_overlapping(x - r, y - r, x + r, y + r)):
            if self.canvas.itemcget(item, "state") == "hidden":
                continue
            for tag in self.canvas.gettags(item):
                if tag.startswith("o_") and tag[2:] in self.objs and self.objs[tag[2:]]["visible"]:
                    return tag[2:]
        return None

    def objects_in(self, x0, y0, x1, y1):
        """Ids of the visible objects that the rectangle touches."""
        found = set()
        for item in self.canvas.find_overlapping(min(x0, x1), min(y0, y1), max(x0, x1), max(y0, y1)):
            if self.canvas.itemcget(item, "state") == "hidden":
                continue
            for tag in self.canvas.gettags(item):
                if tag.startswith("o_") and tag[2:] in self.objs and self.objs[tag[2:]]["visible"]:
                    found.add(tag[2:])
        return found

    def select_at(self, e):
        oid = self.object_at(e.x, e.y)
        shift = bool(getattr(e, "state", 0) & 0x0001)
        self.drag = self.band = None
        if oid is None:                       # empty board: start a selection rectangle
            if not shift:
                self.sel.clear()
            self.band = (e.x, e.y)
        elif shift:                           # add / remove one object
            self.sel ^= {oid}
        elif oid not in self.sel:
            self.sel = {oid}
        if oid is not None and oid in self.sel:
            self.drag = {"ids": [i for i in self.objs if i in self.sel], "x0": e.x, "y0": e.y, "dx": 0, "dy": 0}
        self.show_selection()

    def select_all(self, _e=None, button=False):
        typing = isinstance(self.focus_get(), (tk.Entry, ttk.Entry, tk.Text))     # Ctrl+A in the chat box is not for us
        if (typing and not button) or not self.room or not self.can_draw():
            return
        if self.tool != "select":
            self.tool_var.set("select")
            self.set_tool()
        self.sel = {i for i, r in self.objs.items() if r["visible"] and r["obj"].get("kind") != "enc"}
        self.show_selection()
        return "break"

    def select_none(self, _e=None):
        if self.sel and not self.drag:
            self.sel.clear()
            self.show_selection()

    def show_selection(self):
        """Dashed blue frame around every selected object (objects that were erased meanwhile drop out)."""
        self.canvas.delete("sel")
        self.sel = {i for i in self.sel if i in self.objs and self.objs[i]["visible"]}
        for oid in self.sel:
            box = self.canvas.bbox("o_" + oid)
            if box:
                x0, y0, x1, y1 = box
                self.canvas.create_rectangle(x0 - 3, y0 - 3, x1 + 3, y1 + 3, outline="#1e88e5", dash=(4, 3),
                                             width=1, tags="sel")

    def band_to(self, e):
        self.canvas.delete("band")
        self.canvas.create_rectangle(*self.band, e.x, e.y, outline="#1e88e5", dash=(2, 2), width=1, tags="band")

    def band_done(self, e):
        (x0, y0), self.band = self.band, None
        self.canvas.delete("band")
        if abs(e.x - x0) > 2 or abs(e.y - y0) > 2:        # a plain click on empty board only clears
            self.sel |= self.objects_in(x0, y0, e.x, e.y)
        self.show_selection()

    def drag_to(self, e):
        d = self.drag
        ddx, ddy = e.x - d["x0"] - d["dx"], e.y - d["y0"] - d["dy"]
        if ddx or ddy:
            for oid in d["ids"]:
                self.canvas.move("o_" + oid, ddx, ddy)       # local preview; nothing is sent until release
            self.canvas.move("sel", ddx, ddy)
            d["dx"] += ddx
            d["dy"] += ddy

    def drop(self):
        d, self.drag = self.drag, None
        if d["dx"] or d["dy"]:
            for k in range(0, len(d["ids"]), MOVE_MAX_IDS):      # the server takes at most 500 ids per MOVE
                ids = d["ids"][k:k + MOVE_MAX_IDS]
                msg = {"type": "MOVE", "ids": ids, "dx": d["dx"], "dy": d["dy"]}
                self.send_reliable(msg)
                self.moves[msg["msg_id"]] = ids

    def shift_obj(self, oid, dx, dy):
        """Apply a MOVE to my copy of one object (also to its sealed form, so it lands right once decrypted)."""
        if oid in self.objs:
            o = self.objs[oid]["obj"]
            o = self.objs[oid]["obj"] = {**o, "points": [[x + dx, y + dy] for x, y in o["points"]]}
            self.draw_obj(o, self.objs[oid]["visible"])
        if oid in self.sealed:
            o = self.sealed[oid]
            self.sealed[oid] = {**o, "points": [[x + dx, y + dy] for x, y in o["points"]]}

    def erase_at(self, e):
        r = 5 + self.width
        hits = set()
        for item in self.canvas.find_overlapping(e.x - r, e.y - r, e.x + r, e.y + r):
            for tag in self.canvas.gettags(item):
                if tag.startswith("o_"):
                    oid = tag[2:]
                    if oid in self.objs and self.objs[oid]["visible"] and oid not in self.erased:
                        hits.add(oid)
        if hits:
            self.erased |= hits
            self.send_reliable({"type": "ERASE", "ids": list(hits)})

    # ------------------------------------------------------------ rendering
    def make_item(self, kind, pts, color, width, text, tags, canvas=None):
        c = canvas or self.canvas
        if kind == "enc":                 # end-to-end encrypted and we have no (or the wrong) key: nothing to draw
            return None
        if kind == "image":
            ph = self.photos.get(tags[-1])
            if ph is None:
                ph = self.photos[tags[-1]] = tk.PhotoImage(master=self, data=text)    # `text` carries base64 data here
            return c.create_image(*pts[0], image=ph, anchor="nw", tags=tags)
        if kind == "stroke":
            if len(pts) == 1:
                x, y = pts[0]
                r = max(width / 2, 1)
                return c.create_oval(x - r, y - r, x + r, y + r, fill=color, outline=color, tags=tags)
            return c.create_line(*[v for p in pts for v in p], fill=color, width=width,
                                 capstyle="round", joinstyle="round", tags=tags)
        if kind == "line":
            return c.create_line(*pts[0], *pts[1], fill=color, width=width, capstyle="round", tags=tags)
        if kind == "rect":
            return c.create_rectangle(*pts[0], *pts[1], outline=color, width=width, tags=tags)
        if kind == "oval":
            return c.create_oval(*pts[0], *pts[1], outline=color, width=width, tags=tags)
        if kind == "sticky":
            x, y = pts[0]
            c.create_rectangle(x, y, x + 160, y + 120, fill=pastel(color), outline=color, width=2, tags=tags)
            return c.create_text(x + 8, y + 8, text=text or "", width=144, anchor="nw",
                                 fill="black", font=("Arial", 11), tags=tags)
        return c.create_text(*pts[0], text=text or "", fill=color, anchor="nw",
                             font=("Arial", int(width) * 3 + 8), tags=tags)

    def draw_obj(self, obj, visible):
        self.canvas.delete("o_" + obj["id"])
        payload = obj.get("data") if obj["kind"] == "image" else obj.get("text")
        self.make_item(obj["kind"], obj["points"], obj["color"], obj["width"],
                       payload, ("obj", "o_" + obj["id"]))
        self.canvas.itemconfigure("o_" + obj["id"], state="normal" if visible else "hidden")

    def load_snapshot(self, snap):
        """Replace everything from a full snapshot (join, reconnect, or big gap)."""
        self.canvas.delete("all")
        self.live.clear(); self.cursors.clear(); self.erased.clear(); self.photos.clear()
        self.objs, self.sealed = {}, {}
        for o in snap["objects"]:
            vis = o.pop("visible")
            o = self.reveal(o)
            self.objs[o["id"]] = {"obj": o, "visible": vis}
            self.draw_obj(o, vis)
        self.last_seq, self.resyncing = snap["seq"], False

    def apply_op(self, op):
        if op["seq"] <= self.last_seq:
            self.dup_ops += 1
            return                                  # duplicate / already applied
        if op["seq"] != self.last_seq + 1:          # gap: ask the server for what we missed
            if not self.resyncing:
                self.resyncing = True
                self.resync_at = time.time()
                self.gaps += 1
                self.net.send({"type": "RESYNC_REQ", "since": self.last_seq})
            return
        self.last_seq = op["seq"]
        if op["op"] == "ADD":
            o = self.reveal(op["obj"])
            self.pending_plain.pop(o["id"], None)
            self.objs[o["id"]] = {"obj": o, "visible": True}
            self.draw_obj(o, True)
            if op.get("by") == self.me:
                self.canvas.delete("preview")
                self.draw_pending()                 # the ones still waiting for their turn stay visible
            if op.get("by") in self.live:
                self.canvas.delete(self.live.pop(op["by"]))
        elif op["op"] == "MOVE":
            for i in op["ids"]:
                if self.drag and i in self.drag["ids"] and op.get("by") != self.me:
                    d, self.drag = self.drag, None      # someone else moved it under my mouse: theirs wins
                    for j in d["ids"]:                  # put my preview back where the objects really are
                        if j in self.objs:
                            self.draw_obj(self.objs[j]["obj"], self.objs[j]["visible"])
                self.shift_obj(i, op["dx"], op["dy"])
            if self.sel and not self.drag:
                self.show_selection()
        else:
            for i in op["ids"]:
                if i in self.objs:
                    self.objs[i]["visible"] = op["visible"]
                    self.canvas.itemconfigure("o_" + i, state="normal" if op["visible"] else "hidden")
                self.erased.discard(i)
            if self.sel and not self.drag:
                self.show_selection()               # an erased object leaves the selection

    # ------------------------------------------------------------ message pump
    def pump(self):
        try:
            while True:
                m = self.q.get_nowait()
                try:
                    self.handle(m)
                except Exception:                  # one bad message must never stop the message pump
                    import traceback
                    traceback.print_exc()
        except queue.Empty:
            pass
        self.after(20, self.pump)

    def handle(self, m):
        t = m.get("type")
        if not (t or "_").startswith("_") and t != "PONG":
            self.awaiting = False
        if t == "AUTH_OK":
            self.jwt, self.jwt_user, self.jwt_exp = m["jwt"], m["user"], m["exp"]
            self.jwt_server, self.me, self.my_rooms = (self.conn, self.use_tls), m["user"], m.get("rooms", [])
            if hasattr(self, "vars"):
                self.vars["apw"].set("")            # the password is not needed any more: the token is used
                self.vars["user"].set(m["user"])
            self.show_auth()
            if self.pending:                        # Create/Join was clicked before logging in
                msg, self.pending = self.pending, None
                msg["jwt"] = self.jwt
                self.awaiting = True
                self.net.send(msg)
        elif t == "AUTH_ERR":
            self.pending = None
            messagebox.showerror("Account", m["text"])
        elif t == "ROOMS":
            self.my_rooms = m["rooms"]
            self.show_auth()
        elif t == "_CERT_CHANGED":
            self.go_offline("The server's TLS certificate changed, so the automatic reconnect was stopped "
                            "(possible man-in-the-middle). Go back to the login screen to review it.")
        elif t == "JOIN_OK":
            first = not hasattr(self, "canvas")
            self.room, self.token, self.role = m["room"], m["token"], m["role"]
            self.me = m.get("user", self.me)
            self.host_user = m["host"]
            self.users = m["users"]
            if first:
                self.build_main()
            was_reconnect = self.reconnecting
            if self.reconnecting:
                self.reconnects += 1
            self.reconnecting = False
            if was_reconnect and self.rc_target and self.rc_target != (self.conn, self.use_tls):
                old = self.conn                       # we are on a standby that took over: stay with it
                self.conn, self.use_tls = self.rc_target
                if self.jwt:
                    self.jwt_server = (self.conn, self.use_tls)
                self.failovers += 1
            else:
                old = None
            self.status.config(text=f"Room code: {self.room}", foreground="#006")
            self.show_security()
            self.load_snapshot(m["snapshot"])
            self.web_port, self.voice_port = m.get("web"), m.get("voice")
            if self.vc:                               # voice follows the board to the new connection
                self.start_voice()
            self.set_backups(m.get("backups", []))
            self.show_chaos(m.get("chaos"))
            for i, req in enumerate(self.outbox.values(), 1):    # new connection: number the requests from 1
                req["rn"] = i
            self.rn, self.sent_at, self.rto_tries = len(self.outbox), time.time(), 0
            self.chat.config(state="normal"); self.chat.delete("1.0", "end"); self.chat.config(state="disabled")
            for c in m["chat"]:
                self.add_chat(f"[{c['ts']}] {c['user']}: {self.chat_text(c['text'])}")
            self.refresh_users()
            if old:
                self.add_chat(f"* FAILOVER: {old[0]}:{old[1]} is down - now connected to the standby server "
                              f"{self.conn[0]}:{self.conn[1]}. Nothing was lost.")
            if was_reconnect and self.outbox:     # whatever the server never confirmed goes out again
                self.draw_pending()
                self.add_chat(f"* back online - delivering {len(self.outbox)} action(s) made while offline")
                self.resend_outbox()
        elif t == "JOIN_ERR" and m.get("code") == "STANDBY" and self.reconnecting:
            self.net.close()                      # a standby that has not taken over (yet): keep looking
            self.rc_idx += 1
            threading.Thread(target=self._reconnect_loop, args=(1.0,), daemon=True).start()
        elif t == "JOIN_ERR":
            self.net.close()
            if self.reconnecting:                 # our room is gone (server restarted) or we were banned
                text = m["text"]
                if m.get("code") == "NO_ROOM":
                    text = ("The room no longer exists on the server - the server was probably restarted, "
                            "and rooms live only in its memory.")
                self.go_offline(text)
            else:
                if m.get("code") == "AUTH":           # token missing, expired or from another server
                    self.jwt = None
                    self.show_auth()
                messagebox.showerror("Cannot join", m["text"])
        elif t == "ACK":
            for oid in self.moves.pop(m.get("msg_id"), []):     # my drag preview -> the server's position
                if oid in self.objs:                             # (corrects it if the move was refused)
                    self.draw_obj(self.objs[oid]["obj"], self.objs[oid]["visible"])
            if self.sel and not self.drag:
                self.show_selection()
            if self.outbox.pop(m.get("msg_id"), None) is not None:
                self.acked += 1
                self.sent_at, self.rto_tries = time.time(), 0      # progress: restart the retransmit timer
            if m.get("dup"):
                self.dup_acks += 1
        elif t == "CHAOS":
            self.show_chaos(m.get("chaos"))
            self.add_chat(f"* chaos lab {'ON' if m.get('chaos') else 'off'} (set by {m.get('by')})")
        elif t == "BACKUPS":
            self.set_backups(m.get("backups", []))
        elif t == "INVITE":
            self.show_invite(m)
        elif t == "REPLAY":
            self.show_replay(m["ops"])
        elif t == "_DIAG":
            self.diag_line(m)
        elif t == "FILE_OFFER":
            self.file_offered(m)
        elif t == "FILE_REPLY":
            self.file_reply(m)
        elif t == "_FILE":
            self.file_event(m)
        elif t == "LASER":
            self.laser_at(m["x"], m["y"], m.get("user"))
        elif t == "KICKED":
            self.go_offline(m.get("text", "You were removed from the room by the host"))
        elif t == "_DISCOVERED":
            self.show_servers(m["servers"])
        elif t == "OP":
            self.apply_op(m)
        elif t == "OPS_SINCE":
            self.resyncing = False
            for op in m["ops"]:
                self.apply_op(op)
        elif t == "PONG":
            if m.get("t") is not None:
                rtt = max(0.0, time.time() * 1000 - m["t"])
                self.rtts.append(rtt)
                self.pongs += 1
                self.net.last_rtt = round(rtt, 1)
            self.srv_stats, self.peers = m.get("stats", {}), m.get("peers", {})
            self.kinds = m.get("kinds", {})
            # Heartbeat anti-entropy: the PONG says which seq the room is at. If we are still behind on
            # two PONGs in a row without having moved, the last op(s) were lost with nothing after them
            # to reveal the gap - so ask for them.
            srv_seq = self.srv_stats.get("room_seq")
            if isinstance(srv_seq, int) and srv_seq > self.last_seq and not self.resyncing and self.room:
                if self.seq_at_pong == self.last_seq:
                    self.resyncing, self.resync_at = True, time.time()
                    self.hb_resyncs += 1
                    self.net.send({"type": "RESYNC_REQ", "since": self.last_seq})
                self.seq_at_pong = self.last_seq
            else:
                self.seq_at_pong = -1
            if hasattr(self, "canvas"):            # PONGs also arrive while still on the login screen
                self.update_badge()
                self.refresh_users()
        elif t == "VERSIONS":
            self.show_versions(m["versions"])
        elif t == "SNAPSHOT":
            self.load_snapshot(m)
        elif t == "LIVE":
            old = self.live.pop(m["user"], None)
            if old:
                self.canvas.delete(old)
            if len(m["points"]) > 1:
                self.live[m["user"]] = self.canvas.create_line(
                    *[v for p in m["points"] for v in p], fill=m["color"], width=m["width"],
                    capstyle="round", tags="livepreview")
        elif t == "CURSOR":
            self.draw_cursor(m)
        elif t == "CHAT":
            self.add_chat(f"[{m['ts']}] {m['user']}: {self.chat_text(m['text'])}")
        elif t == "USERS":
            self.users = m["users"]
            me = next((u for u in self.users if u["name"] == self.me), None)
            if me:
                self.role = me["role"]
            self.refresh_users()
        elif t == "INFO":
            self.add_chat("* " + m["text"])
        elif t == "ERROR":
            self.add_chat("! " + m["text"])
        elif t == "_DISCONNECTED":
            if not hasattr(self, "canvas"):           # still on the login screen
                if self.awaiting:
                    self.awaiting = False
                    messagebox.showerror("Disconnected", "The server closed the connection.\n\nIf the server "
                                         "uses TLS, tick 'Encrypted connection'; if it runs with --no-tls, untick it.")
            elif not self.offline:
                self.start_reconnect()

    def draw_cursor(self, m):
        col = next((u["color"] for u in self.users if u["name"] == m["user"]), "#444")
        tag = "cur_" + m["user"]
        self.canvas.delete(tag)
        x, y = m["x"], m["y"]
        self.canvas.create_oval(x - 4, y - 4, x + 4, y + 4, fill=col, outline="", tags=tag)
        self.canvas.create_text(x + 8, y + 2, text=m["user"], fill=col, anchor="w", tags=tag)
        self.cursors[m["user"]] = tag

    def refresh_users(self):
        keep = self.selected_user()          # keep the host's selection across the 1 Hz refresh
        self.plist.delete(0, "end")
        for i, u in enumerate(self.users):
            tags = ("host " if u["host"] else "") + (u["role"] if u["role"] == "viewer" else "")
            ms = self.peers.get(u["name"]) if u["online"] else None
            lat = f" {ms:.0f}ms" if isinstance(ms, (int, float)) else ""
            self.plist.insert("end", f"{'●' if u['online'] else '○'} {u['name']} {('('+tags.strip()+')') if tags.strip() else ''}{lat}")
            self.plist.itemconfig(i, fg=u["color"])
            if not u["online"]:
                self.canvas.delete("cur_" + u["name"])
            if u["name"] == keep:
                self.plist.selection_set(i)

    # ------------------------------------------------------------ network statistics
    def lat_stats(self):
        r = list(self.rtts)
        if not r:
            return None
        diffs = [abs(a - b) for a, b in zip(r, r[1:])]
        sent_done = max(self.net.pings_sent - 1, 1)     # newest ping may still be in flight
        loss = max(0.0, 100.0 * (1 - self.pongs / sent_done)) if self.net.pings_sent > 1 else 0.0
        return dict(now=r[-1], avg=sum(r) / len(r), min=min(r), max=max(r),
                    jitter=sum(diffs) / len(diffs) if diffs else 0.0, loss=min(loss, 100.0))

    def update_badge(self):
        st = self.lat_stats()
        if self.reconnecting or self.offline:
            self.lat_label.config(text="● offline", fg="red")
        elif st:
            col = "#2e7d32" if st["now"] < 50 else ("#ef6c00" if st["now"] < 150 else "#c62828")
            self.lat_label.config(text=f"● {st['now']:.0f} ms", fg=col)

    def net_tick(self, gen):
        """Once a second: compute throughput from the byte counters and refresh the window."""
        if gen != self.tick_gen or not hasattr(self, "canvas"):
            return                                   # main screen was closed (back to login)
        tx, rx = self.net.tx_bytes, self.net.rx_bytes
        self.rate = (tx - self._last_bytes[0], rx - self._last_bytes[1])
        self._last_bytes = (tx, rx)
        self.peak_up, self.peak_down = max(self.peak_up, self.rate[0]), max(self.peak_down, self.rate[1])
        self.update_badge()
        if self.netwin and self.netwin.winfo_exists():
            self.draw_network()
        if self.labwin and self.labwin.winfo_exists():
            self.draw_lab()
        if self.reconnecting:
            self.show_offline()
        self.show_security()
        self.after(1000, self.net_tick, gen)

    def open_network(self):
        if self.netwin and self.netwin.winfo_exists():
            self.netwin.lift()
            return
        self.netwin = w = tk.Toplevel(self)
        w.title("Network statistics")
        self.graph = tk.Canvas(w, width=420, height=120, bg="white", highlightthickness=1)
        self.graph.pack(padx=8, pady=(8, 4))
        self.net_text = tk.Text(w, width=62, height=46, font=("Courier", 10), state="disabled", bg="#f7f7f7")
        self.net_text.pack(padx=8, pady=(0, 8))
        self.draw_network()

    def draw_network(self):
        g, r = self.graph, list(self.rtts)
        g.delete("all")
        top = max(50.0, max(r) * 1.2) if r else 50.0
        for frac in (0.25, 0.5, 0.75):
            g.create_line(0, 120 * frac, 420, 120 * frac, fill="#eee")
        g.create_text(4, 4, anchor="nw", text=f"{top:.0f} ms", fill="#888", font=("Arial", 8))
        g.create_text(4, 116, anchor="sw", text="0", fill="#888", font=("Arial", 8))
        g.create_text(416, 4, anchor="ne", text="round-trip time, last 60 s", fill="#555", font=("Arial", 8))
        if len(r) > 1:
            step = 420 / 59
            pts = [v for i, x in enumerate(r) for v in (420 - (len(r) - 1 - i) * step, 118 - x / top * 112)]
            g.create_line(*pts, fill="#1565c0", width=2)
        st, sv = self.lat_stats(), self.srv_stats
        kb = lambda b: f"{b / 1024:8.1f} KB"
        L = ["LATENCY (client <-> server round trip)"]
        if st:
            L += [f"  now {st['now']:6.1f} ms    avg {st['avg']:6.1f} ms",
                  f"  min {st['min']:6.1f} ms    max {st['max']:6.1f} ms",
                  f"  jitter {st['jitter']:5.1f} ms   ping loss {st['loss']:4.1f} %"]
        else:
            L.append("  waiting for first reply...")
        L += ["", "THIS CLIENT TRAFFIC",
              f"  upload   {self.rate[0] / 1024:7.2f} KB/s   (peak {self.peak_up / 1024:.1f})",
              f"  download {self.rate[1] / 1024:7.2f} KB/s   (peak {self.peak_down / 1024:.1f})",
              f"  sent     {kb(self.net.tx_bytes)}   {self.net.tx_msgs:7d} msgs",
              f"  received {kb(self.net.rx_bytes)}   {self.net.rx_msgs:7d} msgs",
              "", "RELIABILITY",
              f"  connection        {'OFFLINE' if self.offline else 'RECONNECTING' if self.reconnecting else 'connected'} to {self.conn[0]}:{self.conn[1]} ({self.net.family})",
              f"  reconnects        {self.reconnects}",
              f"  awaiting ACK      {len(self.outbox)}    acked {self.acked}    resent {self.resent}",
              f"  duplicate ops ignored {self.dup_ops}    gaps resynced {self.gaps}",
              f"  retransmit timer  RTO {self.rto() * 1000:.0f} ms   retransmitted {self.retx}   dup ACKs {self.dup_acks}",
              f"  heartbeat resyncs {self.hb_resyncs}    failovers to standby {self.failovers}",
              f"  last op seq       {self.last_seq}",
              f"  session time      {int(time.time() - self.t_start)} s"]
        tr, tw, rr, rw = self.net.tx_raw, self.net.tx_bytes, self.net.rx_raw, self.net.rx_bytes
        pct = lambda raw, wire: f"{100 * (1 - wire / raw):4.1f} % saved" if raw else "-"
        L += ["", "BANDWIDTH OPTIMIZER (zlib frames + stroke simplification)",
              f"  sent     {kb(tr)} -> {kb(tw)}  {pct(tr, tw)}",
              f"  received {kb(rr)} -> {kb(rw)}  {pct(rr, rw)}",
              f"  stroke points drawn {self.pts_raw} -> sent {self.pts_sent}"
              + (f"  ({100 * (1 - self.pts_sent / self.pts_raw):.0f} % fewer)" if self.pts_raw else "")]
        if sv:
            L += ["", "SERVER", f"  uptime {sv.get('uptime', 0)} s    clients in room {sv.get('room_clients', '?')}",
                  f"  connections total {sv.get('conns', 0)}   reconnects {sv.get('reconnects', 0)}   timeouts {sv.get('timeouts', 0)}",
                  f"  traffic in {kb(sv.get('bytes_in', 0))} / out {kb(sv.get('bytes_out', 0))}",
                  f"  msgs in {sv.get('msgs_in', 0)} / out {sv.get('msgs_out', 0)}   ops committed {sv.get('ops', 0)}",
                  f"  duplicates dropped {sv.get('dups', 0)}   rejected {sv.get('rejected', 0)}",
                  f"  slow clients dropped {sv.get('slow_drops', 0)}   discovery replies {sv.get('discovery', 0)}"]
        ti = self.net.tls_info
        L += ["", "SECURITY"]
        if ti:
            L += [f"  {ti[0]}  cipher {ti[1]}", "  server certificate SHA-256 fingerprint:",
                  f"    {ti[2][:47]}", f"    {ti[2][48:]}"]
        else:
            L.append("  plain TCP - NOT encrypted (anyone on the LAN can read it)")
        if self.jwt:
            L.append(f"  logged in as {self.jwt_user}, JWT valid until "
                     f"{time.strftime('%H:%M', time.localtime(self.jwt_exp))}")
        if self.peers:
            L += ["", "PER-USER LATENCY (as measured by each client)"]
            L += [f"  {n:<16} {('%.0f ms' % v) if isinstance(v, (int, float)) else '-'}" for n, v in self.peers.items()]
        t = self.net_text
        t.config(state="normal")
        t.delete("1.0", "end")
        t.insert("end", "\n".join(L))
        t.config(state="disabled")

    # ------------------------------------------------------------ reconnection
    def start_reconnect(self):
        if self.reconnecting or not hasattr(self, "canvas"):
            return
        self.reconnecting = True
        self.rc_idx = 0
        self.show_offline()
        threading.Thread(target=self._reconnect_loop, daemon=True).start()

    def show_offline(self):
        """Offline mode: drawing keeps working; every action waits in the outbox and is delivered,
        once and in order, when the connection (or a standby server) is back."""
        n = len(self.outbox)
        self.status.config(foreground="red", text="OFFLINE - reconnecting. You can keep drawing: "
                           + (f"{n} action(s) saved, sent automatically on reconnect" if n else "nothing waiting"))

    def draw_pending(self):
        """Show my own not-yet-confirmed objects (drawn while offline) so the board does not look empty."""
        for req in self.outbox.values():
            if req.get("type") == "ADD":
                o = self.pending_plain.get(req["obj"]["id"], req["obj"])
                if o["id"] not in self.objs:
                    self.make_item(o["kind"], o["points"], o["color"], o["width"],
                                   o.get("data") if o["kind"] == "image" else o.get("text"),
                                   ("preview", "p_" + o["id"]))

    def _reconnect_loop(self, wait=0.0):
        """Try the server we were on, then every standby server we were told about, round and round."""
        time.sleep(wait)
        while self.reconnecting:
            targets = [(self.conn, self.use_tls)] + [((b["host"], b["port"]), bool(b.get("tls")))
                                                      for b in self.backups]
            conn, tls = targets[self.rc_idx % len(targets)]
            try:
                msg = {"type": "JOIN_ROOM", "user": self.me, "room": self.room,
                       "password": self.password, "token": self.token, "z": 1}
                if self.jwt:
                    msg["jwt"] = self.jwt
                self.rc_target = (conn, tls)
                self.net.connect(*conn, msg, tls=tls, check=self.check_cert_silent, timeout=2)
                return                          # JOIN_OK (with fresh snapshot) clears the flag
            except CertRejected:
                self.q.put({"type": "_CERT_CHANGED"})
                return
            except OSError:
                self.rc_idx += 1
                time.sleep(1 if len(targets) > 1 else 2)

    def go_offline(self, text):
        """The connection is gone for good (kicked, or the room vanished). Stop reconnecting, keep the
        board visible so it can still be exported, and offer to go back to the login screen."""
        self.offline, self.reconnecting = True, False
        self.net.close()
        self.outbox.clear()
        self.status.config(text="Disconnected: " + text, foreground="red")
        self.update_badge()
        self.add_chat("! " + text)
        if messagebox.askyesno("Disconnected", text + "\n\nThe board stays on screen (you can still Export PNG)."
                               "\n\nGo back to the login screen now?", parent=self):
            self.back_to_login()

    def back_to_login(self):
        self.net.close()
        for w in self.winfo_children():
            w.destroy()
        del self.canvas
        self.reset_session()
        self.title("LAN Whiteboard")
        self.build_login()
        if self.jwt and self.jwt_server == (self.conn, self.use_tls):
            self.send_first({"type": "MY_ROOMS", "jwt": self.jwt})     # refresh "Your rooms"

    # ------------------------------------------------------------ standby servers (failover)
    def set_backups(self, backups):
        """The server tells us where its standby servers are. Their TLS certificate fingerprints arrive
        over the connection we already trust, so we can remember them now and recognise the standby
        later without asking the user (trust is handed over, not assumed)."""
        self.backups = [b for b in backups if b.get("host") and b.get("port")]
        known, changed = self.load_known(), False
        for b in self.backups:
            key = f"{b['host']}:{b['port']}"
            if b.get("fp") and known.get(key) != b["fp"]:
                known[key], changed = b["fp"], True
        if changed:
            self.save_known(known)

    # ------------------------------------------------------------ chaos lab + network map
    def show_chaos(self, ch):
        self.chaos = ch
        if hasattr(self, "chaos_label"):
            self.chaos_label.config(text=f"\u26A1 chaos: {ch['loss']:.0f}% loss, {ch['delay']:.0f}\u00B1{ch['jitter']:.0f} ms"
                                    + (f", {ch['bw']:.0f} kbit/s" if ch.get("bw") else "") if ch else "")
        if self.labwin and self.labwin.winfo_exists():
            for k in ("loss", "delay", "jitter", "bw"):
                self.lab_vars[k].set(ch.get(k, 0) if ch else 0)
            self.draw_lab()

    def open_lab(self):
        if self.labwin and self.labwin.winfo_exists():
            self.labwin.lift()
            return
        self.labwin = w = tk.Toplevel(self)
        w.title("Chaos lab - break the network, watch it heal")
        self.lab_map = tk.Canvas(w, width=560, height=235, bg="white", highlightthickness=1)
        self.lab_map.pack(padx=8, pady=(8, 4))
        host = self.me == self.host_user
        box = ttk.LabelFrame(w, text="Emulated link between the server and every client in this room"
                             + ("" if host else "  (only the host can change it)"), padding=6)
        box.pack(fill="x", padx=8)
        self.lab_vars = {}
        for r, (k, label, top) in enumerate((("loss", "Message loss %", 60), ("delay", "Delay ms (each way)", 1000),
                                             ("jitter", "Jitter \u00B1 ms", 500),
                                             ("bw", "Bandwidth cap kbit/s (0 = off)", 512))):
            v = self.lab_vars[k] = tk.DoubleVar(self, value=(self.chaos or {}).get(k, 0))
            ttk.Label(box, text=label, width=28).grid(row=r, column=0, sticky="w")
            sc = tk.Scale(box, from_=0, to=top, orient="horizontal", variable=v, length=300, resolution=1,
                          state="normal" if host else "disabled")
            sc.grid(row=r, column=1)
            sc.bind("<ButtonRelease-1>", lambda e: self.send_chaos())
        if host:
            row = ttk.Frame(box)
            row.grid(row=4, column=0, columnspan=2, pady=(6, 0), sticky="w")
            for txt, vals in (("Off", (0, 0, 0, 0)), ("Busy Wi-Fi", (5, 80, 30, 0)), ("Bad link", (20, 200, 80, 0)),
                              ("Terrible", (40, 400, 150, 0)), ("Narrow link", (0, 0, 0, 24))):
                ttk.Button(row, text=txt, command=lambda vals=vals: self.send_chaos(vals)).pack(side="left", padx=2)
            ttk.Button(row, text="Reset counters", command=lambda: self.send_chaos(reset=True)).pack(side="left", padx=8)
        self.lab_text = tk.Text(w, width=78, height=16, font=("Courier", 10), state="disabled", bg="#f7f7f7")
        self.lab_text.pack(padx=8, pady=8)
        self.draw_lab()

    def send_chaos(self, vals=None, reset=False):
        if vals:
            for k, v in zip(("loss", "delay", "jitter", "bw"), vals):
                self.lab_vars[k].set(v)
        self.net.send({"type": "CHAOS_SET", "reset": reset, **{k: v.get() for k, v in self.lab_vars.items()}})

    def draw_lab(self):
        """Network map (server, standby, every online client with its latency) and the repair counters."""
        g, sv = self.lab_map, self.srv_stats
        g.delete("all")
        sx, sy = 280, 50
        online = [u for u in self.users if u["online"]]
        n = max(len(online), 1)
        for i, u in enumerate(online):
            x, y = 560 * (i + 1) / (n + 1), 195
            ms = self.peers.get(u["name"])
            good = isinstance(ms, (int, float))
            col = "#888" if not good else "#2e7d32" if ms < 50 else "#ef6c00" if ms < 150 else "#c62828"
            g.create_line(sx, sy + 22, x, y - 20, fill=col, width=2, dash=(6, 4) if self.chaos else None)
            g.create_text((sx + x) / 2 + 6, (sy + y) / 2, text=f"{ms:.0f} ms" if good else "?", fill=col,
                          anchor="w", font=("Arial", 9, "bold"))
            web = self.kinds.get(u["name"]) == "web"
            g.create_rectangle(x - 46, y - 20, x + 46, y + 20, fill="#fff8e1" if web else "#e3f2fd",
                               outline=u["color"], width=3 if u["name"] == self.me else 1)
            g.create_text(x, y - 6, text=u["name"][:14], font=("Arial", 9, "bold"))
            g.create_text(x, y + 9, text=("browser / WebSocket" if web else "desktop / TCP")
                          + (" (me)" if u["name"] == self.me else ""), font=("Arial", 7), fill="#555")
        g.create_rectangle(sx - 70, sy - 22, sx + 70, sy + 22, fill="#e8f5e9", outline="#2e7d32", width=2)
        g.create_text(sx, sy - 7, text="SERVER (primary)", font=("Arial", 9, "bold"))
        g.create_text(sx, sy + 9, text=f"{self.conn[0]}:{self.conn[1]}  seq {sv.get('room_seq', '?')}",
                      font=("Arial", 8), fill="#555")
        for i, b in enumerate(self.backups[:1]):
            bx = 480
            g.create_line(sx + 70, sy, bx - 60, sy, fill="#6a1b9a", width=2, dash=(3, 3), arrow="last")
            g.create_text((sx + 70 + bx - 60) / 2, sy - 9, text="replication", fill="#6a1b9a", font=("Arial", 8))
            g.create_rectangle(bx - 60, sy - 22, bx + 60, sy + 22, fill="#f3e5f5", outline="#6a1b9a", width=2)
            g.create_text(bx, sy - 7, text="STANDBY", font=("Arial", 9, "bold"))
            g.create_text(bx, sy + 9, text=f"{b['host']}:{b['port']}", font=("Arial", 8), fill="#555")
        if self.chaos:
            g.create_text(8, 8, anchor="nw", fill="#b26a00", font=("Arial", 10, "bold"),
                          text=f"\u26A1 CHAOS ON: {self.chaos['loss']:.0f}% loss, "
                               f"{self.chaos['delay']:.0f} \u00B1 {self.chaos['jitter']:.0f} ms"
                               + (f", {self.chaos['bw']:.0f} kbit/s cap" if self.chaos.get("bw") else ""))
        srv_seq = sv.get("room_seq")
        state = ("IN SYNC with the server" if srv_seq == self.last_seq and not self.outbox else
                 f"catching up ({len(self.outbox)} request(s) awaiting ACK)")
        L = ["DAMAGE DONE BY THE SERVER ON PURPOSE (this room)",
             f"  dropped: client->server {sv.get('chaos_in', 0)}   server->client {sv.get('chaos_out', 0)}",
             f"  requests held back until an earlier lost one arrived: {sv.get('out_of_order', 0)}",
             "", "QUALITY OF SERVICE (board ops are always sent before cursors / live previews)",
             f"  stale cursor/preview frames shed on slow links {sv.get('qos_shed', 0)}   "
             f"refused by rate limit {sv.get('qos_limited', 0)}",
             "", "HOW THIS CLIENT REPAIRED IT",
             f"  retransmitted requests   {self.retx:5d}   (timeout now {self.rto() * 1000:.0f} ms)",
             f"  duplicate ACKs received  {self.dup_acks:5d}   (the ACK was lost, not the request)",
             f"  sequence-gap resyncs     {self.gaps:5d}   heartbeat resyncs {self.hb_resyncs}",
             f"  duplicate ops ignored    {self.dup_ops:5d}",
             "", f"RESULT: my seq {self.last_seq} / server seq {srv_seq}  ->  {state}"]
        t = self.lab_text
        t.config(state="normal")
        t.delete("1.0", "end")
        t.insert("end", "\n".join(L))
        t.config(state="disabled")

    # ------------------------------------------------------------ packet inspector
    @staticmethod
    def summarize(m):
        t = m.get("type")
        if t == "OP":
            what = m["obj"]["kind"] if m.get("op") == "ADD" else \
                f"{len(m.get('ids', []))} ids by ({m.get('dx')}, {m.get('dy')})" if m.get("op") == "MOVE" else \
                f"{len(m.get('ids', []))} ids -> {'show' if m.get('visible') else 'hide'}"
            return f"seq={m.get('seq')} {m.get('op')} {what} by {m.get('by')}"
        if t == "ADD":
            return f"rn={m.get('rn')} {m['obj'].get('kind')} {len(m['obj'].get('points', []))} pts"
        if t == "ACK":
            return f"msg_id={str(m.get('msg_id'))[:8]}" + (" DUPLICATE" if m.get("dup") else "")
        if t == "PING":
            return f"last rtt={m.get('rtt')}"
        if t == "PONG":
            return f"room seq={m.get('stats', {}).get('room_seq')}"
        if t in ("JOIN_OK", "SNAPSHOT"):
            snap = m.get("snapshot", m)
            return f"snapshot seq={snap.get('seq')} {len(snap.get('objects', []))} objects"
        if t == "OPS_SINCE":
            return f"{len(m.get('ops', []))} missed ops"
        if t in ("CHAT", "INFO", "ERROR"):
            return str(m.get("text", ""))[:40]
        if t in ("CURSOR", "LASER"):
            return f"x={m.get('x')} y={m.get('y')}"
        if m.get("rn"):
            return f"rn={m['rn']}"
        return ", ".join(k for k in m if k != "type")[:40]

    def open_inspector(self):
        if self.inspwin and self.inspwin.winfo_exists():
            self.inspwin.lift()
            return
        self.inspwin = w = tk.Toplevel(self)
        w.title("Packet inspector - every frame on this client's connection")
        top = ttk.Frame(w)
        top.pack(fill="x", padx=6, pady=4)
        self.insp_opts = {k: tk.BooleanVar(self, value=v) for k, v in
                          (("beat", True), ("mouse", True), ("pause", False))}
        for k, txt in (("beat", "Hide PING/PONG"), ("mouse", "Hide CURSOR/LIVE/LASER"), ("pause", "Pause")):
            ttk.Checkbutton(top, text=txt, variable=self.insp_opts[k], command=self.insp_rebuild).pack(side="left", padx=4)
        ttk.Button(top, text="Clear", command=lambda: (self.net.trace.clear(), self.insp_rebuild())).pack(side="left", padx=8)
        nb = ttk.Notebook(w)
        nb.pack(fill="both", expand=True, padx=6)
        f1 = ttk.Frame(nb)
        nb.add(f1, text="Frames")
        cols = (("n", "#", 50), ("time", "Time", 90), ("dir", "Direction", 110), ("type", "Type", 90),
                ("info", "Summary", 300), ("wire", "Wire bytes", 80), ("raw", "Uncompressed", 90))
        self.insp_tree = tr = ttk.Treeview(f1, columns=[c[0] for c in cols], show="headings", height=14)
        for cid, title, wd in cols:
            tr.heading(cid, text=title)
            tr.column(cid, width=wd, anchor="w")
        tr.tag_configure("tx", foreground="#1565c0")
        tr.tag_configure("rx", foreground="#2e7d32")
        tr.tag_configure("retx", foreground="#c62828")
        sb = ttk.Scrollbar(f1, orient="vertical", command=tr.yview)
        tr.configure(yscrollcommand=sb.set)
        tr.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
        self.insp_detail = tk.Text(f1, height=9, font=("Courier", 9), state="disabled", bg="#f7f7f7", wrap="word")
        self.insp_detail.grid(row=1, column=0, columnspan=2, sticky="ew", pady=4)
        f1.rowconfigure(0, weight=1)
        f1.columnconfigure(0, weight=1)
        tr.bind("<<TreeviewSelect>>", self.insp_select)
        f2 = ttk.Frame(nb)
        nb.add(f2, text="Sequence diagram")
        self.insp_seq = tk.Canvas(f2, width=800, height=470, bg="white", highlightthickness=0)
        self.insp_seq.pack(fill="both", expand=True)
        self.insp_last, self.insp_rows = 0, {}
        self.insp_tick()

    def insp_wanted(self, rec):
        t = rec[3].get("type")
        if self.insp_opts["beat"].get() and t in ("PING", "PONG"):
            return False
        return not (self.insp_opts["mouse"].get() and t in ("CURSOR", "LIVE", "LASER"))

    def insp_rebuild(self):
        self.insp_tree.delete(*self.insp_tree.get_children())
        self.insp_last, self.insp_rows = 0, {}
        self.insp_fill()

    def insp_fill(self):
        tr, added = self.insp_tree, False
        for rec in list(self.net.trace):
            n, ts, d, m, wire, raw, z, retx = rec
            if n <= self.insp_last:
                continue
            self.insp_last = n
            if not self.insp_wanted(rec):
                continue
            stamp = time.strftime("%H:%M:%S", time.localtime(ts)) + f".{int(ts * 1000) % 1000:03d}"
            arrow = ("client \u2192 server" if d == "tx" else "server \u2192 client") + (" RETX" if retx else "")
            iid = tr.insert("", "end", values=(n, stamp, arrow, m.get("type"), self.summarize(m), wire,
                                               f"{raw} (zlib)" if z else raw),
                            tags=("retx" if retx or m.get("dup") else d,))
            self.insp_rows[iid] = rec
            added = True
        kids = tr.get_children()
        for iid in kids[:max(0, len(kids) - 600)]:            # keep the list short
            tr.delete(iid)
            self.insp_rows.pop(iid, None)
        if added:
            tr.see(tr.get_children()[-1])
        return added

    def insp_tick(self):
        if not (self.inspwin and self.inspwin.winfo_exists()):
            return
        if not self.insp_opts["pause"].get() and self.insp_fill():
            self.insp_draw_seq()
        self.after(400, self.insp_tick)

    def insp_select(self, _e=None):
        sel = self.insp_tree.selection()
        rec = self.insp_rows.get(sel[0]) if sel else None
        if not rec:
            return

        def short(v):                                  # do not print 500 KB of image data
            if isinstance(v, str) and len(v) > 100:
                return v[:100] + f"... ({len(v)} chars)"
            if isinstance(v, list) and len(v) > 12:
                return [short(x) for x in v[:12]] + [f"... ({len(v)} items)"]
            if isinstance(v, list):
                return [short(x) for x in v]
            if isinstance(v, dict):
                return {k: short(x) for k, x in v.items()}
            return v
        n, ts, d, m, wire, raw, z, retx = rec
        head = (f"frame #{n}: 4-byte length prefix + {wire - 4} byte body"
                + (f" (zlib-compressed, {raw - 4} bytes of JSON inside; flag = top bit of the length)" if z else " (plain JSON)")
                + (" - RETRANSMISSION" if retx else "") + "\n")
        t = self.insp_detail
        t.config(state="normal")
        t.delete("1.0", "end")
        t.insert("end", head + json.dumps(short(m), indent=1))
        t.config(state="disabled")

    def insp_draw_seq(self):
        """Message sequence chart of the newest frames: client lifeline on the left, server on the right."""
        g = self.insp_seq
        g.delete("all")
        recs = [r for r in self.net.trace if self.insp_wanted(r)][-20:]
        cx, sx = 170, 650
        for x, name in ((cx, f"Client ({self.me})"), (sx, f"Server {self.conn[0]}:{self.conn[1]}")):
            g.create_rectangle(x - 90, 6, x + 90, 30, fill="#eceff1", outline="#607d8b")
            g.create_text(x, 18, text=name, font=("Arial", 9, "bold"))
            g.create_line(x, 30, x, 465, fill="#90a4ae", dash=(4, 3))
        for i, (n, ts, d, m, wire, raw, z, retx) in enumerate(recs):
            y = 46 + i * 21
            col = "#c62828" if retx or m.get("dup") else "#1565c0" if d == "tx" else "#2e7d32"
            x0, x1 = (cx, sx) if d == "tx" else (sx, cx)
            g.create_line(x0, y, x1, y + 8, fill=col, width=2, arrow="last")
            label = f"{m.get('type')}  {self.summarize(m)}"[:62] + (f"   [{wire} B{' z' if z else ''}]")
            g.create_text((cx + sx) / 2, y - 3, text=("RETX " if retx else "") + label, fill=col, font=("Arial", 8))
            g.create_text(6, y + 4, anchor="w", fill="#777", font=("Courier", 8),
                          text=time.strftime("%H:%M:%S", time.localtime(ts)) + f".{int(ts * 1000) % 1000:03d}")

    # ------------------------------------------------------------ time-travel replay
    def open_replay(self):
        self.net.send({"type": "REPLAY_REQ"})          # the answer (REPLAY) opens the window

    def show_replay(self, ops):
        if self.replaywin and self.replaywin.winfo_exists():
            self.replaywin.destroy()
        self.replaywin = w = tk.Toplevel(self)
        w.title(f"Time travel - room {self.room}: {len(ops)} operations from the server's op log")
        self.rp_ops, self.rp_pos, self.rp_playing = ops, 0, False
        self.rp_canvas = tk.Canvas(w, width=CANVAS_W, height=CANVAS_H, bg="white", highlightthickness=1)
        self.rp_canvas.pack()
        row = ttk.Frame(w, padding=4)
        row.pack(fill="x")
        self.rp_btn = ttk.Button(row, text="\u25B6 Play", width=9, command=self.rp_toggle)
        self.rp_btn.pack(side="left")
        self.rp_speed = tk.StringVar(self, value="8 ops/s")
        ttk.Combobox(row, textvariable=self.rp_speed, values=["2 ops/s", "8 ops/s", "30 ops/s", "120 ops/s"],
                     width=10, state="readonly").pack(side="left", padx=4)
        self.rp_var = tk.IntVar(self, value=0)
        self.rp_scale = tk.Scale(row, from_=0, to=max(len(ops), 1), orient="horizontal", variable=self.rp_var,
                                 showvalue=False, command=lambda v: self.rp_goto(int(float(v))))
        self.rp_scale.pack(side="left", fill="x", expand=True, padx=6)
        self.rp_label = ttk.Label(row, text="", width=46)
        self.rp_label.pack(side="left")
        self.rp_goto(len(ops))                          # start at "now"; drag left or press Play to go back

    def rp_goto(self, k):
        """Show the board as it was after the first k operations. Going forward applies ops one by one
        (exactly what a client does live); going back starts again from an empty board."""
        if not (self.replaywin and self.replaywin.winfo_exists()):
            return
        c, k = self.rp_canvas, max(0, min(k, len(self.rp_ops)))
        if k < self.rp_pos:
            c.delete("all")
            self.rp_pos = 0
        for op in self.rp_ops[self.rp_pos:k]:
            if op["op"] == "ADD":
                o = self.reveal(op["obj"], track=False)
                self.make_item(o["kind"], o["points"], o["color"], o["width"],
                               o.get("data") if o["kind"] == "image" else o.get("text"),
                               ("obj", "o_" + o["id"]), canvas=c)
            elif op["op"] == "MOVE":
                for i in op["ids"]:
                    c.move("o_" + i, op["dx"], op["dy"])
            else:
                for i in op["ids"]:
                    c.itemconfigure("o_" + i, state="normal" if op["visible"] else "hidden")
        self.rp_pos = k
        self.rp_var.set(k)
        if k:
            op = self.rp_ops[k - 1]
            what = ("drew " + op["obj"]["kind"]) if op["op"] == "ADD" else \
                   (f"moved {len(op['ids'])} object(s) by ({op['dx']}, {op['dy']})") if op["op"] == "MOVE" else \
                   (("restored " if op["visible"] else "erased / undid ") + f"{len(op['ids'])} object(s)")
            self.rp_label.config(text=f"op {k}/{len(self.rp_ops)}: {op.get('by', '?')} {what}")
        else:
            self.rp_label.config(text=f"op 0/{len(self.rp_ops)}: empty board")

    def rp_toggle(self):
        self.rp_playing = not self.rp_playing
        if self.rp_playing:
            if self.rp_pos >= len(self.rp_ops):
                self.rp_goto(0)
            self.rp_step()
        self.rp_btn.config(text="\u23F8 Pause" if self.rp_playing else "\u25B6 Play")

    def rp_step(self):
        if not (self.rp_playing and self.replaywin and self.replaywin.winfo_exists()):
            return
        if self.rp_pos >= len(self.rp_ops):
            self.rp_playing = False
            self.rp_btn.config(text="\u25B6 Play")
            return
        self.rp_goto(self.rp_pos + 1)
        self.after(int(1000 / int(self.rp_speed.get().split()[0])), self.rp_step)

    # ------------------------------------------------------------ phone / browser join
    def show_invite(self, m):
        if not m.get("url"):
            return messagebox.showinfo("Phone join", "The server was started with --no-web (or its web port is "
                                                     "in use), so browsers cannot join.", parent=self)
        if self.qrwin and self.qrwin.winfo_exists():
            self.qrwin.destroy()
        self.qrwin = w = tk.Toplevel(self)
        w.title("Join from a phone or any browser")
        ttk.Label(w, text="Scan with a phone on the same Wi-Fi / LAN - or open the link in any browser.",
                  padding=8).pack()
        if qrcode:
            qr = qrcode.QRCode(border=3, error_correction=qrcode.constants.ERROR_CORRECT_L)
            qr.add_data(m["url"])
            qr.make(fit=True)
            mat = qr.get_matrix()
            px = max(3, min(8, 420 // len(mat)))
            c = tk.Canvas(w, width=px * len(mat), height=px * len(mat), bg="white", highlightthickness=0)
            c.pack(padx=12)
            for y, line in enumerate(mat):
                for x, on in enumerate(line):
                    if on:
                        c.create_rectangle(x * px, y * px, (x + 1) * px, (y + 1) * px, fill="black", outline="")
        else:
            ttk.Label(w, text="(install the 'qrcode' package to show a QR code here: pip install qrcode)",
                      foreground="#888").pack()
        e = ttk.Entry(w, width=70)
        e.insert(0, m["url"])
        e.config(state="readonly")
        e.pack(padx=12, pady=8)

        def copy():
            self.clipboard_clear()
            self.clipboard_append(m["url"])
        ttk.Button(w, text="Copy link", command=copy).pack()
        ttk.Label(w, foreground="#666", padding=8, justify="center",
                  text=f"The link holds a signed invite (JWT) for room {m['room']} only, valid until "
                       f"{time.strftime('%H:%M', time.localtime(m['exp']))}.\nGuests appear as 'name (web)'. "
                       "The browser page uses HTTP + WebSocket on the server's web port.").pack()

    # ------------------------------------------------------------ end-to-end encryption
    def reveal(self, o, track=True):
        """An object as it should be drawn: end-to-end encrypted ones are decrypted with the room key.
        Without the right key the object stays sealed (and is remembered, to open when a key is set)."""
        if o.get("kind") != "enc":
            return o
        plain = e2e.unseal(self.e2e_keys, o.get("data", "")) if self.e2e_keys else None
        if plain is not None:
            try:
                inner = json.loads(plain.decode("utf-8"))
                if isinstance(inner, dict) and inner.get("kind") not in (None, "enc") and "points" in inner:
                    if track:
                        self.sealed.pop(o["id"], None)
                    ox, oy = (o.get("points") or [[0, 0]])[0]      # a moved encrypted object: the server only
                    if ox or oy:                                      # knows its offset, the shape is inside
                        inner["points"] = [[x + ox, y + oy] for x, y in inner["points"]]
                    return {**inner, "id": o["id"], "owner": o.get("owner")}
            except ValueError:
                pass
        if track:
            self.sealed[o["id"]] = o
        return o

    def ask_e2e(self):
        s = simpledialog.askstring(
            "End-to-end key", "Passphrase for this room (everyone must type the same one; it is never sent).\n"
            "From now on your drawings and chat are encrypted on this PC; the server relays\nand stores "
            "only ciphertext. Leave empty to turn it off.", show="*", parent=self)
        if s is not None:
            self.set_e2e(s)

    def set_e2e(self, passphrase):
        self.e2e_keys = e2e.derive(passphrase, self.room) if passphrase else None
        for oid, o in list(self.sealed.items()):          # try the new key on everything still sealed
            plain = self.reveal(o)
            if plain is not o and oid in self.objs:
                self.objs[oid]["obj"] = plain
                self.draw_obj(plain, self.objs[oid]["visible"])
        self.e2e_btn.config(text="E2E: ON" if self.e2e_keys else "E2E key")
        self.show_security()
        self.add_chat("* end-to-end encryption " + ("ON: your new drawings and chat are unreadable for the server"
                                                    if self.e2e_keys else "off"))

    # ------------------------------------------------------------ peer-to-peer file transfer
    @staticmethod
    def download_dir():
        if os.environ.get("WB_DOWNLOADS"):
            return os.environ["WB_DOWNLOADS"]
        d = os.path.join(os.path.expanduser("~"), "Downloads")
        return os.path.join(d if os.path.isdir(d) else os.path.expanduser("~"), "whiteboard-files")

    def send_file(self, path=None):
        to = self.selected_user()
        if not to or to == self.me:
            return messagebox.showinfo("Send file", "Select another participant in the list first.", parent=self)
        path = path or filedialog.askopenfilename(title=f"File to send to {to}")
        if not path:
            return
        self.file_label.config(text="hashing " + os.path.basename(path) + " ...")

        def prepare():                                   # hashing a big file must not freeze the window
            try:
                sha = p2p.sha256_file(path)
                token = uuid.uuid4().hex
                snd = p2p.Sender(path, token, lambda kind, a, b: self.q.put(
                    {"type": "_FILE", "ev": "out_" + kind, "a": a, "b": b, "name": os.path.basename(path)}))
                self.q.put({"type": "_FILE", "ev": "offer", "sender": snd, "sha": sha, "to": to, "id": token,
                            "name": os.path.basename(path)})
            except OSError as e:
                self.q.put({"type": "_FILE", "ev": "error", "text": f"cannot send {path}: {e}"})
        threading.Thread(target=prepare, daemon=True).start()

    def file_offered(self, m):
        mb = m["size"] / 1e6
        if not messagebox.askyesno("Incoming file", f"{m['from']} wants to send you:\n\n{m['name']}  ({mb:.2f} MB)\n\n"
                                   f"It comes directly from {m['from']}'s PC (peer to peer) and is saved in\n"
                                   f"{self.download_dir()}\n\nAccept?", parent=self):
            return self.net.send({"type": "FILE_REPLY", "to": m["from"], "id": m["id"], "status": "declined"})
        host = self.conn[0] if is_loopback(m["ip"]) else m["ip"]   # sender sits on the server PC: use its LAN address
        self.net.send({"type": "FILE_REPLY", "to": m["from"], "id": m["id"], "status": "accepted"})
        self.add_chat(f"* receiving {m['name']} directly from {m['from']} ({host}:{m['port']}) ...")

        def work():
            t0, last = time.time(), [0.0]

            def progress(got, size):
                if time.time() - last[0] > 0.2 or got == size:
                    last[0] = time.time()
                    self.q.put({"type": "_FILE", "ev": "in_progress", "a": got, "b": size, "name": m["name"]})
            try:
                path = p2p.fetch(host, m["port"], m["id"], m["name"], m["size"], m["sha"], self.download_dir(), progress)
                secs = max(time.time() - t0, 0.001)
                self.q.put({"type": "_FILE", "ev": "received", "path": path, "m": m,
                            "text": f"{m['name']}, {mb:.2f} MB at {mb / secs:.1f} MB/s, SHA-256 verified"})
            except (OSError, ValueError) as e:
                self.q.put({"type": "_FILE", "ev": "failed", "m": m, "text": str(e)})
        threading.Thread(target=work, daemon=True).start()

    def file_reply(self, m):
        st = m.get("status")
        if st == "declined":
            self.add_chat(f"* {m['from']} declined the file")
        elif st == "failed":
            self.add_chat(f"! file transfer to {m['from']} failed: {m.get('text')} - send it again to resume")
        if st in ("declined", "received"):
            snd = self.file_out.pop(m.get("id"), None)
            if snd:
                snd.close()
            self.file_label.config(text="")

    def file_event(self, m):
        ev = m["ev"]
        if ev == "offer":
            self.file_out[m["id"]] = snd = m["sender"]
            self.net.send({"type": "FILE_OFFER", "to": m["to"], "id": m["id"], "name": m["name"], "size": snd.size,
                           "sha": m["sha"], "port": snd.port})
            self.file_label.config(text=f"offered {m['name']} to {m['to']}")
            self.add_chat(f"* offering {m['name']} ({snd.size / 1e6:.2f} MB) to {m['to']} - it will go directly "
                          f"from this PC (TCP port {snd.port}), not through the server")
        elif ev in ("in_progress", "out_progress"):
            self.file_label.config(text=f"{'receiving' if ev[0] == 'i' else 'sending'} {m['name'][:18]} "
                                        f"{100 * m['a'] // max(m['b'], 1)}%")
        elif ev == "received":
            self.file_label.config(text="")
            self.add_chat(f"* file saved: {m['path']} ({m['text']})")
            self.net.send({"type": "FILE_REPLY", "to": m["m"]["from"], "id": m["m"]["id"], "status": "received",
                           "text": m["text"]})
        elif ev == "failed":
            self.file_label.config(text="")
            self.add_chat(f"! file transfer failed: {m['text']}")
            self.net.send({"type": "FILE_REPLY", "to": m["m"]["from"], "id": m["m"]["id"], "status": "failed",
                           "text": m["text"]})
        elif ev == "error":
            self.file_label.config(text="")
            self.add_chat("! " + m["text"])

    # ------------------------------------------------------------ voice chat (UDP)
    def start_voice(self):
        """(Re)connect the voice client to the server we are on now."""
        talking = self.vc.talking if self.vc else False
        self.close_voice()
        self.vc = voice.VoiceClient(self.conn[0], self.voice_port, self.room, self.me, self.token)
        self.vc.talking = talking
        try:
            self.audio = voice.AudioIO(self.vc)
            self.voice_err = ""
        except Exception as e:                          # no package, no microphone, no sound card ...
            self.audio, self.voice_err = None, str(e)

    def close_voice(self):
        if getattr(self, "audio", None):
            self.audio.close()
        if getattr(self, "vc", None):
            self.vc.close()
        self.audio = self.vc = None

    def open_voice(self):
        if not self.voice_port:
            return messagebox.showinfo("Voice", "The server's voice relay is off (--no-voice or UDP port in use).",
                                       parent=self)
        if self.voicewin and self.voicewin.winfo_exists():
            return self.voicewin.lift()
        self.start_voice()
        self.voicewin = w = tk.Toplevel(self)
        w.title("Voice chat (UDP)")
        btn = tk.Button(w, text="Hold to talk", width=28, height=2, bg="#e3f2fd")
        btn.pack(padx=12, pady=(12, 4))

        def talk(on):
            if self.vc:
                self.vc.talking = on or self.voice_free.get()
            btn.config(bg="#ffcdd2" if on else "#e3f2fd", text="Talking ..." if on else "Hold to talk")
        btn.bind("<ButtonPress-1>", lambda e: talk(True))
        btn.bind("<ButtonRelease-1>", lambda e: talk(False))
        self.voice_free = tk.BooleanVar(self, value=False)
        ttk.Checkbutton(w, text="Hands-free (microphone stays open)", variable=self.voice_free,
                        command=lambda: talk(False)).pack()
        self.voice_text = tk.Text(w, width=58, height=9, font=("Courier", 10), state="disabled", bg="#f7f7f7")
        self.voice_text.pack(padx=12, pady=10)

        def closed():
            self.close_voice()
            w.destroy()
        w.protocol("WM_DELETE_WINDOW", closed)
        self.voice_tick()

    def voice_tick(self):
        if not (self.voicewin and self.voicewin.winfo_exists() and self.vc):
            return
        s = self.vc.stats()
        L = [f"relay    {self.conn[0]} UDP {self.voice_port}: " + ("registered" if s["connected"] else "not registered yet"),
             "audio    " + ("microphone + speaker on" if self.audio else "NO AUDIO DEVICE: " + self.voice_err[:60]),
             "codec    G.711 mu-law, 8 kHz, 20 ms packets (64 kbit/s)",
             f"sent     {s['sent']} packets",
             f"received {s['received']} packets   lost {s['lost']} ({s['loss_pct']:.1f} %)   late {s['late']}",
             f"jitter   {s['jitter']:.1f} ms   (playout delay 60 ms)",
             "speaking " + (", ".join(s["speakers"]) or "-"),
             "", "A lost packet is 20 ms of silence - the voice never waits (try the Chaos lab)."]
        t = self.voice_text
        t.config(state="normal")
        t.delete("1.0", "end")
        t.insert("end", "\n".join(L))
        t.config(state="disabled")
        self.after(500, self.voice_tick)

    # ------------------------------------------------------------ connection diagnostics
    def open_diagnose(self):
        try:
            conn, tls, _ = self.target()
        except ValueError:
            return messagebox.showerror("Diagnose", "The port must be a number")
        w = tk.Toplevel(self)
        w.title(f"Diagnose connection to {conn[0]}:{conn[1]}")
        self.diag_text = t = tk.Text(w, width=110, height=24, font=("Courier", 10), bg="#f7f7f7")
        t.pack(padx=8, pady=8)
        for tag, col in (("ok", "#2e7d32"), ("warn", "#b26a00"), ("bad", "#c62828"), ("info", "#555")):
            t.tag_configure(tag, foreground=col)
        t.insert("end", "Checking, layer by layer (the route check at the end can take half a minute) ...\n\n", "info")
        emit = lambda v, n, text: self.q.put({"type": "_DIAG", "v": v, "n": n, "text": text})
        threading.Thread(target=lambda: diagnose.run(conn[0], conn[1], tls, emit), daemon=True).start()

    def diag_line(self, m):
        t = getattr(self, "diag_text", None)
        if t is None or not t.winfo_exists():
            return
        mark = {"ok": "[ OK ]", "warn": "[WARN]", "bad": "[FAIL]", "info": "      "}[m["v"]]
        t.insert("end", f"{mark} {m['n']:<10} {m['text']}\n", m["v"])
        t.see("end")

    def on_close(self):
        self.close_voice()
        for snd in self.file_out.values():
            snd.close()
        self.net.close()
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
