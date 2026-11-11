"""LAN whiteboard client (Tkinter). Run: python client.py

Threads: a reader thread pushes server messages into a queue; a heartbeat thread
sends PING; the Tk main thread polls the queue (Tkinter is not thread-safe, so
sockets never touch widgets directly). LAN discovery runs in its own short-lived
thread and reports back through the same queue.

Reliability: requests that change the board (ADD, ERASE, UNDO, REDO, CLEAR) and chat
carry a msg_id and stay in an "outbox" until the server ACKs them. After a reconnect
everything still in the outbox is sent again; the server ignores ids it has already
processed, so nothing is lost and nothing is applied twice.
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
                      recv_msg_ex, send_msg)

from auth import fingerprint

CANVAS_W, CANVAS_H = 1000, 640
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
        self.lock = threading.Lock()
        # traffic counters (read by the Network window)
        self.tx_bytes = self.rx_bytes = self.tx_msgs = self.rx_msgs = 0
        self.pings_sent = 0
        self.last_rtt = None

    def connect(self, host, port, first_msg, tls=False, check=None):
        s = socket.create_connection((host, port), timeout=5)
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
        self.sock, self.gen = s, self.gen + 1
        self.open, self.target = True, ((host, port), tls)
        self.tx_bytes += send_msg(s, first_msg)
        self.tx_msgs += 1
        threading.Thread(target=self._reader, args=(s, self.gen), daemon=True).start()
        threading.Thread(target=self._beat, args=(s, self.gen), daemon=True).start()

    def _reader(self, s, gen):
        try:
            while gen == self.gen:
                msg, n = recv_msg_ex(s)
                self.rx_bytes += n
                self.rx_msgs += 1
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

    def send(self, msg, s=None):
        s = s or self.sock
        try:
            with self.lock:
                self.tx_bytes += send_msg(s, msg)
                self.tx_msgs += 1
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
        ttk.Label(f, text="(click a server to use it)", foreground="#666").grid(row=r, column=1, sticky="w")
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
        msg = {"type": kind, "user": v["user"], "room": v["room"], "password": v["pw"]}
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
        for t in ("pen", "eraser", "line", "rect", "oval", "text", "sticky", "image"):
            ttk.Radiobutton(bar, text=t.title(), value=t, variable=self.tool_var,
                            command=lambda: setattr(self, "tool", self.tool_var.get())).pack(side="left", padx=2)
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
        ttk.Button(foot, text="Network", command=self.open_network).pack(side="right")

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
        self.bind("<Control-z>", lambda e: self.send_reliable({"type": "UNDO"}))
        self.bind("<Control-y>", lambda e: self.send_reliable({"type": "REDO"}))

    def send_reliable(self, msg):
        """Send a request that must not be lost: it keeps a msg_id and stays in the outbox until ACKed.
        If the connection is down, the send fails silently and the request goes out after reconnecting."""
        msg["msg_id"] = uuid.uuid4().hex
        self.outbox[msg["msg_id"]] = msg
        self.net.send(msg)

    def resend_outbox(self):
        for msg in list(self.outbox.values()):
            self.net.send(msg)
            self.resent += 1

    def show_security(self):
        ti = self.net.tls_info
        if ti:
            self.sec_label.config(text=f"\U0001F512 {ti[0]} encrypted" + (f" - {self.me} (logged in)" if self.jwt else ""),
                                  fg="#2e7d32")
        else:
            self.sec_label.config(text="\u26A0 not encrypted", fg="#c62828")

    def pick_color(self):
        c = colorchooser.askcolor(color=self.color)[1]
        if c:
            self.color = c
            lum = int(c[1:3], 16) * 0.3 + int(c[3:5], 16) * 0.59 + int(c[5:7], 16) * 0.11
            self.color_btn.config(bg=c, fg="black" if lum > 140 else "white")

    def send_chat(self, _e):
        t = self.chat_entry.get().strip()
        if t:
            self.send_reliable({"type": "CHAT", "text": t})
            self.chat_entry.delete(0, "end")

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
    def can_draw(self):
        return self.role == "editor" and not self.offline

    def on_move(self, e):
        now = time.time()
        if now - self.last_cursor > 0.07:          # throttle cursor traffic (~14/s)
            self.last_cursor = now
            self.net.send({"type": "CURSOR", "x": e.x, "y": e.y})

    def on_press(self, e):
        if not self.can_draw():
            return
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
            if time.time() - self.last_live > 0.04:
                self.last_live = time.time()
                self.net.send({"type": "LIVE", "color": self.color, "width": self.width,
                               "points": self.cur_pts[-50:]})
        elif self.tool in ("line", "rect", "oval"):
            self.canvas.delete("preview")
            x0, y0 = self.cur_pts[0]
            self.make_item(self.tool, [[x0, y0], [e.x, e.y]], self.color, self.width, None, ("preview",))
            self.cur_pts = [self.cur_pts[0], [e.x, e.y]]

    def on_release(self, e):
        if not self.can_draw() or not self.cur_pts:
            return
        if self.tool == "pen":
            self.send_add("stroke", self.cur_pts)
        elif self.tool in ("line", "rect", "oval") and len(self.cur_pts) == 2:
            self.send_add(self.tool, self.cur_pts)
        self.cur_pts = []

    def send_add(self, kind, pts, text=None):
        obj = {"id": uuid.uuid4().hex, "kind": kind, "color": self.color, "width": self.width, "points": pts}
        if text is not None:
            obj["text"] = text
        self.send_reliable({"type": "ADD", "obj": obj})

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
    def make_item(self, kind, pts, color, width, text, tags):
        c = self.canvas
        if kind == "image":
            ph = self.photos.get(tags[-1])
            if ph is None:
                ph = self.photos[tags[-1]] = tk.PhotoImage(master=self.canvas, data=text)    # `text` carries base64 data here
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
        self.objs = {}
        for o in snap["objects"]:
            vis = o.pop("visible")
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
                self.gaps += 1
                self.net.send({"type": "RESYNC_REQ", "since": self.last_seq})
            return
        self.last_seq = op["seq"]
        if op["op"] == "ADD":
            o = op["obj"]
            self.objs[o["id"]] = {"obj": o, "visible": True}
            self.draw_obj(o, True)
            if op.get("by") == self.me:
                self.canvas.delete("preview")
            if op.get("by") in self.live:
                self.canvas.delete(self.live.pop(op["by"]))
        else:
            for i in op["ids"]:
                if i in self.objs:
                    self.objs[i]["visible"] = op["visible"]
                    self.canvas.itemconfigure("o_" + i, state="normal" if op["visible"] else "hidden")
                self.erased.discard(i)

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
            self.status.config(text=f"Room code: {self.room}", foreground="#006")
            self.show_security()
            self.load_snapshot(m["snapshot"])
            self.chat.config(state="normal"); self.chat.delete("1.0", "end"); self.chat.config(state="disabled")
            for c in m["chat"]:
                self.add_chat(f"[{c['ts']}] {c['user']}: {c['text']}")
            self.refresh_users()
            if was_reconnect and self.outbox:     # whatever the server never confirmed goes out again
                self.add_chat(f"* reconnected - resending {len(self.outbox)} unconfirmed action(s)")
                self.resend_outbox()
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
            if self.outbox.pop(m.get("msg_id"), None) is not None:
                self.acked += 1
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
            self.add_chat(f"[{m['ts']}] {m['user']}: {m['text']}")
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
        self.after(1000, self.net_tick, gen)

    def open_network(self):
        if self.netwin and self.netwin.winfo_exists():
            self.netwin.lift()
            return
        self.netwin = w = tk.Toplevel(self)
        w.title("Network statistics")
        self.graph = tk.Canvas(w, width=420, height=120, bg="white", highlightthickness=1)
        self.graph.pack(padx=8, pady=(8, 4))
        self.net_text = tk.Text(w, width=58, height=40, font=("Courier", 10), state="disabled", bg="#f7f7f7")
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
              f"  connection        {'OFFLINE' if self.offline else 'RECONNECTING' if self.reconnecting else 'connected'} to {self.conn[0]}:{self.conn[1]}",
              f"  reconnects        {self.reconnects}",
              f"  awaiting ACK      {len(self.outbox)}    acked {self.acked}    resent {self.resent}",
              f"  duplicate ops ignored {self.dup_ops}    gaps resynced {self.gaps}",
              f"  last op seq       {self.last_seq}",
              f"  session time      {int(time.time() - self.t_start)} s"]
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
        self.status.config(text="Connection lost - reconnecting...", foreground="red")
        threading.Thread(target=self._reconnect_loop, daemon=True).start()

    def _reconnect_loop(self):
        while self.reconnecting:
            try:
                msg = {"type": "JOIN_ROOM", "user": self.me, "room": self.room,
                       "password": self.password, "token": self.token}
                if self.jwt:
                    msg["jwt"] = self.jwt
                self.net.connect(*self.conn, msg, tls=self.use_tls, check=self.check_cert_silent)
                return                          # JOIN_OK (with fresh snapshot) clears the flag
            except CertRejected:
                self.q.put({"type": "_CERT_CHANGED"})
                return
            except OSError:
                time.sleep(2)

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

    def on_close(self):
        self.net.close()
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
