# LAN Collaborative Whiteboard (CN Lab)

Python 3.9+ (`pip install -r requirements.txt`: Pillow for PNG export and JPEG images, `cryptography` so the server can create its TLS certificate) (Tkinter ships with Python on Windows; on Linux: `sudo apt install python3-tk`).

## Run
1. On the host machine: `python server.py` (optional `--port 5050 --name LabPC`). It prints the LAN address, e.g. `192.168.1.20:5050`.
   Allow the ports through the firewall: TCP 5050 (drawing), UDP 5051 (LAN discovery), TCP 8080 (phones/browsers, dashboard) and UDP 5053 (voice).
   Windows: click **Allow access** for *Private networks* when prompted (make sure the Wi-Fi/LAN profile is set to Private);
   Linux: `sudo ufw allow 5050/tcp && sudo ufw allow 5051/udp && sudo ufw allow 8080/tcp && sudo ufw allow 5053/udp`.
   On first start the server creates its TLS certificate and prints its **fingerprint**; write it on the board for the demo.
2. On each client: `python client.py`. The login screen has three steps:
   1. **Server**: the LAN is searched automatically and every server is listed (**Find servers on LAN** searches again);
      clicking one fills in the IP, port and the *Encrypted connection (TLS)* box. You can still type the IP by hand.
   2. **Account**: first time, type a username + password and click **Register**; afterwards **Log in**.
      (Typing name + password and clicking Create/Join directly also logs in first.)
   3. **Room**: *Your rooms* lists the rooms your account belongs to (click one to fill the code). Create a room
      (optional password) and share the 5-character code, or enter a code and click **Join room**.
   - Host: click **Create new room** (optional password); share the 5-character **room code**.
   - Others: enter the room code (+ password) and click **Join room**.

## Features
**Select tool (move objects)**: pick **Select**, press on any image, shape, stroke, text or sticky note and drag it; it moves
for everyone when you let go (dashed blue frame while dragging; Ctrl+Z moves it back). To move several things at once: drag over
empty board to draw a selection rectangle (everything it touches is selected), **Shift+click** to add or remove one object, or press
**All** / **Ctrl+A** to select everything; then drag any selected object and the whole selection moves together as one step
(one undo puts it all back). **Esc** or a click on empty board clears the selection. Freehand pen, object eraser, line/rectangle/oval/text, colour + width, live remote strokes and cursors in each user's colour,
participant list with online status, group chat with timestamps, per-user undo/redo (Ctrl+Z / Ctrl+Y),
host-only Clear / Save / Restore (saved to `saves/<room>.json` on the server), host can switch users between editor/viewer, kick, and **let removed people back in** (they are listed as `✕ name (removed)`;
select one and click **Let back in**), an **Exit room** button (desktop and phone) that goes back to the join screen,
room password, **LAN server discovery (UDP broadcast)**, **sticky notes**, **image insertion** (PNG/GIF; JPEG/BMP need Pillow; resized to <=400px), **PNG export**, **version history**, automatic reconnect (same username + token) with full state recovery, and actions made while the
connection was down are resent after reconnecting (nothing lost, nothing applied twice).

## Extras
- Sticky note: pick **Sticky**, click the canvas, type text (note colour = current colour, lightened).
- Image: pick **Image**, click where it goes, choose a file. Sent to everyone as base64 inside an `ADD` op (limit ~500 KB).
- Export PNG: **Export PNG** redraws the visible board with Pillow (`pip install pillow`); without Pillow it exports PostScript.
- Version history: server snapshots the visible-object set every 25 ops (`auto @op N`) and on host request (**History > Save version now**).
  **History > Restore selected** (host only) turns the board back to that version for everyone; it is itself recorded as normal ops.

## Standout features (each one is a networking topic)
All of them work together; the buttons are in the bottom bar of the client (**Phone join, Replay, Chaos lab, Inspector, Network**).

### 1. Join from a phone or any browser (HTTP + WebSocket, written by hand)
- The server also listens on TCP **8080** (`--web-port`, `--no-web`). `web.py` is a small HTTP/1.1 server and an RFC 6455
  WebSocket server using only `socket`, `hashlib`, `base64`, `struct`: `GET /` returns the web client (one HTML page, `webpage.py`),
  `GET /ws` with `Upgrade: websocket` is answered with `101 Switching Protocols` and
  `Sec-WebSocket-Accept = base64(SHA-1(key + GUID))`; after that the same TCP connection carries WebSocket frames
  (FIN/opcode byte, 7/16/64-bit length, 4-byte XOR mask on client frames, ping/pong/close, fragments).
- Each WebSocket text frame holds the same JSON message the desktop client sends, so the room logic is shared: one server, two transports.
- **Phone join** (desktop client) shows a **QR code** and link. The link carries a signed **invite JWT** for that one room, valid 1 hour;
  the guest only types a name and appears as `name (web)`. No account password ever travels over the plain-HTTP page.
- **Each link belongs to the person who opened Phone join**, and at most **2 phones/browsers** can be connected through one person's
  links at the same time, however often the QR code is shared or re-opened. A third device is refused with a message naming the two
  devices in use; when one of them presses **Exit** (or closes the page) its place is free again. Guests cannot make links of their own,
  and a removed person's links stop letting new devices in. Links made by an older server version must be opened again.
  Without an invite, `http://SERVER-IP:8080/` asks for name, account password and room code.
- The page has select (drag to move; **All** or a selection rectangle to move many), pen, eraser, line, rect, oval, text, sticky, laser, colour, width, undo/redo, chat, live cursors, latency, and the same
  reliability rules (ACK + retransmit timer, seq-gap resync, auto reconnect, failover).
- **If port 8080 is already used by another program** on the host PC (for example the web server that EDB Postgres installs,
  which shows "Server is up and running"), the whiteboard does not share or fight for it: it moves its browser listener to the next
  free port (8081, 8082, ...), says so in the server window, and the **Phone join** QR code / link already carries that port.
  A link or QR code made before a server restart may still point at the old port: open **Phone join** again for a fresh one.
- Firewall: also allow TCP 8080 (`sudo ufw allow 8080/tcp`), or the port the server printed. Limits (say so in the report): the page is HTTP, not HTTPS (a phone would
  reject the self-signed certificate), so browser traffic is readable on the LAN; browsers cannot insert images.

### 2. Chaos lab (emulated bad network, like `tc netem`, inside the app)
- **Chaos lab** window: the host sets **message loss %**, **delay** and **jitter** for the room (presets: Busy Wi-Fi, Bad link, Terrible).
  The server then drops / holds back messages between itself and every client of that room, in both directions.
- TCP never loses data, so loss is emulated at message level, and only for message types that have a recovery mechanism
  (requests with a `msg_id`, `OP`, `ACK`, `PING/PONG`, live strokes, cursors, resync traffic). Chat lines, user lists and join replies are only delayed.
- What repairs the board (all visible as live counters in the window):
  - **Retransmit timer (ARQ)**: an unACKed request is resent after RTO = 3 x average RTT (0.6 to 3 s), doubling on each retry.
  - **Ordered requests**: each request has a number `rn`; the server processes them in order and holds back one that arrives before a
    lost earlier one (like TCP's out-of-order queue), so "draw then erase" can never be applied as "erase then draw".
  - **Duplicate ACK**: if only the ACK was lost, the resend is recognised by its `msg_id` and ACKed again, not applied twice.
  - **Sequence-gap resync**: a client that sees `seq` jump asks for the missing ops (`RESYNC_REQ` -> `OPS_SINCE`), and asks again if the answer is lost.
  - **Heartbeat check**: every `PONG` carries the room's current `seq`; a client that is behind with nothing arriving asks for the rest.
- The window also draws a **network map**: server, standby, every online client (desktop/TCP or browser/WebSocket) with its latency.

### 3. Packet inspector (a mini Wireshark in the client)
- **Inspector** lists every frame on this client's connection: time, direction, type, summary, bytes on the wire and uncompressed size.
  Retransmissions and duplicate ACKs are red. Click a frame for its JSON. Filters hide PING/PONG and cursor traffic; Pause freezes it.
- The **Sequence diagram** tab draws the newest frames as arrows between the client and server lifelines.

### 4. Time-travel replay
- **Replay** fetches the room's whole op log (`REPLAY_REQ` -> `REPLAY`) and opens a second board with a slider: drag to any op, or press
  Play (2 to 120 ops/s). It applies ops exactly as a live client does, which demonstrates that the board is just the op log replayed.

### 5. Hot-standby server with automatic failover
- Main server: `python server.py --cluster-key SECRET`. Standby (other PC, or same PC on other ports):
  `python server.py --standby-of MAIN-IP:5050 --cluster-key SECRET` (same PC: add `--port 5052 --web-port 8081`).
- The standby connects to the primary like a client, proves it knows the cluster key, receives a full copy (accounts, JWT secret, rooms,
  op logs, chat, versions, duplicate filters), and then every change as it happens (primary/backup replication). It writes its own database
  (`whiteboard-standby.db`). While standing by it refuses clients (`JOIN_ERR` code `STANDBY`).
- The primary tells every client where the standby is, including the standby's **TLS certificate fingerprint**, so clients trust it later
  without a prompt (the trust is passed along the already-verified connection).
- If the primary dies (connection lost, or silent for 4 s, and two reconnect attempts fail) the standby promotes itself. Clients try the
  old server, then the standby, rejoin with their token/JWT, get the snapshot and resend unconfirmed actions. In the tests this takes 1 to 2 s.
- Limits: replication is asynchronous (an action ACKed in the last few milliseconds before a crash could be missing on the standby; the
  client's outbox covers actions not yet ACKed). There is no automatic fail-back: restart the old primary as `--standby-of` the new one.
  Never run both as primary. The standby does not verify the primary's certificate when it connects.

### 6. Bandwidth optimizer
- **Frame compression**: bodies of 256+ bytes are zlib-compressed when that makes them smaller; the top bit of the 4-byte length prefix
  marks a compressed frame. A client asks for it with `"z":1` when joining; small messages and images (already compressed) go as they are.
  `--no-compress` turns it off on the server.
- **Stroke simplification**: a finished pen stroke goes through Ramer-Douglas-Peucker (1 px tolerance) before it is sent.
- The Network window shows bytes before/after and points before/after (typically about half the points and 30 to 70 % fewer bytes).

### 7. Quality of service: priority queues, rate limiting, bandwidth cap
- Every client's outgoing queue on the server has **two priority classes**: board traffic (ops, ACKs, chat, snapshots) is always sent
  before disposable traffic (`CURSOR`, `LIVE`, `LASER`). If more than 30 disposable frames wait for one client, the oldest are **shed**:
  a newer cursor position makes them worthless.
- **Token bucket** on the way in: each client may send 80 disposable messages per second (burst 80); the rest are dropped at the door,
  so one client cannot flood the room.
- The Chaos lab has a fourth slider, **Bandwidth cap kbit/s** (preset *Narrow link* = 24 kbit/s): a byte token bucket per client.
  On a narrow link cursors and live previews get choppy while every stroke still arrives complete and in order.
  The window shows how many frames were shed and rate limited.

### 8. Offline mode
- When the connection drops you can keep drawing. The status bar says `OFFLINE - N action(s) saved`, your strokes stay on screen, and on
  reconnect (to the same server or the standby) they are delivered once, in order (outbox + `msg_id` duplicate filter + request numbers).

### 9. Connection diagnostics (`diagnose.py`)
- Login screen > **Diagnose connection** (or `python diagnose.py SERVER-IP [PORT] [--no-tls]`) checks the path layer by layer: this PC's
  addresses and subnet, the TCP handshake (it tells **refused** = nothing listening from **no answer** = firewall / wrong network),
  the TLS handshake, an application-level PING/PONG, the web port, the UDP discovery broadcast, and the route (`tracert` / `traceroute`).
  Every failed line says what to fix. Use it first when a client cannot connect on demo day.

### 10. IPv6
- The server's TCP, web and voice sockets are **dual-stack**: one IPv6 socket with `IPV6_V6ONLY` off serves IPv6 clients and IPv4 clients
  (seen as `::ffff:a.b.c.d`). Type an IPv6 address (e.g. `::1` or `fe80::...%eth0`) in the client's Server IP field. If the PC has no IPv6
  the server says so and serves IPv4 only. LAN discovery stays IPv4 (IPv6 has no broadcast; it would need multicast).

### 11. Admin dashboard (browser)
- At startup the server prints `Admin dashboard: http://IP:8080/admin?key=...` (`--admin-key` to choose the key). The page polls
  `/admin/state` once a second and shows role, uptime, clients, a 60-second traffic graph, every room with its clients, latency and
  emulated link, all counters, and the event log. Good to leave on the projector during the demo.

### 12. Peer-to-peer file transfer (`p2p.py`)
- Select a participant, click **Send file**. The server only relays a small `FILE_OFFER` (name, size, SHA-256, the sender's address and
  port, a one-time token); the bytes travel on a **direct TCP connection** between the two clients (signalling vs data channel, as in FTP).
- The receiver confirms, the file lands in `Downloads/whiteboard-files`, and its SHA-256 is checked before the `.part` file is renamed.
  If the connection breaks, sending the same file again **resumes** from the bytes already on disk.
- Limits: desktop clients only; the sender's PC must accept an incoming TCP connection (Windows shows a firewall prompt the first time);
  the data connection is not encrypted.

### 13. End-to-end encrypted rooms (`e2e.py`)
- **Only the host can turn end-to-end encryption on or off** for the room: the host clicks **E2E key** and types a passphrase
  (empty = off for everyone). The others then see **E2E: key?** and type the same passphrase (it is never sent). While it is on,
  each client's drawings and chat are encrypted before they leave the PC, so the server relays and stores only ciphertext: `python db_tool.py ROOMCODE` shows `"kind":"enc"`.
- Key = PBKDF2-HMAC-SHA256(passphrase, room code, 100 000 rounds). Cipher = HMAC-SHA256 in counter mode as a stream cipher, with an
  HMAC tag (encrypt-then-MAC), standard library only. A wrong key or a changed byte is detected and the object stays hidden.
- TLS protects client-to-server; this protects against the server itself. Limits: the server still sees who draws when and how big it is;
  live stroke previews are switched off while a key is set; browser guests cannot read encrypted objects; chat already on screen is not
  re-decrypted when you enter the key later.

### 14. Voice chat over UDP (`voice.py`)
- **Only the host can turn voice chat on or off** for the room (the button shows **Voice: off** to the others until then; the host's
  voice window has **Turn voice chat off for everyone**, which hangs everyone up). While it is off the relay refuses every client.
- **Voice** opens push-to-talk. Audio is 8 kHz mono, 20 ms per packet, G.711 mu-law (64 kbit/s), sent as UDP datagrams with a sequence
  number and timestamp (the idea of RTP) to a relay in the server (UDP **5053**, `--voice-port`, `--no-voice`), which forwards them to
  the room's other members. A HELLO with the member token registers the client's UDP address.
- Receiver: a jitter buffer per speaker reorders packets and plays them 60 ms late; a missing packet is 20 ms of silence. The window shows
  packets sent/received/lost/late and RFC 3550 jitter. The Chaos lab's loss also hits voice packets, so you can hear the difference between
  UDP (a click) and TCP (a stall).
- Needs `pip install sounddevice` (Linux also `sudo apt install libportaudio2`) for microphone and speaker; without it the window says so.
  Firewall: allow UDP 5053. Limits: not encrypted, no echo cancellation (use headphones), no voice for browser guests.

### Also new
- **Laser** tool: a red pointer everyone sees for a moment (not stored); viewers can use it too.

### 3-minute demo script
1. Start primary and standby. Open two desktop clients, create a room, click **Phone join**, scan the QR code, draw from the phone.
2. Open **Chaos lab**, press **Bad link**, draw on all devices: latency goes red, counters climb, every board still ends up identical. Press **Off**.
3. Open **Inspector** > Sequence diagram while drawing; point out a red retransmission and a `zlib` frame.
4. Open **Replay** and scrub through the session.
5. Kill the primary server (Ctrl+C or close its window). Clients show "reconnecting", then the chat says FAILOVER and drawing continues.

## Network statistics
- Bottom-right of the client: live round-trip latency badge (green < 50 ms, orange < 150 ms, red above). Click it or **Network** for the full window.
- Network window: RTT graph (last 60 s), now/avg/min/max, jitter, ping loss, upload/download KB/s and totals, message counts,
  reconnects, duplicate ops ignored, gaps resynced, server uptime/traffic/ops/duplicates/rejected, and every participant's latency.
- Participant list also shows each user's latency. The server prints a `[stats]` line every 10 s.
- How: client `PING` (1/s) carries a timestamp, server echoes it in `PONG` with its counters; RTT = now - timestamp.

## Security: accounts, password hashing, JWT, TLS
- **Accounts**: `REGISTER` / `LOGIN` with a username and password. Passwords are **never stored**: the database keeps
  `PBKDF2-HMAC-SHA256(password, random 16-byte salt, 200 000 rounds)` (`auth.py`). Login compares in constant time and gives the
  same error for an unknown user and a wrong password (no user enumeration). 5 failed logins per IP per minute -> blocked for a minute.
- **JWT**: a successful login returns a JSON Web Token (`header.payload.signature`, HS256 = HMAC-SHA256 with a server secret
  kept in the database, valid 24 h). Create/Join/reconnect send the token instead of the password. The server takes the user name
  **from the verified token**, so nobody can draw under someone else's name, and rejects tokens that are edited, expired, signed
  with another key or use `alg: none`. The secret is stored, so tokens stay valid across server restarts. A JWT is signed, not
  encrypted, which is why it travels only inside TLS.
- **TLS** (Python `ssl`, TLS 1.2+, usually TLS 1.3 with AES-256-GCM): all TCP traffic is encrypted, so passwords, tokens and drawings
  cannot be read or changed on the LAN. The certificate is self-signed (no internet, no CA), so the client uses **trust on first use**
  like SSH: it remembers the server's SHA-256 fingerprint in `~/.lan_whiteboard_known_servers.json` and, if it ever changes, stops
  the automatic reconnect and shows a man-in-the-middle warning with both fingerprints. Compare them with what the server printed.
  The status bar shows a lock with the TLS version; the Network window shows version, cipher, fingerprint and token expiry.
- Server switches: `--no-tls` (plain TCP, e.g. to show the readable protocol in Wireshark) and `--no-auth` (no accounts, anyone
  joins with any name, as before). Untick *Encrypted connection* on the client for a `--no-tls` server; the client tells you if they don't match.
- Not covered (say so in the report): the self-signed certificate is only as trustworthy as the first connection; a stolen
  token works until it expires (no logout list); there is no password reset.

## Robustness
- **Kick** bans the name in that room: the kicked client is told why (`KICKED`), does not auto-reconnect, and its saved token is refused
  until the host lets them back in (`UNBAN`). The removed list and the host's voice/E2E switches are saved in the database.
- **Slow client isolation**: each client has its own outgoing queue and writer thread on the server, so a client that stops reading
  (frozen laptop, full TCP receive window) cannot stall drawing for the others. It is dropped after 15 s or 64 MB of backlog and reconnects.
- **Image budget**: a room holds at most 20 MB of images (erased ones count, since objects are only hidden), so a joining client's
  snapshot always fits in one frame (`MAX_MSG` = 32 MB).
- **Server restart**: with the database (default) every room comes back and clients reconnect into it on their own.
  Only with `--no-db` (or if the database file was deleted) does a reconnecting client get "room no longer exists";
  it then keeps its board on screen (Export PNG still works) and can go back to the login screen to make a new room.

## Database (SQLite)
The server saves everything automatically in `whiteboard.db` (SQLite, part of Python's standard library, nothing to install),
created in the folder the server is started from. Options: `--db path/to/file.db`, or `--no-db` for memory only.
- Tables: `rooms`, `members` (name, reconnect token, colour, role), `banned`, `ops` (the sequenced op log, one row per seq),
  `chat`, `versions`, `users` (name + PBKDF2 hash), `meta` (JWT secret). See the top of `db.py`.
  The TLS certificate and key are separate files: `server_cert.pem`, `server_key.pem` (`--cert`, `--key`).
- On startup the server rebuilds each room by **replaying its op log** in seq order, the same way a client applies ops,
  so the restored board is exactly the one everybody saw. Sequence numbers continue where they stopped, and the duplicate
  filters are rebuilt too, so actions a client resends after the restart are still applied only once.
- Writes never block drawing: they are queued and a single writer thread commits them in batches (one transaction per batch,
  WAL mode). Ctrl+C or closing the server normally flushes the queue; a hard crash can lose at most the last few milliseconds.
- Not saved: per-user undo/redo stacks (start empty after a restart) and who is online.
- Look inside (works while the server runs): `python db_tool.py` lists rooms; `python db_tool.py ROOMCODE` shows members,
  the op log, chat and versions; `python db_tool.py --sql "SELECT seq, by, kind FROM ops LIMIT 10"` runs any query.
  Any SQLite viewer (e.g. DB Browser for SQLite) can open the file too.
- **Save / Restore** (host buttons) still exist: they write/read a manual JSON snapshot in `saves/<room>.json`, separate from the database.
- To start fresh, stop the server and delete `whiteboard.db` (plus `whiteboard.db-wal` / `-shm` if present).

## Protocol (details for the report)
- TCP; each message = 4-byte big-endian length + UTF-8 JSON (see `protocol.py`); top bit of the length = zlib-compressed body.
- Server stamps every canvas op (`ADD`, `VIS`, `MOVE`) with a room-wide `seq` under a lock -> one total order for all clients.
- Clients apply ops only in `seq` order; duplicates (`seq` already applied, or repeated `msg_id`) are ignored; a gap triggers `RESYNC_REQ` -> `OPS_SINCE` (or `SNAPSHOT`).
- Heartbeat: client `PING` every 1 s (carries a timestamp; the server echoes it so the client measures round-trip time), server drops a client silent for 15 s; client reconnects automatically and receives a `SNAPSHOT`.
- Undo/redo is per user (hides/shows that user's own last action), so it never removes other users' work.
- `MOVE {ids, dx, dy}` (Select tool): the client drags a local preview and sends ONE request on release, so a drag costs one
  sequenced op, not a stream of positions. The server shifts the object's points (a new copy: the original `ADD` in the op log
  is unchanged, so replay stays exact), and undo/redo sends the opposite / same shift. Any editor may move any object (like the
  eraser). For an end-to-end encrypted object the server only shifts its offset; clients add it to the decrypted shape.
  Limit: version restore brings back which objects are visible, not where they were.
- Transient messages (`LIVE`, `CURSOR`) are broadcast but not stored; chat is stored with timestamps.
- Acknowledgements: requests that change the board (`ADD`, `ERASE`, `MOVE`, `UNDO`, `REDO`, `CLEAR`) and `CHAT` carry a `msg_id`.
  The server answers each with `ACK` after processing it (and ACKs a duplicate again without applying it). The client keeps
  un-ACKed requests in an outbox and resends them after a reconnect: at-least-once delivery + duplicate filtering = applied exactly once.
- Server isolation: `send()` only queues an already-encoded frame; a per-client writer thread does the blocking `sendall`.
  A broadcast is JSON-encoded once and the same bytes are queued for every client.
- LAN discovery (UDP, port 5051): the client broadcasts the datagram `WB_DISCOVER_V1` to `255.255.255.255` and to its subnet's
  broadcast address; every server answers by unicast with `{"type":"WB_SERVER","name","port","rooms","users",...}`.
  The client takes the server's IP from the reply's source address. TCP is used for the board (reliable, ordered),
  UDP for discovery (connectionless, can broadcast; a lost datagram just means "search again").

## Wireshark (for the report / demo)
`wireshark/whiteboard.lua` is a dissector for this protocol: it reassembles messages using the 4-byte length prefix and shows
each message's type, op, seq, msg_id and the JSON tree. `wireshark/sample_capture.pcapng` is a short example capture.
With TLS on, a capture shows only encrypted *Application Data*: that is the point (the test capture of a REGISTER contains no
trace of the password). To look inside anyway, start the client with `SSLKEYLOGFILE` set (Windows: `set SSLKEYLOGFILE=C:\temp\keys.log`
then `python client.py`; Linux: `SSLKEYLOGFILE=~/keys.log python client.py`) and give that file to Wireshark under
Preferences > Protocols > TLS > *(Pre)-Master-Secret log filename*; the dissector then shows the decrypted messages.
`sample_tls_capture.pcapng` + `sample_tls_keys.log` are an example. Showing the same login once with `--no-tls` (password readable)
and once with TLS (unreadable) makes a strong slide.
1. Copy `whiteboard.lua` into Wireshark's personal plugins folder (Windows `%APPDATA%\Wireshark\plugins\`, Linux
   `~/.local/lib/wireshark/plugins/`; Help > About Wireshark > Folders shows it) and restart Wireshark.
2. Capture on the Wi-Fi/Ethernet adapter of the server PC (for a single-PC demo, capture on the loopback adapter; on Windows that
   needs Npcap's loopback support) with capture filter `tcp port 5050 or udp port 5051`.
3. Useful display filters: `whiteboard`, `whiteboard.type == "OP"`, `whiteboard.type == "PING" || whiteboard.type == "PONG"`,
   `whiteboard_disc`. Good screenshots for the report: the 3-way handshake + `JOIN_OK`; one segment carrying two messages
   (`ADD  CHAT`, shows why framing is needed); a big `JOIN_OK` split over many TCP segments; PING/PONG timing; the discovery broadcast and reply.

## Tests
`tests/test_move.py` covers the Select tool: server rules (viewers refused, undo/redo, database restart, browser guest) and two
real clients dragging a rectangle, an image and an end-to-end encrypted shape.
`tests/test_more.py` (no Tkinter) and `tests/test_gui_more.py` cover diagnostics, the dashboard, P2P files with resume, end-to-end
encryption, the voice relay and jitter buffer, and IPv6 (skipped on a PC without IPv6).
`tests/test_host_controls.py` (no Tkinter) covers the host-only voice/E2E switches, letting removed people back in and the
2-phones-per-person invite limit; `tests/test_gui_host.py` runs the same from the desktop client, plus Exit room.
`tests/test_features.py` (no Tkinter) covers the WebSocket handshake and browser guest join, compression, ordered requests,
the chaos lab, the replay log and standby failover. `tests/test_gui_features.py` runs two real clients through the chaos lab,
inspector, replay, phone-join window, laser and a TLS failover.
`python tests/test_server.py`, `test_fixes.py`, `test_db.py` and `test_auth.py` need only Python (+ `cryptography` or openssl
for the certificate). `test_gui_auth.py` covers the login screen, TLS and the certificate warning. The GUI tests (`test_gui.py`, `test_gui_fixes.py`,
`test_network.py`, `test_extras.py`) open real windows and need Tkinter (+ Pillow for `test_extras.py`). Run them from any folder.

## Build standalone executables
`pip install pyinstaller`, then run `build.bat` (Windows) or `./build.sh` (Linux). Output is in `dist/`.
Build on each target OS; PyInstaller does not cross-compile.

**Ready-made downloads:** the GitHub Actions workflow `.github/workflows/build.yml` builds both executables on Windows
and on Linux (Ubuntu 22.04), checks that the server answers `diagnose.py` and that the client starts, and runs every test
file on both systems. Pushing a tag such as `v1.0`, or running the workflow by hand (Actions tab -> Build executables -> Run workflow) with a release tag, attaches the files to a GitHub Release (see the Releases page).
- Windows: `whiteboard-server.exe`, `whiteboard-client.exe`. The files are not code-signed, so SmartScreen may say
  "Windows protected your PC": click *More info* -> *Run anyway*. On the first server start, allow it through the
  firewall on *Private networks*, or other PCs cannot connect.
- Linux: unpack `whiteboard-linux.tar.gz`, then `./whiteboard-server` and `./whiteboard-client` (the client carries its
  own PortAudio for voice chat; running from source needs `sudo apt install libportaudio2`).
The server keeps `whiteboard.db` and its certificate in the folder it is started from.
- Install `cryptography` before building (`pip install -r requirements.txt`) so the server .exe can create its certificate.
  Keep `server_cert.pem` / `server_key.pem` / `whiteboard.db` next to the .exe between runs; deleting the certificate makes every
  client show the "certificate changed" warning.
- Build and test the Windows .exe a day early. Windows Defender/SmartScreen sometimes flags fresh `--onefile` builds:
  choose *More info > Run anyway*, or keep the plain `python client.py` as a fallback for the demo.
- The first run of `whiteboard-server.exe` triggers the Windows firewall prompt: allow it on Private networks, otherwise other
  PCs cannot connect or discover it.
- Lab Linux PCs may lack Tkinter for system Python: `sudo apt install python3-tk` (the built binary already contains it).
