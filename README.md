# LAN Collaborative Whiteboard (CN Lab)

Python 3.9+ (`pip install -r requirements.txt`: Pillow for PNG export and JPEG images, `cryptography` so the server can create its TLS certificate) (Tkinter ships with Python on Windows; on Linux: `sudo apt install python3-tk`).

## Run
1. On the host machine: `python server.py` (optional `--port 5050 --name LabPC`). It prints the LAN address, e.g. `192.168.1.20:5050`.
   Allow the ports through the firewall: TCP 5050 (drawing) and UDP 5051 (LAN discovery).
   Windows: click **Allow access** for *Private networks* when prompted (make sure the Wi-Fi/LAN profile is set to Private);
   Linux: `sudo ufw allow 5050/tcp && sudo ufw allow 5051/udp`.
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
Freehand pen, object eraser, line/rectangle/oval/text, colour + width, live remote strokes and cursors in each user's colour,
participant list with online status, group chat with timestamps, per-user undo/redo (Ctrl+Z / Ctrl+Y),
host-only Clear / Save / Restore (saved to `saves/<room>.json` on the server), host can switch users between editor/viewer or kick,
room password, **LAN server discovery (UDP broadcast)**, **sticky notes**, **image insertion** (PNG/GIF; JPEG/BMP need Pillow; resized to <=400px), **PNG export**, **version history**, automatic reconnect (same username + token) with full state recovery, and actions made while the
connection was down are resent after reconnecting (nothing lost, nothing applied twice).

## Extras
- Sticky note: pick **Sticky**, click the canvas, type text (note colour = current colour, lightened).
- Image: pick **Image**, click where it goes, choose a file. Sent to everyone as base64 inside an `ADD` op (limit ~500 KB).
- Export PNG: **Export PNG** redraws the visible board with Pillow (`pip install pillow`); without Pillow it exports PostScript.
- Version history: server snapshots the visible-object set every 25 ops (`auto @op N`) and on host request (**History > Save version now**).
  **History > Restore selected** (host only) turns the board back to that version for everyone; it is itself recorded as normal ops.

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
- **Kick** bans the name in that room: the kicked client is told why (`KICKED`), does not auto-reconnect, and its saved token is refused.
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
- TCP; each message = 4-byte big-endian length + UTF-8 JSON (see `protocol.py`).
- Server stamps every canvas op (`ADD`, `VIS`) with a room-wide `seq` under a lock -> one total order for all clients.
- Clients apply ops only in `seq` order; duplicates (`seq` already applied, or repeated `msg_id`) are ignored; a gap triggers `RESYNC_REQ` -> `OPS_SINCE` (or `SNAPSHOT`).
- Heartbeat: client `PING` every 1 s (carries a timestamp; the server echoes it so the client measures round-trip time), server drops a client silent for 15 s; client reconnects automatically and receives a `SNAPSHOT`.
- Undo/redo is per user (hides/shows that user's own last action), so it never removes other users' work.
- Transient messages (`LIVE`, `CURSOR`) are broadcast but not stored; chat is stored with timestamps.
- Acknowledgements: requests that change the board (`ADD`, `ERASE`, `UNDO`, `REDO`, `CLEAR`) and `CHAT` carry a `msg_id`.
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
`python tests/test_server.py`, `test_fixes.py`, `test_db.py` and `test_auth.py` need only Python (+ `cryptography` or openssl
for the certificate). `test_gui_auth.py` covers the login screen, TLS and the certificate warning. The GUI tests (`test_gui.py`, `test_gui_fixes.py`,
`test_network.py`, `test_extras.py`) open real windows and need Tkinter (+ Pillow for `test_extras.py`). Run them from any folder.

## Build standalone executables
`pip install pyinstaller`, then run `build.bat` (Windows) or `./build.sh` (Linux). Output is in `dist/`.
Build on each target OS; PyInstaller does not cross-compile.
- Install `cryptography` before building (`pip install -r requirements.txt`) so the server .exe can create its certificate.
  Keep `server_cert.pem` / `server_key.pem` / `whiteboard.db` next to the .exe between runs; deleting the certificate makes every
  client show the "certificate changed" warning.
- Build and test the Windows .exe a day early. Windows Defender/SmartScreen sometimes flags fresh `--onefile` builds:
  choose *More info > Run anyway*, or keep the plain `python client.py` as a fallback for the demo.
- The first run of `whiteboard-server.exe` triggers the Windows firewall prompt: allow it on Private networks, otherwise other
  PCs cannot connect or discover it.
- Lab Linux PCs may lack Tkinter for system Python: `sudo apt install python3-tk` (the built binary already contains it).
