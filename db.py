"""SQLite persistence for the whiteboard server (Python standard library only).

Design: the in-memory Room objects stay the authority while the server runs (fast, and the
room lock already gives one total order). Every state change is ALSO written to SQLite, so after a
restart (or a crash) the server rebuilds every room by replaying its op log. Clients that were
connected simply auto-reconnect with their saved token and get their room back.

Writes never block the room: they go into a queue and one writer thread executes them in
batches inside a single transaction (one disk sync per batch instead of one per op). The queue
keeps the same order as the room lock produced, so the op log on disk has the same seq order.

Tables
  rooms(code, password, host, created)
  members(room, name, token, color, role)        - identity used for reconnection
  banned(room, name)                             - users kicked by the host
  ops(room, seq, ts, by, kind, body)             - the sequenced op log (body = op as JSON)
  chat(room, id, ts, user, text, msg_id)
  versions(room, id, label, ts, seq, visible)    - version history (visible = JSON list of ids)
  users(name, pw_hash, created)                  - accounts; pw_hash is PBKDF2 (see auth.py), never the password
  meta(key, value)                               - e.g. the JWT signing secret (so tokens survive restarts)
"""
import json
import queue
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS rooms   (code TEXT PRIMARY KEY, password TEXT, host TEXT, created REAL);
CREATE TABLE IF NOT EXISTS members (room TEXT, name TEXT, token TEXT, color TEXT, role TEXT,
                                    PRIMARY KEY (room, name));
CREATE TABLE IF NOT EXISTS banned  (room TEXT, name TEXT, PRIMARY KEY (room, name));
CREATE TABLE IF NOT EXISTS ops     (room TEXT, seq INTEGER, ts REAL, by TEXT, kind TEXT, body TEXT,
                                    PRIMARY KEY (room, seq));
CREATE TABLE IF NOT EXISTS chat    (id INTEGER PRIMARY KEY AUTOINCREMENT, room TEXT, ts TEXT, user TEXT, text TEXT,
                                    msg_id TEXT);
CREATE TABLE IF NOT EXISTS versions(room TEXT, id INTEGER, label TEXT, ts TEXT, seq INTEGER, visible TEXT,
                                    PRIMARY KEY (room, id));
CREATE INDEX IF NOT EXISTS chat_room ON chat(room, id);
CREATE TABLE IF NOT EXISTS users   (name TEXT PRIMARY KEY COLLATE NOCASE, pw_hash TEXT, created REAL);
CREATE TABLE IF NOT EXISTS meta    (key TEXT PRIMARY KEY, value TEXT);
"""


class Store:
    def __init__(self, path, on_write=None):
        self.path = path
        self.on_write = on_write              # callback(n) for statistics
        self.q = queue.Queue()
        con = sqlite3.connect(path)
        con.executescript(SCHEMA)
        con.close()
        self.writer = threading.Thread(target=self._writer, daemon=True)
        self.writer.start()

    # ---------------------------------------------------------------- writing (non-blocking)
    def _put(self, sql, args=()):
        self.q.put((sql, args))

    def add_room(self, room):
        self._put("INSERT OR REPLACE INTO rooms VALUES (?,?,?,?)", (room.code, room.password, room.host, time.time()))

    def save_member(self, code, m):
        self._put("INSERT OR REPLACE INTO members VALUES (?,?,?,?,?)", (code, m.name, m.token, m.color, m.role))

    def ban(self, code, name):
        self._put("DELETE FROM members WHERE room=? AND name=?", (code, name))
        self._put("INSERT OR IGNORE INTO banned VALUES (?,?)", (code, name))

    def add_op(self, code, op):
        self._put("INSERT OR REPLACE INTO ops VALUES (?,?,?,?,?,?)",
                  (code, op["seq"], time.time(), op.get("by"), op["op"], json.dumps(op, separators=(",", ":"))))

    def add_user(self, name, pw_hash):
        self._put("INSERT OR REPLACE INTO users VALUES (?,?,?)", (name, pw_hash, time.time()))

    def load_users(self):
        con = sqlite3.connect(self.path)
        try:
            return dict(con.execute("SELECT name, pw_hash FROM users"))
        finally:
            con.close()

    def secret(self, make):
        """The JWT signing secret: read it, or create it once with make() and store it."""
        con = sqlite3.connect(self.path)
        try:
            row = con.execute("SELECT value FROM meta WHERE key='jwt_secret'").fetchone()
            if row:
                return bytes.fromhex(row[0])
            value = make()
            with con:
                con.execute("INSERT INTO meta VALUES ('jwt_secret', ?)", (value.hex(),))
            return value
        finally:
            con.close()

    def wipe(self):
        """Standby server: forget everything before taking a fresh copy from the primary."""
        for t in ("rooms", "members", "banned", "ops", "chat", "versions", "users"):
            self._put(f"DELETE FROM {t}")

    def set_secret(self, hex_value):
        self._put("INSERT OR REPLACE INTO meta VALUES ('jwt_secret', ?)", (hex_value,))

    def add_chat(self, code, entry, msg_id=None):
        self._put("INSERT INTO chat (room, ts, user, text, msg_id) VALUES (?,?,?,?,?)",
                  (code, entry["ts"], entry["user"], entry["text"], msg_id))

    def add_version(self, code, v):
        self._put("INSERT OR REPLACE INTO versions VALUES (?,?,?,?,?,?)",
                  (code, v["id"], v["label"], v["ts"], v["seq"], json.dumps(v["visible"])))

    def delete_version(self, code, vid):
        self._put("DELETE FROM versions WHERE room=? AND id=?", (code, vid))

    def flush(self, timeout=10):
        """Wait until everything queued so far is on disk (used at shutdown and in tests)."""
        done = threading.Event()
        self.q.put(done)
        return done.wait(timeout)

    def _writer(self):
        con = sqlite3.connect(self.path)
        con.execute("PRAGMA journal_mode=WAL")     # readers (db_tool.py) never block the server
        con.execute("PRAGMA synchronous=NORMAL")
        while True:
            batch = [self.q.get()]
            while len(batch) < 500:                 # group whatever else is already waiting
                try:
                    batch.append(self.q.get_nowait())
                except queue.Empty:
                    break
            events, n = [], 0
            try:
                with con:                           # one transaction per batch
                    for item in batch:
                        if isinstance(item, threading.Event):
                            events.append(item)
                        else:
                            con.execute(*item)
                            n += 1
            except sqlite3.Error as e:
                print(f"[db] write failed: {e}", flush=True)
            if self.on_write and n:
                self.on_write(n)
            for e in events:
                e.set()

    # ---------------------------------------------------------------- loading (at startup only)
    def load(self):
        """Return plain data for every saved room; the server rebuilds Room objects from it."""
        con = sqlite3.connect(self.path)
        out = []
        for code, password, host, created in con.execute("SELECT * FROM rooms ORDER BY created"):
            out.append({
                "code": code, "password": password, "host": host,
                "members": con.execute("SELECT name, token, color, role FROM members WHERE room=?",
                                       (code,)).fetchall(),
                "banned": [r[0] for r in con.execute("SELECT name FROM banned WHERE room=?", (code,))],
                "ops": [json.loads(r[0]) for r in
                        con.execute("SELECT body FROM ops WHERE room=? ORDER BY seq", (code,))],
                "chat": con.execute("SELECT ts, user, text, msg_id FROM chat WHERE room=? ORDER BY id",
                                    (code,)).fetchall(),
                "versions": [{"id": i, "label": lb, "ts": ts, "seq": sq, "visible": json.loads(vis)}
                             for i, lb, ts, sq, vis in
                             con.execute("SELECT id, label, ts, seq, visible FROM versions WHERE room=? ORDER BY id",
                                         (code,))],
            })
        con.close()
        return out
