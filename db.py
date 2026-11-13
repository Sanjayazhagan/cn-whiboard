"""SQLite storage for the server.

Rooms live in memory while the server runs; every change is also written here so the
server can rebuild all rooms after a restart by replaying the op log. Writes go through
a queue and a single writer thread, so they never block a room.

Tables: rooms, members, banned, room_cfg, ops, chat, versions, users, meta.
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
CREATE TABLE IF NOT EXISTS room_cfg(room TEXT PRIMARY KEY, cfg TEXT);
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
        self.on_write = on_write
        self.q = queue.Queue()
        con = sqlite3.connect(path)
        con.executescript(SCHEMA)
        con.close()
        self.writer = threading.Thread(target=self._writer, daemon=True)
        self.writer.start()

    # Writing
    def _put(self, sql, args=()):
        self.q.put((sql, args))

    def add_room(self, room):
        self._put("INSERT OR REPLACE INTO rooms VALUES (?,?,?,?)", (room.code, room.password, room.host, time.time()))

    def save_member(self, code, m):
        self._put("INSERT OR REPLACE INTO members VALUES (?,?,?,?,?)", (code, m.name, m.token, m.color, m.role))

    def ban(self, code, name):
        self._put("DELETE FROM members WHERE room=? AND name=?", (code, name))
        self._put("INSERT OR IGNORE INTO banned VALUES (?,?)", (code, name))

    def unban(self, code, name):
        self._put("DELETE FROM banned WHERE room=? AND name=?", (code, name))

    def set_cfg(self, code, cfg):
        self._put("INSERT OR REPLACE INTO room_cfg VALUES (?,?)", (code, json.dumps(cfg)))

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
        """Load the JWT signing secret, creating it on first use."""
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
        """Wipe everything (a standby does this before copying the primary)."""
        for t in ("rooms", "members", "banned", "room_cfg", "ops", "chat", "versions", "users"):
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
        """Block until everything queued so far has been written."""
        done = threading.Event()
        self.q.put(done)
        return done.wait(timeout)

    def _writer(self):
        con = sqlite3.connect(self.path)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        while True:
            batch = [self.q.get()]
            while len(batch) < 500:
                try:
                    batch.append(self.q.get_nowait())
                except queue.Empty:
                    break
            events, n = [], 0
            try:
                with con:
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

    # Loading
    def load(self):
        """Return every saved room as plain data."""
        con = sqlite3.connect(self.path)
        out = []
        for code, password, host, created in con.execute("SELECT * FROM rooms ORDER BY created"):
            out.append({
                "code": code, "password": password, "host": host,
                "members": con.execute("SELECT name, token, color, role FROM members WHERE room=?",
                                       (code,)).fetchall(),
                "banned": [r[0] for r in con.execute("SELECT name FROM banned WHERE room=?", (code,))],
                "cfg": json.loads((con.execute("SELECT cfg FROM room_cfg WHERE room=?", (code,)).fetchone()
                                   or ["{}"])[0]),
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
