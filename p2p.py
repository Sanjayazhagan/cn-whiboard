"""Peer-to-peer file transfer: the file goes straight from one client to the other.

The whiteboard server only INTRODUCES the two clients (it relays a small FILE_OFFER message with the
sender's address, port and a one-time token); the file's bytes never pass through it. This is the
classic split between a signalling channel (client-server) and a data channel (peer-to-peer), as in
FTP's data connection or WebRTC.

Data connection (plain TCP, sender listens, receiver connects):
    receiver -> sender   one JSON line  {"token": "...", "offset": N}
    sender -> receiver   one JSON line  {"ok": true, "size": S}      (or {"ok": false, "error": "..."})
    sender -> receiver   the file's bytes from offset N to the end, then the connection closes

Resume: the receiver writes to "<name>.<first 8 hex of sha256>.part". If that file already exists
(an earlier transfer broke), it asks for the rest by sending its size as `offset`.
Integrity: the offer carries the SHA-256 of the whole file; the receiver hashes what it has on disk
at the end and only then renames the .part file. A wrong token closes the connection.
Limit: the data connection is not encrypted (the offer travels inside TLS, the file does not).
"""
import hashlib
import json
import os
import re
import socket
import threading
import time

from protocol import listen_socket

CHUNK = 64 * 1024
OFFER_TTL = 300           # the sender stops listening this long after its last activity


def sha256_file(path, upto=None):
    h, left = hashlib.sha256(), upto
    with open(path, "rb") as f:
        while left is None or left > 0:
            block = f.read(CHUNK if left is None else min(CHUNK, left))
            if not block:
                break
            h.update(block)
            if left is not None:
                left -= len(block)
    return h.hexdigest()


def safe_name(name):
    name = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", os.path.basename(str(name))).strip(". ") or "file"
    return name[:120]


def _line(sock, limit=4096):
    buf = bytearray()
    while not buf.endswith(b"\n"):
        c = sock.recv(1)
        if not c or len(buf) > limit:
            raise ConnectionError("bad header")
        buf.extend(c)
    return json.loads(buf.decode("utf-8"))


class Sender:
    """Listens on a free port and serves one file to whoever presents the token."""
    def __init__(self, path, token, on_event=None):
        self.path, self.token, self.on_event = path, token, on_event or (lambda *a: None)
        self.size = os.path.getsize(path)
        self.sock, _ = listen_socket("0.0.0.0", 0)
        self.sock.listen(2)
        self.port = self.sock.getsockname()[1]
        self.sent_bytes, self.last, self.closed = 0, time.time(), False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        self.sock.settimeout(1.0)
        while not self.closed and time.time() - self.last < OFFER_TTL:
            try:
                c, _addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.last = time.time()
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()
        self.close()

    def _serve(self, c):
        try:
            c.settimeout(15)
            req = _line(c)
            offset = int(req.get("offset", 0))
            if req.get("token") != self.token or not 0 <= offset <= self.size:
                c.sendall(b'{"ok":false,"error":"wrong token"}\n')
                return
            c.sendall((json.dumps({"ok": True, "size": self.size}) + "\n").encode())
            done = offset
            with open(self.path, "rb") as f:
                f.seek(offset)
                while True:
                    block = f.read(CHUNK)
                    if not block:
                        break
                    c.sendall(block)
                    done += len(block)
                    self.sent_bytes += len(block)
                    self.last = time.time()
                    self.on_event("progress", done, self.size)
            self.on_event("sent", done, self.size)
        except (OSError, ValueError) as e:
            self.on_event("error", str(e), self.size)
        finally:
            c.close()

    def close(self):
        self.closed = True
        try:
            self.sock.close()
        except OSError:
            pass


def fetch(host, port, token, name, size, sha, folder, on_progress=None, stop_after=None):
    """Download (or finish downloading) a file from a Sender. Returns the final path.
    Raises OSError / ValueError on failure; the .part file is kept so a retry resumes.
    `stop_after` (bytes) cuts the transfer short - used by the tests to simulate a broken link."""
    os.makedirs(folder, exist_ok=True)
    name = safe_name(name)
    part = os.path.join(folder, f"{name}.{sha[:8]}.part")
    offset = os.path.getsize(part) if os.path.exists(part) else 0
    if offset > size:
        os.remove(part)
        offset = 0
    s = socket.create_connection((host, port), timeout=10)
    try:
        s.sendall((json.dumps({"token": token, "offset": offset}) + "\n").encode())
        reply = _line(s)
        if not reply.get("ok"):
            raise ValueError(reply.get("error", "refused"))
        got = offset
        with open(part, "ab") as f:
            while got < size:
                block = s.recv(min(CHUNK, size - got))
                if not block:
                    break
                f.write(block)
                got += len(block)
                if on_progress:
                    on_progress(got, size)
                if stop_after is not None and got - offset >= stop_after:
                    raise ConnectionError("link cut (test)")
    finally:
        s.close()
    if got < size:
        raise ConnectionError(f"connection lost at {got} of {size} bytes - send again to resume")
    if sha256_file(part) != sha:
        os.remove(part)
        raise ValueError("SHA-256 mismatch: the file was damaged or changed; partial file deleted")
    base, ext = os.path.splitext(name)
    final, n = os.path.join(folder, name), 1
    while os.path.exists(final):
        final = os.path.join(folder, f"{base} ({n}){ext}")
        n += 1
    os.replace(part, final)
    return final
