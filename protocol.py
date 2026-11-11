"""Shared wire protocol: 4-byte big-endian length prefix + UTF-8 JSON body.

TCP is a byte stream with no message boundaries, so every message is framed with
its length. Every message is a JSON object with at least a "type" field.

LAN discovery uses UDP instead: a client broadcasts DISCOVER_MAGIC to
DISCOVERY_PORT and every server on the subnet answers with a small JSON datagram
(unicast, back to the sender) saying which TCP port it listens on.
"""
import json
import socket
import struct

MAX_MSG = 32 * 1024 * 1024  # refuse absurd frames (a room snapshot with images can be ~20 MB)
DEFAULT_PORT = 5050
DISCOVERY_PORT = 5051  # UDP
DISCOVER_MAGIC = b"WB_DISCOVER_V1"
HEARTBEAT_SEC = 1      # client sends PING this often (also used to measure round-trip latency)
TIMEOUT_SEC = 15       # server drops a client silent for this long


def encode_msg(obj: dict) -> bytes:
    """One frame = 4-byte big-endian length + JSON body. Encoding is separate from sending so the
    server can encode a broadcast once and queue the same bytes for every client."""
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return struct.pack(">I", len(body)) + body


def send_msg(sock: socket.socket, obj: dict) -> int:
    """Send one framed message; returns the number of bytes put on the wire (for statistics)."""
    frame = encode_msg(obj)
    sock.sendall(frame)
    return len(frame)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed connection")
        buf.extend(chunk)
    return bytes(buf)


def recv_msg_ex(sock: socket.socket):
    """Receive one framed message; returns (message, bytes_on_wire)."""
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    if length > MAX_MSG:
        raise ConnectionError("frame too large")
    return json.loads(_recv_exact(sock, length).decode("utf-8")), 4 + length


def recv_msg(sock: socket.socket) -> dict:
    return recv_msg_ex(sock)[0]
