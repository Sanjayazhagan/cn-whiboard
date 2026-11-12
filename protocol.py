"""Shared wire protocol: 4-byte big-endian length prefix + UTF-8 JSON body.

TCP is a byte stream with no message boundaries, so every message is framed with
its length. Every message is a JSON object with at least a "type" field.

LAN discovery uses UDP instead: a client broadcasts DISCOVER_MAGIC to
DISCOVERY_PORT and every server on the subnet answers with a small JSON datagram
(unicast, back to the sender) saying which TCP port it listens on.
"""
import errno
import json
import socket
import struct
import zlib

MAX_MSG = 32 * 1024 * 1024  # refuse absurd frames (a room snapshot with images can be ~20 MB)
DEFAULT_PORT = 5050
DISCOVERY_PORT = 5051  # UDP
WEB_PORT = 8080        # HTTP + WebSocket (browser / phone clients)
VOICE_PORT = 5053      # UDP voice relay
DISCOVER_MAGIC = b"WB_DISCOVER_V1"
# Compression: the top bit of the 4-byte length marks a zlib-compressed body (lengths never get near
# 2^31, so the bit is free). A sender compresses only bodies >= Z_MIN bytes and only if that makes
# them smaller, so small messages (CURSOR, PING, ACK) are never slowed down.
Z_FLAG = 0x80000000
Z_MIN = 256
HEARTBEAT_SEC = 1      # client sends PING this often (also used to measure round-trip latency)
TIMEOUT_SEC = 15       # server drops a client silent for this long


def compress_frame(frame: bytes) -> bytes:
    """Compressed version of an already encoded plain frame (or the same frame if that is not smaller)."""
    body = frame[4:]
    if len(body) < Z_MIN:
        return frame
    z = zlib.compress(body, 6)
    if len(z) >= len(body):                 # e.g. PNG image data: already compressed
        return frame
    return struct.pack(">I", len(z) | Z_FLAG) + z


def encode_msg(obj: dict, compress: bool = False) -> bytes:
    """One frame = 4-byte big-endian length + JSON body. Encoding is separate from sending so the
    server can encode a broadcast once and queue the same bytes for every client."""
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    frame = struct.pack(">I", len(body)) + body
    return compress_frame(frame) if compress else frame


def send_msg(sock: socket.socket, obj: dict, compress: bool = False) -> int:
    """Send one framed message; returns the number of bytes put on the wire (for statistics)."""
    frame = encode_msg(obj, compress)
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


def recv_frame(sock: socket.socket):
    """Receive one framed message; returns (message, bytes_on_wire, bytes_uncompressed, was_compressed)."""
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    z = bool(length & Z_FLAG)
    length &= ~Z_FLAG
    if length > MAX_MSG:
        raise ConnectionError("frame too large")
    body = _recv_exact(sock, length)
    if z:
        d = zlib.decompressobj()
        try:
            body = d.decompress(body, MAX_MSG + 1)      # bounded: a "zip bomb" cannot exhaust memory
        except zlib.error:
            raise ConnectionError("bad compressed frame")
        if len(body) > MAX_MSG or d.unconsumed_tail:
            raise ConnectionError("frame too large")
    return json.loads(body.decode("utf-8")), 4 + length, 4 + len(body), z


def recv_msg_ex(sock: socket.socket):
    """Receive one framed message; returns (message, bytes_on_wire)."""
    return recv_frame(sock)[:2]


def recv_msg(sock: socket.socket) -> dict:
    return recv_msg_ex(sock)[0]


def simplify(points, eps=1.0):
    """Ramer-Douglas-Peucker: drop the points of a stroke that lie within `eps` pixels of the straight
    line between their neighbours. A hand-drawn stroke usually keeps its shape with 20-40% of the points,
    so the ADD message (and every snapshot that contains it) gets that much smaller."""
    if len(points) < 3:
        return list(points)
    keep = [False] * len(points)
    keep[0] = keep[-1] = True
    stack = [(0, len(points) - 1)]
    while stack:                            # iterative (a long stroke would overflow the recursion limit)
        a, b = stack.pop()
        (ax, ay), (bx, by) = points[a], points[b]
        dx, dy = bx - ax, by - ay
        norm = (dx * dx + dy * dy) ** 0.5
        worst, idx = 0.0, -1
        for i in range(a + 1, b):
            px, py = points[i]
            d = abs(dy * (px - ax) - dx * (py - ay)) / norm if norm else ((px - ax) ** 2 + (py - ay) ** 2) ** 0.5
            if d > worst:
                worst, idx = d, i
        if worst > eps:
            keep[idx] = True
            stack += [(a, idx), (idx, b)]
    return [p for p, k in zip(points, keep) if k]


def port_taken(host, port, timeout=0.3):
    """True if some program already accepts TCP connections on this port of this machine.

    bind() alone does not tell us on Windows: there SO_REUSEADDR lets two programs listen on the same
    port, and the connections go to the other one (seen in the lab: EDB Postgres' web server on 8080
    answered the phones instead of the whiteboard). So we simply try to connect before we bind."""
    targets = ("127.0.0.1", "::1") if host in ("0.0.0.0", "", "::") else (host,)
    for h in targets:
        try:
            socket.create_connection((h, port), timeout=timeout).close()
            return True
        except OSError:
            pass
    return False


def _own_port(s):
    """Socket options before bind(): this port is ours alone.
    Linux/macOS: SO_REUSEADDR only skips the TIME_WAIT pause after a restart; a second listener still
    gets "address already in use". Windows: SO_REUSEADDR would allow a second listener (port hijacking),
    so SO_EXCLUSIVEADDRUSE is used instead; Windows has no TIME_WAIT pause for listening sockets."""
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def listen_socket(host, port, kind=socket.SOCK_STREAM):
    """A listening/bound socket. For the default "all addresses" host this is a dual-stack IPv6
    socket (IPV6_V6ONLY off): one socket accepts both IPv6 clients and IPv4 clients (which then
    appear as IPv4-mapped addresses, ::ffff:a.b.c.d). Falls back to plain IPv4 where IPv6 is missing.
    Raises OSError (EADDRINUSE) if another program already uses the port.
    Returns (socket, True if IPv6 is served)."""
    if kind == socket.SOCK_STREAM and port and port_taken(host, port):
        raise OSError(errno.EADDRINUSE, f"port {port} is already used by another program")
    if host in ("0.0.0.0", "", "::"):
        s = None
        try:
            s = socket.socket(socket.AF_INET6, kind)
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            _own_port(s)
            s.bind(("::", port))
            return s, True
        except OSError as e:
            if s is not None:
                s.close()
            if e.errno in (errno.EADDRINUSE, errno.EACCES, getattr(errno, "WSAEADDRINUSE", -1),
                           getattr(errno, "WSAEACCES", -1)):
                raise                        # taken: do not quietly retry on IPv4 only
        except AttributeError:
            if s is not None:
                s.close()
        host = "0.0.0.0"
    v6 = ":" in host
    s = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, kind)
    try:
        _own_port(s)
        s.bind((host, port))
    except OSError:
        s.close()
        raise
    return s, v6


def norm_addr(addr):
    """(ip, port) with an IPv4-mapped IPv6 address written as plain IPv4."""
    ip = addr[0]
    return (ip[7:] if ip.startswith("::ffff:") and "." in ip else ip, addr[1])


def is_loopback(ip):
    return ip.startswith("127.") or ip == "::1"
