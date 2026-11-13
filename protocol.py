"""Wire format shared by the client and server.

Each TCP message is a 4-byte big-endian length followed by a UTF-8 JSON object with a
"type" field. LAN discovery is a UDP broadcast that every server answers with its port.
"""
import errno
import json
import socket
import struct
import zlib

MAX_MSG = 32 * 1024 * 1024  # a snapshot with images can be ~20 MB
DEFAULT_PORT = 5050
DISCOVERY_PORT = 5051
WEB_PORT = 8080  # browser clients
VOICE_PORT = 5053
DISCOVER_MAGIC = b"WB_DISCOVER_V1"
# The top bit of the length marks a zlib-compressed body. Only bodies of Z_MIN bytes or
# more are compressed, so small messages like CURSOR and PING are left alone.
Z_FLAG = 0x80000000
Z_MIN = 256
HEARTBEAT_SEC = 1  # also used to measure latency
TIMEOUT_SEC = 15


def compress_frame(frame: bytes) -> bytes:
    """Compress an encoded frame if that actually makes it smaller."""
    body = frame[4:]
    if len(body) < Z_MIN:
        return frame
    z = zlib.compress(body, 6)
    if len(z) >= len(body):  # already compressed (e.g. images)
        return frame
    return struct.pack(">I", len(z) | Z_FLAG) + z


def encode_msg(obj: dict, compress: bool = False) -> bytes:
    """Encode one message as a frame. Kept separate from sending so a broadcast is
    encoded once and the same bytes are queued for every client.
    """
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    frame = struct.pack(">I", len(body)) + body
    return compress_frame(frame) if compress else frame


def send_msg(sock: socket.socket, obj: dict, compress: bool = False) -> int:
    """Send one message. Returns the number of bytes sent."""
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
    """Receive one message. Returns (msg, bytes_on_wire, bytes_uncompressed, was_compressed)."""
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    z = bool(length & Z_FLAG)
    length &= ~Z_FLAG
    if length > MAX_MSG:
        raise ConnectionError("frame too large")
    body = _recv_exact(sock, length)
    if z:
        d = zlib.decompressobj()
        try:
            body = d.decompress(body, MAX_MSG + 1)  # cap the size so a zip bomb can't eat all memory
        except zlib.error:
            raise ConnectionError("bad compressed frame")
        if len(body) > MAX_MSG or d.unconsumed_tail:
            raise ConnectionError("frame too large")
    return json.loads(body.decode("utf-8")), 4 + length, 4 + len(body), z


def recv_msg_ex(sock: socket.socket):
    """Receive one message. Returns (msg, bytes_on_wire)."""
    return recv_frame(sock)[:2]


def recv_msg(sock: socket.socket) -> dict:
    return recv_msg_ex(sock)[0]


def simplify(points, eps=1.0):
    """Simplify a stroke with Ramer-Douglas-Peucker: drop points closer than `eps`
    pixels to the line between their neighbours.
    """
    if len(points) < 3:
        return list(points)
    keep = [False] * len(points)
    keep[0] = keep[-1] = True
    stack = [(0, len(points) - 1)]
    while stack:  # iterative so long strokes don't hit the recursion limit
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
    """True if something already accepts connections on this port.
    On Windows bind() can succeed on a port another program is using, so we try connecting first.
    """
    targets = ("127.0.0.1", "::1") if host in ("0.0.0.0", "", "::") else (host,)
    for h in targets:
        try:
            socket.create_connection((h, port), timeout=timeout).close()
            return True
        except OSError:
            pass
    return False


def _own_port(s):
    """Make the port exclusive (SO_EXCLUSIVEADDRUSE on Windows, SO_REUSEADDR elsewhere)."""
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def listen_socket(host, port, kind=socket.SOCK_STREAM):
    """Bind a socket. For the "all addresses" host this is a dual-stack IPv6 socket that
    also accepts IPv4 clients, falling back to IPv4 if IPv6 isn't available.
    Returns (socket, ipv6). Raises OSError if the port is taken.
    """
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
                raise  # port taken, don't silently fall back to IPv4
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
    """Normalise an IPv4-mapped IPv6 address to plain IPv4."""
    ip = addr[0]
    return (ip[7:] if ip.startswith("::ffff:") and "." in ip else ip, addr[1])


def is_loopback(ip):
    return ip.startswith("127.") or ip == "::1"
