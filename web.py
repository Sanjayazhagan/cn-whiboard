"""Minimal HTTP + WebSocket server (RFC 6455) for browser and phone clients.

Browsers can't open raw TCP sockets, so the server also serves the web page here and
upgrades /ws to a WebSocket. Each text frame carries the same JSON message the desktop
client sends, so the room code doesn't care which kind of client it is talking to.
"""
import base64
import hashlib
import json
import socket
import struct
import threading

from protocol import listen_socket, norm_addr

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"  # from the RFC
MAX_HEADER = 16 * 1024
MAX_WS_MSG = 4 * 1024 * 1024


def ws_accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode("ascii")).digest()).decode("ascii")


def ws_encode(payload: bytes, opcode: int = 1) -> bytes:
    """Build one unmasked frame (server frames are never masked)."""
    n = len(payload)
    if n < 126:
        head = struct.pack(">BB", 0x80 | opcode, n)
    elif n < 65536:
        head = struct.pack(">BBH", 0x80 | opcode, 126, n)
    else:
        head = struct.pack(">BBQ", 0x80 | opcode, 127, n)
    return head + payload


def _xor(data: bytes, key: bytes) -> bytes:
    """Unmask a payload with the 4-byte key."""
    n = len(data)
    if not n:
        return b""
    k = (key * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(k, "big")).to_bytes(n, "big")


def _exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed connection")
        buf.extend(chunk)
    return bytes(buf)


def ws_recv(sock, send):
    """Read one complete message. Returns (payload, bytes_on_wire).
    Answers pings, joins fragments and raises ConnectionError when the browser closes.
    """
    parts, wire = [], 0
    while True:
        b0, b1 = _exact(sock, 2)
        fin, opcode, masked, n = b0 & 0x80, b0 & 0x0F, b1 & 0x80, b1 & 0x7F
        wire += 2
        if n == 126:
            (n,) = struct.unpack(">H", _exact(sock, 2)); wire += 2
        elif n == 127:
            (n,) = struct.unpack(">Q", _exact(sock, 8)); wire += 8
        if not masked:
            raise ConnectionError("client frames must be masked")
        if n > MAX_WS_MSG or sum(map(len, parts)) + n > MAX_WS_MSG:
            raise ConnectionError("message too large")
        key = _exact(sock, 4)
        data = _xor(_exact(sock, n), key)
        wire += 4 + n
        if opcode == 8:  # close
            send(ws_encode(data[:2], 8))
            raise ConnectionError("websocket closed")
        if opcode == 9:  # ping
            send(ws_encode(data, 10))
            continue
        if opcode == 10:
            continue
        parts.append(data)
        if fin:
            return b"".join(parts), wire


def _http(sock, status, body=b"", ctype="text/plain; charset=utf-8", extra=""):
    head = (f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
            f"Cache-Control: no-store\r\nConnection: close\r\n{extra}\r\n")
    sock.sendall(head.encode("ascii") + body)


def read_request(sock):
    """Read the request line and headers. Returns (method, path, headers)."""
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("closed before the request was complete")
        buf.extend(chunk)
        if len(buf) > MAX_HEADER:
            raise ConnectionError("request header too large")
    lines = bytes(buf).split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
    method, path, _version = lines[0].split(" ", 2)
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return method, path, headers


def serve_connection(sock, addr, page, info, on_websocket, timeout, extra=None):
    """Handle one browser connection: a plain HTTP request or a WebSocket upgrade."""
    try:
        sock.settimeout(timeout)
        method, path, h = read_request(sock)
        route = path.split("?", 1)[0]
        if route == "/ws":
            key = h.get("sec-websocket-key")
            if "websocket" not in h.get("upgrade", "").lower() or not key:
                return _http(sock, "400 Bad Request", b"WebSocket upgrade expected")
            sock.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                          f"Sec-WebSocket-Accept: {ws_accept(key)}\r\n\r\n").encode("ascii"))
            on_websocket(sock, addr)
            return
        if method != "GET":
            return _http(sock, "405 Method Not Allowed", b"GET only", extra="Allow: GET\r\n")
        if route in ("/", "/index.html"):
            return _http(sock, "200 OK", page(), "text/html; charset=utf-8")
        if extra is not None:  # e.g. the admin dashboard
            query = dict(kv.split("=", 1) for kv in path.partition("?")[2].split("&") if "=" in kv)
            res = extra(route, query)
            if res is not None:
                return _http(sock, *res)
        if route == "/info":
            return _http(sock, "200 OK", json.dumps(info()).encode("utf-8"), "application/json")
        _http(sock, "404 Not Found", b"Not found")
    except (OSError, ValueError):
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def start(host, port, page, info, on_websocket, timeout=15, extra=None):
    """Listen on `port` and handle each connection in its own thread."""
    srv, _v6 = listen_socket(host, port)
    srv.listen(50)

    def loop():
        while True:
            try:
                s, addr = srv.accept()
            except OSError:
                return
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(target=serve_connection,
                             args=(s, norm_addr(addr), page, info, on_websocket, timeout, extra),
                             daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return srv
