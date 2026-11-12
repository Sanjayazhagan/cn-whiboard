"""Connection diagnostics: "why can't I connect?" answered layer by layer.

Run from the client's login screen (button "Diagnose connection") or on its own:
    python diagnose.py SERVER-IP [PORT] [--no-tls]

Checks, bottom of the stack to the top:
  1. this PC's addresses (is it on a network at all, and on the same subnet as the server?)
  2. name / address resolution (IPv4 or IPv6)
  3. TCP three-way handshake to the server port. The three possible outcomes mean different things:
       connected            -> the server is reachable
       refused (RST)        -> the PC is reachable but nothing listens there (server not started / wrong port)
       timeout (no answer)  -> packets are dropped: wrong IP, different network, or a firewall
  4. TLS handshake (version, cipher, certificate fingerprint) - or a hint that TLS is on one side only
  5. application layer: PING -> PONG round-trip time over that connection
  6. the browser port (HTTP GET /info) and the voice port (UDP)
  7. UDP LAN discovery broadcast: does the server answer?
  8. the route: the system's traceroute / tracert (each router on the way; on one LAN this is a single hop)
"""
import json
import shutil
import socket
import ssl
import subprocess
import sys
import time

from auth import fingerprint
from protocol import DEFAULT_PORT, DISCOVER_MAGIC, DISCOVERY_PORT, WEB_PORT, recv_msg, send_msg

OK, WARN, BAD, INFO = "ok", "warn", "bad", "info"


def local_addresses():
    out = []
    try:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.connect(("10.255.255.255", 1))
        out.append(u.getsockname()[0])
        u.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ip not in out and not ip.startswith("127.") and ip != "::1":
                out.append(ip)
    except OSError:
        pass
    return out


def tcp_probe(host, port, timeout=3):
    """Returns (socket or None, verdict, text). Distinguishes refused from timed out."""
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        return s, OK, f"connected in {(time.time() - t0) * 1000:.0f} ms (TCP handshake SYN, SYN-ACK, ACK completed)"
    except ConnectionRefusedError:
        return None, BAD, ("REFUSED: the PC answered with RST, so it is reachable but no program listens on this "
                           "port. Is the server running, and is this the right port?")
    except socket.timeout:
        return None, BAD, (f"NO ANSWER in {timeout} s: the SYN was dropped. Wrong IP address, a different network / "
                           "VLAN, or a firewall on the server PC is blocking this port.")
    except OSError as e:
        return None, BAD, f"failed: {e}"


def traceroute(host, emit, hops=8):
    win = sys.platform.startswith("win")
    tool = shutil.which("tracert" if win else "traceroute") or (None if win else shutil.which("tracepath"))
    if not tool:
        return emit(INFO, "route", "no traceroute tool on this PC (Linux: sudo apt install traceroute)")
    if win:
        cmd, kw = [tool, "-d", "-h", str(hops), "-w", "700", host], {"creationflags": 0x08000000}   # no console window
    elif tool.endswith("tracepath"):
        cmd, kw = [tool, "-n", "-m", str(hops), host], {}
    else:
        cmd, kw = [tool, "-n", "-m", str(hops), "-w", "1", "-q", "1", host], {}
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=40, **kw).stdout
    except (OSError, subprocess.SubprocessError) as e:
        return emit(INFO, "route", f"traceroute could not run: {e}")
    lines = [ln.rstrip() for ln in out.splitlines() if ln.strip()]
    n = sum(1 for ln in lines if ln.strip()[:2].strip().isdigit())
    emit(OK if n else INFO, "route", f"{n} hop(s) to {host}" + (" - same LAN, no router in between" if n == 1 else ""))
    for ln in lines[:hops + 3]:
        emit(INFO, "", "    " + ln)


def run(host, port=DEFAULT_PORT, tls=True, emit=print, web_port=WEB_PORT, discovery_port=DISCOVERY_PORT,
        route=True):
    """Run every check, reporting each line through emit(verdict, check_name, text). Returns the number
    of failed checks."""
    bad = 0

    def out(verdict, name, text):
        nonlocal bad
        bad += verdict == BAD
        emit(verdict, name, text)

    mine = local_addresses()
    out(OK if mine else BAD, "this PC", "addresses: " + (", ".join(mine) if mine else
        "none - this PC is not connected to any network (check Wi-Fi / cable)"))
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ip = infos[0][4][0]
        fam = "IPv6" if infos[0][0] == socket.AF_INET6 else "IPv4"
        out(OK, "address", f"{host} -> {ip} ({fam})")
        if fam == "IPv4" and mine and not ip.startswith("127."):
            same = any(m.rsplit(".", 1)[0] == ip.rsplit(".", 1)[0] for m in mine if "." in m)
            out(OK if same else WARN, "subnet", "server is in the same /24 network as this PC" if same else
                "server is NOT in the same /24 network as this PC: are both on the same Wi-Fi / switch?")
    except OSError as e:
        out(BAD, "address", f"cannot resolve '{host}': {e}")
        return bad

    s, verdict, text = tcp_probe(host, port)
    out(verdict, f"TCP {port}", text)
    if s is not None:
        try:
            if tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                try:
                    s = ctx.wrap_socket(s)
                    out(OK, "TLS", f"{s.version()}, {s.cipher()[0]}; certificate fingerprint "
                                   f"{fingerprint(s.getpeercert(binary_form=True))[:23]}...")
                except (ssl.SSLError, OSError) as e:
                    out(BAD, "TLS", f"handshake failed ({getattr(e, 'reason', e)}): the server probably runs with "
                                    "--no-tls. Untick 'Encrypted connection'.")
                    s = None
            if s is not None:
                s.settimeout(3)
                t0 = time.time()
                send_msg(s, {"type": "PING", "t": t0 * 1000})
                try:
                    reply = recv_msg(s)
                    st = reply.get("stats", {})
                    if isinstance(reply.get("web"), int):       # the server says which web port it really uses
                        web_port = reply["web"]                 # (it moves on when 8080 is taken by another program)
                    out(OK, "protocol", f"PING -> {reply.get('type')} in {(time.time() - t0) * 1000:.0f} ms; server up "
                                        f"{st.get('uptime', '?')} s, {st.get('conns', '?')} connections so far")
                except (OSError, ValueError):
                    out(BAD, "protocol", "connected, but no valid PONG: " + ("the server probably uses TLS - tick "
                        "'Encrypted connection'" if not tls else "something else is listening on this port"))
        finally:
            if s is not None:
                s.close()

    w, verdict, text = tcp_probe(host, web_port, timeout=2)
    if w is not None:
        try:
            w.settimeout(2)
            w.sendall(b"GET /info HTTP/1.1\r\nHost: x\r\n\r\n")
            body = w.recv(4096).split(b"\r\n\r\n", 1)[-1]
            info = json.loads(body)
            out(OK, f"web {web_port}", f"HTTP 200, server '{info.get('name')}' role {info.get('role')}: phones can join")
        except (OSError, ValueError):
            out(WARN, f"web {web_port}", "port is open but ANOTHER program answers there, not the whiteboard: "
                                         "phones would see that program's page. Restart the server (it then picks a "
                                         "free web port by itself) or start it with --web-port <other number>")
        finally:
            w.close()
    else:
        out(WARN, f"web {web_port}", "not reachable: phones/browsers cannot join (firewall, --no-web or another --web-port)")

    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        u.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        u.settimeout(0.3)
        targets = {"255.255.255.255", host if "." in host else "127.0.0.1"}
        for m in mine:
            if "." in m:
                targets.add(m.rsplit(".", 1)[0] + ".255")
        for t in targets:
            try:
                u.sendto(DISCOVER_MAGIC, (t, discovery_port))
            except OSError:
                pass
        found, end = [], time.time() + 1.2
        while time.time() < end:
            try:
                data, addr = u.recvfrom(2048)
                d = json.loads(data.decode("utf-8"))
                if d.get("type") == "WB_SERVER":
                    found.append(f"{d.get('name')} at {addr[0]}:{d.get('port')}")
            except (OSError, ValueError):
                continue
        found = sorted(set(found))
        out(OK if found else WARN, f"UDP {discovery_port}", ("discovery answered by: " + "; ".join(found)) if found else
            "no answer to the discovery broadcast: UDP is blocked by a firewall or the Wi-Fi isolates clients. "
            "Typing the IP by hand still works.")
    finally:
        u.close()

    if route:
        traceroute(host, out)
    out(OK if not bad else BAD, "result", "everything needed to connect works" if not bad else
        f"{bad} check(s) failed - fix the first failed line first, the later ones usually follow from it")
    return bad


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        sys.exit(__doc__)
    marks = {OK: "[ OK ]", WARN: "[WARN]", BAD: "[FAIL]", INFO: "      "}
    failed = run(args[0], int(args[1]) if len(args) > 1 else DEFAULT_PORT, "--no-tls" not in sys.argv,
                 emit=lambda v, n, t: print(f"{marks[v]} {n:<10} {t}", flush=True))
    sys.exit(1 if failed else 0)
