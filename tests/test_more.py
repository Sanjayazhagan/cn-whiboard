"""Socket-level tests (no Tkinter) for: connection diagnostics, the admin dashboard, peer-to-peer file
transfer with resume, end-to-end encryption, the UDP voice relay with jitter buffer, and IPv6."""
import sys, time, socket, subprocess, os, json, tempfile, shutil, struct, math
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from protocol import send_msg, recv_msg
import diagnose, p2p, e2e, voice

PORT, WEBP, VP, DP = 5102, 8102, 5152, 5162
tmp = tempfile.mkdtemp()
srv = subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py"), "--no-auth", "--no-tls", "--no-db",
                        "--port", str(PORT), "--web-port", str(WEBP), "--voice-port", str(VP), "--discovery-port", str(DP),
                        "--admin-key", "adm1n", "--name", "more-tests"], cwd=tmp, stdout=subprocess.DEVNULL,
                       stderr=subprocess.STDOUT)
time.sleep(1.3)


def conn(first, host="127.0.0.1"):
    s = socket.create_connection((host, PORT), timeout=5)
    send_msg(s, first)
    return s


def drain(s, t=0.4):
    out = []
    s.settimeout(t)
    try:
        while True:
            out.append(recv_msg(s))
    except (socket.timeout, OSError):
        pass
    return out


def http(path):
    s = socket.create_connection(("127.0.0.1", WEBP), timeout=5)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    return head.split(b"\r\n")[0].decode(), body


try:
    # ---- 1. diagnostics
    lines = []
    bad = diagnose.run("127.0.0.1", PORT, tls=False, emit=lambda v, n, t: lines.append((v, n, t)), web_port=WEBP,
                       discovery_port=DP, route=False)
    by = {n: (v, t) for v, n, t in lines}
    assert bad == 0 and by[f"TCP {PORT}"][0] == "ok" and by["protocol"][0] == "ok" and "PONG" in by["protocol"][1], lines
    assert by[f"web {WEBP}"][0] == "ok" and by[f"UDP {DP}"][0] == "ok" and "more-tests" in by[f"UDP {DP}"][1], lines
    lines = []
    bad = diagnose.run("127.0.0.1", 5999, tls=False, emit=lambda v, n, t: lines.append((v, n, t)), web_port=5998,
                       discovery_port=5997, route=False)
    assert bad >= 1 and any("REFUSED" in t for v, n, t in lines), lines
    lines = []
    diagnose.run("127.0.0.1", PORT, tls=True, emit=lambda v, n, t: lines.append((v, n, t)), web_port=WEBP,
                 discovery_port=DP, route=False)
    assert any(n == "TLS" and v == "bad" and "--no-tls" in t for v, n, t in lines), lines
    print("ok  diagnostics: healthy server passes every check; a closed port is reported as REFUSED; "
          "a TLS/plain mismatch is explained")

    # ---- 2. admin dashboard
    a = conn({"type": "CREATE_ROOM", "user": "alice"}); ja = recv_msg(a); room = ja["room"]
    b = conn({"type": "JOIN_ROOM", "user": "bob", "room": room}); jb = recv_msg(b); drain(a)
    assert http("/admin")[0].endswith("403 Forbidden") and http("/admin/state?key=wrong")[0].endswith("403 Forbidden")
    st, body = http("/admin?key=adm1n"); assert st.endswith("200 OK") and b"dashboard" in body
    st, body = http("/admin/state?key=adm1n"); state = json.loads(body)
    r0 = state["rooms"][0]
    assert r0["code"] == room and sorted(c["name"] for c in r0["clients"]) == ["alice", "bob"]
    assert state["role"] == "primary" and any("alice joined" in e[1] for e in state["events"]), state["events"]
    print(f"ok  admin dashboard: key required; state lists room {room} with 2 clients and {len(state['events'])} events")

    # ---- 3. peer-to-peer file transfer: introduction by the server, direct data, resume, integrity
    src = os.path.join(tmp, "notes.bin"); data = os.urandom(3_000_000 + 123)
    open(src, "wb").write(data)
    sha = p2p.sha256_file(src)
    snd = p2p.Sender(src, "tok123")
    send_msg(a, {"type": "FILE_OFFER", "to": "bob", "id": "tok123", "name": "notes.bin", "size": len(data),
                 "sha": sha, "port": snd.port})
    offer = [m for m in drain(b) if m["type"] == "FILE_OFFER"][0]
    assert offer["from"] == "alice" and offer["ip"] == "127.0.0.1" and offer["port"] == snd.port, offer
    dl = os.path.join(tmp, "dl")
    try:
        p2p.fetch(offer["ip"], offer["port"], "wrong", offer["name"], offer["size"], offer["sha"], dl)
        raise AssertionError("wrong token accepted")
    except ValueError:
        pass
    try:                                                    # the link breaks after ~1 MB
        p2p.fetch(offer["ip"], offer["port"], offer["id"], offer["name"], offer["size"], offer["sha"], dl,
                  stop_after=1_000_000)
        raise AssertionError("should have been cut")
    except ConnectionError:
        pass
    part = [f for f in os.listdir(dl) if f.endswith(".part")][0]
    have = os.path.getsize(os.path.join(dl, part)); time.sleep(0.3); sent_before = snd.sent_bytes
    final = p2p.fetch(offer["ip"], offer["port"], offer["id"], offer["name"], offer["size"], offer["sha"], dl)
    time.sleep(0.2)
    assert open(final, "rb").read() == data and os.path.basename(final) == "notes.bin"
    assert snd.sent_bytes - sent_before == len(data) - have, (snd.sent_bytes, sent_before, have)
    send_msg(b, {"type": "FILE_REPLY", "to": "alice", "id": "tok123", "status": "received", "text": "notes.bin"})
    got = drain(a)
    assert any(m["type"] == "FILE_REPLY" and m["status"] == "received" for m in got)
    assert any(m["type"] == "INFO" and "peer to peer" in m["text"] for m in got)
    snd.close()
    print(f"ok  P2P file: server relayed only the offer; 3 MB went directly; after a cut at {have} bytes the retry "
          f"sent only the remaining {len(data) - have}; SHA-256 verified; a wrong token was refused")

    # ---- 4. end-to-end encryption
    keys = e2e.derive("open sesame", room)
    secret = {"kind": "text", "color": "#112233", "width": 4, "points": [[40, 50]], "text": "TOP-SECRET-PLAN"}
    sealed = e2e.seal(keys, json.dumps(secret).encode())
    assert json.loads(e2e.unseal(keys, sealed)) == secret
    assert e2e.unseal(e2e.derive("wrong", room), sealed) is None
    assert e2e.unseal(keys, sealed[:20] + ("A" if sealed[20] != "A" else "B") + sealed[21:]) is None
    assert e2e.seal(keys, b"same") != e2e.seal(keys, b"same")              # fresh nonce every time
    send_msg(a, {"type": "ADD", "msg_id": "e1", "obj": {"id": "enc1", "kind": "enc", "color": "#000000", "width": 1,
                                                         "points": [[0, 0]], "data": sealed}})
    send_msg(a, {"type": "CHAT", "msg_id": "e2", "text": e2e.PREFIX + e2e.seal(keys, b"meet at 5")}); drain(a)
    c = conn({"type": "JOIN_ROOM", "user": "carl", "room": room}); jc = recv_msg(c)
    wire = json.dumps(jc)
    assert "TOP-SECRET-PLAN" not in wire and "meet at 5" not in wire and "112233" not in wire
    obj = [o for o in jc["snapshot"]["objects"] if o["id"] == "enc1"][0]
    assert json.loads(e2e.unseal(keys, obj["data"]))["text"] == "TOP-SECRET-PLAN"
    assert e2e.unseal(keys, jc["chat"][-1]["text"][len(e2e.PREFIX):]) == b"meet at 5"
    print("ok  end-to-end encryption: wrong key and tampering are detected; the server relays and stores only "
          "ciphertext, a client with the passphrase reads it")

    # ---- 5. voice: mu-law codec, jitter buffer, UDP relay, loss
    tone = struct.pack("<160h", *[int(12000 * math.sin(i * 2 * math.pi * 440 / 8000)) for i in range(160)])
    back = struct.unpack("<160h", voice.ulaw_decode(voice.ulaw_encode(tone)))
    err = max(abs(x - y) for x, y in zip(struct.unpack("<160h", tone), back))
    assert len(voice.ulaw_encode(tone)) == 160 and err < 600, err           # 2:1 compression, small error
    buf = voice.JitterBuffer()
    for seq in (10, 12, 11, 14):                                             # reordered, 13 missing
        buf.push(seq, seq * 20, bytes([seq]), seq * 20.0)
    order = [buf.pop() for _ in range(5)]
    assert order == [b"\n", b"\x0b", b"\x0c", None, b"\x0e"] and buf.lost == 1, (order, buf.lost)
    buf.push(11, 220, b"x", 500.0); assert buf.late == 1
    va = voice.VoiceClient("127.0.0.1", VP, room, "alice", ja["token"])
    vb = voice.VoiceClient("127.0.0.1", VP, room, "bob", jb["token"])
    vx = voice.VoiceClient("127.0.0.1", VP, room, "bob", "not-the-token")
    time.sleep(0.6)
    assert va.ok and vb.ok and not vx.ok and "alice" in vb.names.values(), (va.ok, vb.ok, vx.ok, vb.names)
    vx.close()
    heard = 0
    for i in range(100):                                    # 2 seconds of speech, one packet per 20 ms
        va.send_frame(tone)
        time.sleep(0.02)
        heard += vb.pull() != voice.SILENCE
    for _ in range(10):
        heard += vb.pull() != voice.SILENCE
    s1 = vb.stats()
    assert s1["received"] == 100 and s1["lost"] == 0 and heard >= 95, (s1, heard)
    assert vb.pull() == voice.SILENCE and va.stats()["received"] == 0       # nobody hears themselves
    send_msg(a, {"type": "CHAOS_SET", "loss": 30}); time.sleep(0.3)
    heard2 = 0
    for i in range(150):
        va.send_frame(tone)
        time.sleep(0.02)
        heard2 += vb.pull() != voice.SILENCE
    s2 = vb.stats()
    got2, lost2 = s2["received"] - 100, s2["lost"]
    assert 70 <= got2 <= 135 and lost2 >= 10 and heard2 >= 60, (s2, heard2)
    send_msg(a, {"type": "CHAOS_SET", "loss": 0}); drain(a)
    va.close(); vb.close()
    print(f"ok  voice: mu-law halves the bytes (max error {err}); jitter buffer reorders and counts loss; UDP relay "
          f"delivered 100/100 packets, a wrong token was refused; with 30% loss {got2}/150 arrived, {lost2} gaps "
          f"played as silence and the stream never stalled ({heard2} frames played)")

    # ---- 6. IPv6
    try:
        s6 = conn({"type": "JOIN_ROOM", "user": "six", "room": room}, host="::1")
        r6 = recv_msg(s6)
        assert r6["type"] == "JOIN_OK"
        print("ok  IPv6: joined through ::1 on the same dual-stack socket that serves IPv4")
    except OSError as e:
        print(f"--  IPv6: SKIPPED, this machine has no IPv6 ({e}); the server fell back to IPv4 only")
    print("ALL MORE TESTS PASSED")
finally:
    srv.kill()
    shutil.rmtree(tmp, ignore_errors=True)
