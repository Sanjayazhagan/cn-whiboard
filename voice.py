"""Push-to-talk voice chat over UDP (the real-time half of the project; the board uses TCP).

Why UDP: for live audio a late packet is useless. TCP would stop everything to retransmit a lost
segment (head-of-line blocking) and the voice would stall and then lag behind. With UDP a lost
packet is 20 ms of silence and the conversation stays live. The price is that the application
must do what TCP did for it: number the packets, cope with reordering and smooth out jitter.

Audio: 8 kHz, mono, 20 ms per packet (160 samples), companded to 8 bits with G.711 mu-law -
the codec of the telephone network - so one packet carries 160 bytes (64 kbit/s + headers).

Datagram formats (all start with the magic bytes "WV"):
  client -> relay   WV 0x00 + JSON {"room","user","token"}        HELLO, repeated every 2 s (keep-alive)
  relay  -> client  WV 0x02 + JSON {"ok", "id", "names": {id: user}}
  client -> relay   WV 0x01 + seq(uint16) + timestamp ms(uint32) + 160 bytes mu-law
  relay  -> client  WV 0x01 + speaker id(uint8) + seq(uint16) + timestamp(uint32) + payload
  (seq + timestamp + payload is the same idea as an RTP header)

The relay (in the server) checks the HELLO against the room's member token, remembers the UDP
address, and forwards audio to the other registered members of the same room. The chaos lab's
loss setting is applied to voice packets too, so you can HEAR what packet loss does to UDP.

Receiver: one jitter buffer per speaker. Packets are stored by sequence number and played out
60 ms later, in order; a missing packet becomes silence (counted as lost), a packet that arrives
after its slot was played is dropped (counted as late). Interarrival jitter is estimated as in
RFC 3550:  J = J + (|D| - J) / 16.

Limit: voice is not encrypted, and browser guests have no voice (a web page cannot open UDP sockets).
Needs the optional `sounddevice` package for the microphone and speaker.
"""
import ctypes.util
import glob
import json
import os
import random
import socket
import struct
import sys
import threading
import time

from protocol import listen_socket

MAGIC = b"WV"
HELLO, AUDIO, WELCOME = 0, 1, 2
RATE, FRAME = 8000, 160                 # 20 ms
PREBUFFER = 3                           # packets held before playout starts (60 ms)
SILENCE = b"\x00\x00" * FRAME


def bundled_portaudio():
    """The PortAudio library packed into a PyInstaller build (Linux: libportaudio.so.2), or None."""
    base = getattr(sys, "_MEIPASS", None)
    if not getattr(sys, "frozen", False) or not base:
        return None
    libs = sorted(glob.glob(os.path.join(base, "libportaudio.so*")))
    return libs[0] if libs else None


def load_sounddevice():
    """sounddevice finds PortAudio with ctypes.util.find_library("portaudio"), which only looks at the system
    libraries and only for the unversioned libportaudio.so. The Linux executable carries its own
    libportaudio.so.2, so without help voice only worked on PCs that had libportaudio2 installed anyway."""
    lib = bundled_portaudio()
    if lib is None:
        import sounddevice
        return sounddevice
    find = ctypes.util.find_library
    ctypes.util.find_library = lambda name: find(name) or (lib if name == "portaudio" else None)
    try:
        import sounddevice
    finally:
        ctypes.util.find_library = find
    return sounddevice


try:
    sounddevice, SOUND_ERR = load_sounddevice(), ""
except (ImportError, OSError) as e:     # OSError: the PortAudio library is missing
    sounddevice, SOUND_ERR = None, str(e)


# ---------------------------------------------------------------- G.711 mu-law (tables built once)
def _encode_sample(s):
    s = max(-32635, min(32635, s))
    sign = 0x80 if s < 0 else 0
    s = abs(s) + 0x84
    exp = 7
    mask = 0x4000
    while exp > 0 and not s & mask:
        exp -= 1
        mask >>= 1
    return ~(sign | (exp << 4) | ((s >> (exp + 3)) & 0x0F)) & 0xFF


def _decode_byte(b):
    b = ~b & 0xFF
    s = (((b & 0x0F) << 3) + 0x84) << ((b >> 4) & 7)
    return (0x84 - s) if b & 0x80 else (s - 0x84)


_ENC = bytes(_encode_sample(s) for s in range(-32768, 32768))
_DEC = [_decode_byte(b) for b in range(256)]


def ulaw_encode(pcm: bytes) -> bytes:
    """16-bit little-endian PCM -> one mu-law byte per sample."""
    n = len(pcm) // 2
    return bytes(_ENC[s + 32768] for s in struct.unpack(f"<{n}h", pcm[:n * 2]))


def ulaw_decode(data: bytes) -> bytes:
    return struct.pack(f"<{len(data)}h", *[_DEC[b] for b in data])


def mix(frames):
    """Add several 16-bit PCM frames (several people talking at once), clipping at the limits."""
    if len(frames) == 1:
        return frames[0]
    cols = zip(*(struct.unpack(f"<{FRAME}h", f) for f in frames))
    return struct.pack(f"<{FRAME}h", *[max(-32768, min(32767, sum(c))) for c in cols])


# ---------------------------------------------------------------- relay (server side)
class Relay:
    def __init__(self, host, port, authenticate, loss_of=None, on_packet=None):
        """authenticate(room, user, token) -> bool; loss_of(room) -> percent of packets to drop."""
        self.sock, _ = listen_socket(host, port, socket.SOCK_DGRAM)
        self.auth, self.loss_of, self.on_packet = authenticate, loss_of or (lambda r: 0), on_packet or (lambda k: None)
        self.peers = {}        # addr -> {"room", "user", "id", "seen"}
        self.ids = {}          # (room, user) -> small speaker id
        self.lock = threading.Lock()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(2048)
            except OSError:
                continue
            if len(data) < 3 or data[:2] != MAGIC:
                continue
            try:
                if data[2] == HELLO:
                    self._hello(json.loads(data[3:].decode("utf-8")), addr)
                elif data[2] == AUDIO:
                    self._audio(data, addr)
            except (ValueError, KeyError, TypeError, OSError):
                continue

    def _hello(self, h, addr):
        room, user = str(h["room"]), str(h["user"])
        if not self.auth(room, user, h.get("token")):
            self.sock.sendto(MAGIC + bytes([WELCOME]) + b'{"ok":false}', addr)
            return
        now = time.time()
        with self.lock:
            for a in [a for a, p in self.peers.items() if now - p["seen"] > 8]:
                del self.peers[a]                                      # stopped sending keep-alives
            sid = self.ids.setdefault((room, user), len([k for k in self.ids if k[0] == room]) % 250 + 1)
            for a in [a for a, p in self.peers.items() if (p["room"], p["user"]) == (room, user) and a != addr]:
                del self.peers[a]                                      # same user from a new address
            self.peers[addr] = {"room": room, "user": user, "id": sid, "seen": now}
            names = {str(p["id"]): p["user"] for p in self.peers.values() if p["room"] == room}
        self.sock.sendto(MAGIC + bytes([WELCOME]) + json.dumps({"ok": True, "id": sid, "names": names}).encode(), addr)

    def _audio(self, data, addr):
        me = self.peers.get(addr)
        if me is None or len(data) > 1500:
            return
        me["seen"] = time.time()
        out = MAGIC + bytes([AUDIO, me["id"]]) + data[3:]
        loss = self.loss_of(me["room"])
        with self.lock:
            targets = [a for a, p in self.peers.items() if p["room"] == me["room"] and a != addr]
        for a in targets:
            if loss and random.random() * 100 < loss:
                self.on_packet("drop")
                continue
            try:
                self.sock.sendto(out, a)
                self.on_packet("relay")
            except OSError:
                pass


# ---------------------------------------------------------------- jitter buffer (receiver side)
class JitterBuffer:
    """Reorders one speaker's packets by sequence number and releases one per 20 ms tick."""
    def __init__(self):
        self.buf = {}
        self.next = None           # sequence number due next; None = waiting to (re)fill
        self.received = self.lost = self.late = self.empty = 0
        self.jitter = 0.0          # ms, RFC 3550 estimate
        self._prev = None          # (arrival ms, sender timestamp ms) of the previous packet

    @staticmethod
    def _ahead(a, b):
        """How far sequence number a is ahead of b, modulo 2^16 (negative = behind)."""
        d = (a - b) & 0xFFFF
        return d - 0x10000 if d > 0x7FFF else d

    def push(self, seq, ts, payload, now_ms):
        self.received += 1
        if self._prev is not None:
            d = abs((now_ms - self._prev[0]) - ((ts - self._prev[1]) & 0xFFFFFFFF))
            if d < 2000:
                self.jitter += (d - self.jitter) / 16
        self._prev = (now_ms, ts)
        if self.next is not None and self._ahead(seq, self.next) < 0:
            self.late += 1                              # its slot has already been played
            return
        self.buf[seq] = payload
        if len(self.buf) > 50:                          # far too much queued: jump ahead
            self.next = min(self.buf, key=lambda s: self._ahead(s, seq))

    def pop(self):
        """The payload for the next 20 ms, or None for silence."""
        if self.next is None:
            if len(self.buf) < PREBUFFER:
                return None
            self.next = min(self.buf, key=lambda s: self._ahead(s, next(iter(self.buf))))
        if self.next in self.buf:
            self.empty = 0
            data = self.buf.pop(self.next)
            self.next = (self.next + 1) & 0xFFFF
            return data
        if self.buf:                                    # a later packet is here, so this one is lost
            self.lost += 1
            self.next = (self.next + 1) & 0xFFFF
            return None
        self.empty += 1                                 # nothing at all: the speaker stopped talking
        if self.empty > 10:
            self.next = None                            # refill before the next talk spurt
        return None


# ---------------------------------------------------------------- client
class VoiceClient:
    def __init__(self, host, port, room, user, token):
        info = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
        self.addr = info[4]
        self.sock = socket.socket(info[0], socket.SOCK_DGRAM)
        self.sock.settimeout(0.5)
        self.hello = MAGIC + bytes([HELLO]) + json.dumps({"room": room, "user": user, "token": token}).encode()
        self.seq, self.t0 = random.randrange(65536), time.time()
        self.buffers, self.names = {}, {}
        self.sent = 0
        self.ok, self.alive, self.talking = False, True, False
        self.speaking = {}          # speaker name -> time of the last packet (for the "is talking" display)
        self.lock = threading.Lock()
        threading.Thread(target=self._recv, daemon=True).start()
        threading.Thread(target=self._keepalive, daemon=True).start()

    def _keepalive(self):
        while self.alive:
            try:
                self.sock.sendto(self.hello, self.addr)
            except OSError:
                pass
            time.sleep(2)

    def _recv(self):
        while self.alive:
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                if not self.alive:
                    return
                time.sleep(0.2)        # e.g. ICMP "port unreachable" while the server restarts
                continue
            if len(data) < 3 or data[:2] != MAGIC:
                continue
            if data[2] == WELCOME:
                try:
                    w = json.loads(data[3:].decode("utf-8"))
                except ValueError:
                    continue
                self.ok = bool(w.get("ok"))
                self.names = {int(k): v for k, v in w.get("names", {}).items()}
            elif data[2] == AUDIO and len(data) >= 10:
                sid, seq, ts = struct.unpack(">BHI", data[3:10])
                with self.lock:
                    jb = self.buffers.setdefault(sid, JitterBuffer())
                    jb.push(seq, ts, data[10:], time.time() * 1000)
                self.speaking[self.names.get(sid, f"#{sid}")] = time.time()

    def send_frame(self, pcm: bytes):
        """One 20 ms frame of 16-bit PCM from the microphone -> one UDP datagram."""
        self.seq = (self.seq + 1) & 0xFFFF
        ts = int((time.time() - self.t0) * 1000) & 0xFFFFFFFF
        try:
            self.sock.sendto(MAGIC + bytes([AUDIO]) + struct.pack(">HI", self.seq, ts) + ulaw_encode(pcm), self.addr)
            self.sent += 1
        except OSError:
            pass

    def pull(self) -> bytes:
        """The next 20 ms for the loudspeaker: every speaker's frame decoded and mixed."""
        with self.lock:
            frames = [jb.pop() for jb in self.buffers.values()]
        pcm = [ulaw_decode(f).ljust(FRAME * 2, b"\x00")[:FRAME * 2] for f in frames if f]
        return mix(pcm) if pcm else SILENCE

    def stats(self):
        with self.lock:
            b = list(self.buffers.values())
        got = sum(x.received for x in b)
        lost = sum(x.lost for x in b)
        return {"sent": self.sent, "received": got, "lost": lost, "late": sum(x.late for x in b),
                "loss_pct": 100.0 * lost / (got + lost) if got + lost else 0.0,
                "jitter": max((x.jitter for x in b), default=0.0), "connected": self.ok,
                "speakers": sorted(n for n, t in self.speaking.items() if time.time() - t < 0.4)}

    def close(self):
        self.alive = False
        try:
            self.sock.close()
        except OSError:
            pass


class AudioIO:
    """Microphone and loudspeaker through the optional `sounddevice` package (PortAudio)."""
    def __init__(self, client):
        if sounddevice is None:
            raise RuntimeError(f"no sound support ({SOUND_ERR}); pip install sounddevice, "
                               "Linux also needs: sudo apt install libportaudio2")
        self.c = client

        def mic(indata, frames, t, status):
            if self.c.talking:
                self.c.send_frame(bytes(indata))

        def speaker(outdata, frames, t, status):
            outdata[:] = self.c.pull()

        self.inp = sounddevice.RawInputStream(samplerate=RATE, blocksize=FRAME, channels=1, dtype="int16", callback=mic)
        self.out = sounddevice.RawOutputStream(samplerate=RATE, blocksize=FRAME, channels=1, dtype="int16",
                                               callback=speaker)
        self.inp.start()
        self.out.start()

    def close(self):
        for st in (self.inp, self.out):
            try:
                st.stop()
                st.close()
            except Exception:
                pass
