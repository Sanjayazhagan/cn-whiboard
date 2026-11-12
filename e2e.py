"""End-to-end encryption for room content (standard library only).

TLS protects the link between a client and the server, but the server itself still sees every
stroke and stores it in its database. With an end-to-end key the clients encrypt drawings and chat
themselves; the server relays and stores only ciphertext it cannot read.

  key      = PBKDF2-HMAC-SHA256(passphrase, salt = "lan-whiteboard-e2e:" + room code, 100 000 rounds)
             -> 32 bytes for encryption + 32 bytes for authentication. The passphrase never leaves the client.
  cipher   = a stream cipher built from HMAC-SHA256 in counter mode:
             keystream block i = HMAC(k_enc, nonce || i);  ciphertext = plaintext XOR keystream
  tag      = HMAC-SHA256(k_mac, nonce || ciphertext)       (encrypt-then-MAC: tampering or a wrong key is detected)
  message  = base64( nonce(16 random bytes) || ciphertext || tag(32) )

Python's standard library has no AES, and the project must run without extra packages, so the
cipher is built from HMAC-SHA256 used as a pseudo-random function - a textbook construction.
What the server still sees: who is in the room, when something is drawn, object ids and sizes
(traffic analysis), and anything drawn without a key.
"""
import base64
import hashlib
import hmac
import os

ROUNDS = 100_000
PREFIX = "e2e1:"          # marks an encrypted chat line


def derive(passphrase: str, room: str):
    dk = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), b"lan-whiteboard-e2e:" + room.encode("utf-8"),
                             ROUNDS, dklen=64)
    return dk[:32], dk[32:]


def _keystream(k_enc, nonce, n):
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hmac.digest(k_enc, nonce + i.to_bytes(8, "big"), "sha256")
        i += 1
    return bytes(out[:n])


def _xor(a, b):
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big") if a else b""


def seal(keys, plaintext: bytes) -> str:
    k_enc, k_mac = keys
    nonce = os.urandom(16)
    ct = _xor(plaintext, _keystream(k_enc, nonce, len(plaintext)))
    tag = hmac.digest(k_mac, nonce + ct, "sha256")
    return base64.b64encode(nonce + ct + tag).decode("ascii")


def unseal(keys, token: str):
    """The plaintext, or None if the key is wrong or the message was altered."""
    try:
        raw = base64.b64decode(token, validate=True)
    except (ValueError, TypeError):
        return None
    if len(raw) < 48:
        return None
    k_enc, k_mac = keys
    nonce, ct, tag = raw[:16], raw[16:-32], raw[-32:]
    if not hmac.compare_digest(tag, hmac.digest(k_mac, nonce + ct, "sha256")):
        return None
    return _xor(ct, _keystream(k_enc, nonce, len(ct)))
