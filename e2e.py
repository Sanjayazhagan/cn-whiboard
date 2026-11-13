"""End-to-end encryption of drawings and chat.

The key comes from a shared passphrase (PBKDF2, salted with the room code) and never
leaves the client, so the server only ever stores ciphertext. The standard library has
no AES, so the cipher is HMAC-SHA256 in counter mode with encrypt-then-MAC:

    message = base64(nonce || ciphertext || tag)
"""
import base64
import hashlib
import hmac
import os

ROUNDS = 100_000
PREFIX = "e2e1:"  # prefix of an encrypted chat message


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
    """Decrypt a message. Returns None if the key is wrong or the data was tampered with."""
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
