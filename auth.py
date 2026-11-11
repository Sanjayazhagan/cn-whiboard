"""Accounts, password hashing, JWT and TLS certificates (standard library, plus optional `cryptography`).

Passwords: never stored. We store PBKDF2-HMAC-SHA256(password, random 16-byte salt, 200 000 rounds).
  The salt makes equal passwords hash differently (no precomputed tables); the many rounds make
  each guess slow for someone who steals the database. Checking uses a constant-time compare.

JWT (JSON Web Token, RFC 7519), HS256: header.payload.signature, each part base64url without padding.
  signature = HMAC-SHA256(server secret, "header.payload"). The server can check a token without a
  database lookup and nobody without the secret can forge or edit one. A JWT is SIGNED, not
  encrypted: anyone who sees it can read the payload, which is why the connection uses TLS.

TLS: the server needs a certificate. On first start it creates a self-signed one (server_cert.pem /
  server_key.pem). Clients cannot check a self-signed certificate against a CA, so they use
  "trust on first use" like SSH: remember the certificate's SHA-256 fingerprint and warn if it changes.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import time

PBKDF2_ROUNDS = 200_000
JWT_TTL = 24 * 3600                 # tokens are valid for 24 hours
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,20}$")
MIN_PASSWORD = 4


# ---------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt, want = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), _unb64(salt), int(rounds))
        return hmac.compare_digest(dk, _unb64(want))        # constant time: no timing side channel
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------- JWT (HS256)
def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_encode(claims: dict, secret: bytes) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    sig = hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64(sig)}"


class TokenError(Exception):
    pass


def jwt_decode(token: str, secret: bytes) -> dict:
    """Return the claims of a valid, unexpired token; raise TokenError otherwise."""
    try:
        header, payload, sig = token.split(".")
        h = json.loads(_unb64(header))
        claims = json.loads(_unb64(payload))
        given = _unb64(sig)
    except (ValueError, AttributeError, TypeError):
        raise TokenError("malformed token")
    if h.get("alg") != "HS256":           # never accept "none" or another algorithm chosen by the client
        raise TokenError("unsupported algorithm")
    want = hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(want, given):
        raise TokenError("bad signature")
    if not isinstance(claims, dict) or claims.get("exp", 0) < time.time():
        raise TokenError("token expired")
    return claims


def issue_token(user: str, secret: bytes) -> tuple:
    now = int(time.time())
    claims = {"sub": user, "iat": now, "exp": now + JWT_TTL, "iss": "lan-whiteboard"}
    return jwt_encode(claims, secret), claims["exp"]


# ---------------------------------------------------------------- login rate limiting
class RateLimiter:
    """At most `limit` failed logins per IP address per `window` seconds (slows down password guessing)."""
    def __init__(self, limit=5, window=60):
        self.limit, self.window, self.fails = limit, window, {}

    def blocked(self, ip):
        now = time.time()
        self.fails[ip] = [t for t in self.fails.get(ip, []) if now - t < self.window]
        return len(self.fails[ip]) >= self.limit

    def failed(self, ip):
        self.fails.setdefault(ip, []).append(time.time())

    def reset(self, ip):
        self.fails.pop(ip, None)


# ---------------------------------------------------------------- TLS certificate
def fingerprint(der: bytes) -> str:
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def ensure_certificate(cert_path, key_path, name="lan-whiteboard"):
    """Create a self-signed certificate if none exists. Returns a message describing what happened,
    or raises RuntimeError if no tool is available (then the server runs without TLS)."""
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return f"using certificate {cert_path}"
    try:                                       # 1st choice: the `cryptography` package (pip install cryptography)
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=3650))
                .sign(key, hashes.SHA256()))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return f"created self-signed certificate {cert_path}"
    except ImportError:
        pass
    if shutil.which("openssl"):                # 2nd choice: the openssl command line tool
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-days", "3650", "-subj", f"/CN={name}", "-keyout", key_path, "-out", cert_path],
                       check=True, capture_output=True)
        return f"created self-signed certificate {cert_path} (openssl)"
    raise RuntimeError("cannot create a TLS certificate: run `pip install cryptography` (or install openssl)")
