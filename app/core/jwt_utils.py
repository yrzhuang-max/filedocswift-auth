import os
import binascii
import hmac
import hashlib
import base64
import json
from datetime import datetime, timedelta, UTC
from joserfc.errors import JoseError


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    padding = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + padding)


def get_jwt_secret() -> str:
    value = os.getenv("SECRET_KEY")
    if not value:
        raise RuntimeError("SECRET_KEY is not configured in .env")
    return value


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    secret = get_jwt_secret()
    key_bytes = binascii.unhexlify(secret.strip())

    header = {"alg": "HS256", "typ": "JWT"}
    payload = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=30)
    payload["exp"] = int(expire.timestamp())

    h_json = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    p_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    h_b64 = b64url_encode(h_json)
    p_b64 = b64url_encode(p_json)
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")

    sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
    sig_b64 = b64url_encode(sig)

    token = f"{h_b64}.{p_b64}.{sig_b64}"
    return token


def decode_access_token(token: str):
    secret = get_jwt_secret()
    key_bytes = binascii.unhexlify(secret.strip())

    parts = token.split(".")
    if len(parts) != 3:
        raise JoseError("Malformed token")
    h_b64, p_b64, sig_b64 = parts

    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    computed_sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
    computed_sig_b64 = b64url_encode(computed_sig)

    if not hmac.compare_digest(computed_sig_b64.encode("ascii"), sig_b64.encode("ascii")):
        raise JoseError("decode_error: Invalid JSON Web Signature")

    payload_bytes = b64url_decode(p_b64)
    claims = json.loads(payload_bytes)

    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        raise JoseError("missing exp")
    now = datetime.now(UTC).timestamp()
    if now > exp:
        raise JoseError("token expired")
    return claims


def verify_paddle_signature(raw_body: bytes, signature_header: str | None) -> bool:
    paddle_secret = os.getenv("PADDLE_WEBHOOK_SECRET", "")
    if not paddle_secret or paddle_secret == "REPLACE_ME":
        return True
    if not signature_header:
        return False

    parts = {}
    for seg in signature_header.split(";"):
        if "=" in seg:
            k, v = seg.split("=", 1)
            parts[k.strip()] = v.strip()
    ts = parts.get("ts")
    h1 = parts.get("h1")
    if not ts or not h1:
        return False

    message = f"{ts}:{raw_body.decode('utf-8')}"
    digest = hmac.new(
        paddle_secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(digest, h1)
