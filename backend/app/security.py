import hashlib
import hmac
import secrets
import time
from collections import defaultdict
from typing import Any

import jwt

from app.config import settings

_ITERATIONS = 600_000
_FAILED: dict[str, list[float]] = defaultdict(list)
_WINDOW = 300
_MAX_FAILED = 5


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return f"{salt.hex()}${_ITERATIONS}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, iters, dk_hex = stored.split("$")
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
    return hmac.compare_digest(dk.hex(), dk_hex)


def create_token(username: str, role: str) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": username,
        "role": role,
        "iss": settings.token_issuer,
        "aud": settings.token_audience,
        "iat": now,
        "exp": now + settings.token_ttl_seconds,
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def decode_token(token: str) -> dict[str, Any] | None:
    try:
        return jwt.decode(
            token,
            settings.secret_key,
            algorithms=["HS256"],
            audience=settings.token_audience,
            issuer=settings.token_issuer,
        )
    except jwt.PyJWTError:
        return None


def login_allowed(key: str) -> bool:
    now = time.time()
    _FAILED[key] = [t for t in _FAILED[key] if now - t < _WINDOW]
    return len(_FAILED[key]) < _MAX_FAILED


def record_failed_login(key: str) -> None:
    _FAILED[key].append(time.time())


def clear_failed_logins(key: str) -> None:
    _FAILED.pop(key, None)
