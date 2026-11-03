"""SD-JWT encoding helpers (IETF SD-JWT, sha-256 digests).

Format: <issuer-signed JWT>~<disclosure>~<disclosure>~...~[<KB-JWT>]
"""

import base64
import hashlib
import json
import secrets
from typing import Any


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def make_disclosure(name: str, value: Any) -> str:
    salt = b64url(secrets.token_bytes(16))
    return b64url(json.dumps([salt, name, value], separators=(",", ":"), ensure_ascii=False).encode())


def disclosure_digest(disclosure: str) -> str:
    return b64url(hashlib.sha256(disclosure.encode("ascii")).digest())


def decode_disclosure(disclosure: str) -> tuple[str, str, Any]:
    salt, name, value = json.loads(unb64url(disclosure))
    return salt, name, value


def split(sd_jwt: str) -> tuple[str, list[str], str | None]:
    """Return (issuer_jwt, disclosures, kb_jwt_or_None)."""
    parts = sd_jwt.split("~")
    if len(parts) < 2:
        raise ValueError("Not an SD-JWT")
    issuer_jwt, *rest = parts
    kb_jwt = rest[-1] or None
    return issuer_jwt, [d for d in rest[:-1] if d], kb_jwt


def sd_hash(sd_jwt_without_kb: str) -> str:
    """Hash of the presented SD-JWT (issuer JWT + disclosures + trailing ~) used in the KB-JWT."""
    return b64url(hashlib.sha256(sd_jwt_without_kb.encode("ascii")).digest())
