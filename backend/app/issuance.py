"""Builds Campus ID credentials as SD-JWT VCs signed with the issuer key (ES256)."""

import time
from datetime import date, datetime, time as dtime, timezone
from typing import Any

import jwt

from app import campus_id
from app.config import settings
from app.issuer_keys import issuer_key
from app.sdjwt import disclosure_digest, make_disclosure


def status_url(credential_id: str) -> str:
    return f"{settings.public_base_url}/api/v1/status/{credential_id}"


def expiry_timestamp(valid_until: str) -> int:
    d = date.fromisoformat(valid_until)
    return int(datetime.combine(d, dtime(23, 59, 59), tzinfo=timezone.utc).timestamp())


def build_sd_jwt(claims: dict[str, Any], holder_jwk: dict[str, Any]) -> str:
    """Return `<issuer JWT>~<disclosures>~`. Every disclosable claim is hidden behind a salted digest."""
    key = issuer_key()
    now = int(time.time())

    disclosures, digests = [], []
    for name in campus_id.DISCLOSABLE:
        if claims.get(name) not in (None, ""):
            d = make_disclosure(name, claims[name])
            disclosures.append(d)
            digests.append(disclosure_digest(d))
    digests.sort()  # order must not leak which claim is which

    payload: dict[str, Any] = {
        "iss": settings.public_base_url,
        "vct": campus_id.VCT,
        "iat": now,
        "nbf": now,
        "exp": expiry_timestamp(claims["valid_until"]),
        "cnf": {"jwk": {k: holder_jwk[k] for k in ("kty", "crv", "x", "y") if k in holder_jwk}},
        "credential_id": claims["credential_id"],
        "status": {"type": "CampusIDRevocationCheck", "url": status_url(claims["credential_id"])},
        "_sd": digests,
        "_sd_alg": "sha-256",
    }
    headers = {"typ": "vc+sd-jwt", "kid": key.kid, "x5c": [key.cert_b64]}
    issuer_jwt = jwt.encode(payload, key.private_key, algorithm="ES256", headers=headers)
    return issuer_jwt + "~" + "".join(f"{d}~" for d in disclosures)
