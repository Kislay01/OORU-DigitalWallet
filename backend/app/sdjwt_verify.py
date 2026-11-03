"""Verification of Campus ID SD-JWT presentations.

A presentation is `<issuer JWT>~<disclosure>~...~<KB-JWT>`. It is accepted only when:

1. the issuer JWT is signed by a trusted issuer key and is within its validity window,
2. every disclosure hashes to a digest listed in `_sd` (nothing added or altered),
3. the KB-JWT is signed by the holder key in `cnf.jwk`, is addressed to this verifier,
   carries this request's nonce, is fresh, and its `sd_hash` covers exactly what was presented,
4. every requested claim was disclosed,
5. the credential has not been revoked by the issuer.
"""

import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import jwt

from app import campus_id
from app.config import settings
from app.issuer_keys import issuer_key
from app.sdjwt import decode_disclosure, disclosure_digest, sd_hash, split

KB_MAX_AGE = 300
CLOCK_SKEW = 60
_RESERVED = {"_sd", "_sd_alg", "iss", "iat", "nbf", "exp", "cnf", "vct", "status", "credential_id", "sub"}


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class VerificationResult:
    status: str = "invalid"  # valid | invalid | revoked | expired
    checks: list[Check] = field(default_factory=list)
    claims: dict[str, Any] = field(default_factory=dict)
    credential_id: str | None = None

    def add(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append(Check(name, ok, detail))
        return ok

    @property
    def reasons(self) -> list[str]:
        return [f"{c.name}: {c.detail}" for c in self.checks if not c.ok]

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "credential_id": self.credential_id,
            "claims": self.claims,
            "checks": [c.__dict__ for c in self.checks],
            "reasons": self.reasons,
        }


def trusted_issuers() -> dict[str, dict[str, Any]]:
    """Issuer URL -> {kid: public JWK}. The Campus ID issuer runs in this deployment."""
    key = issuer_key()
    return {settings.public_base_url: {key.kid: key.public_jwk}}


def _issuer_public_key(header: dict[str, Any], iss: str | None):
    keys = trusted_issuers().get(iss or "")
    if not keys:
        raise ValueError(f"issuer {iss!r} is not trusted")
    jwk_ = keys.get(header.get("kid")) if header.get("kid") else (next(iter(keys.values())) if len(keys) == 1 else None)
    if not jwk_:
        raise ValueError("signing key id is not one of the issuer's keys")
    return jwt.PyJWK.from_dict(jwk_).key


def verify_presentation(
    presentation: str,
    *,
    nonce: str,
    audience: str,
    required_claims: list[str] | tuple[str, ...] = (),
) -> VerificationResult:
    """Run every structural and cryptographic check. Revocation is checked separately (needs the DB)."""
    r = VerificationResult()
    now = time.time()

    # 1. structure
    try:
        issuer_jwt, disclosures, kb_jwt = split(presentation.strip())
    except ValueError as e:
        r.add("format", False, str(e))
        return r
    if not r.add("format", kb_jwt is not None, "SD-JWT with key binding" if kb_jwt else "key binding JWT is missing"):
        return r

    # 2. issuer signature and validity window
    try:
        header = jwt.get_unverified_header(issuer_jwt)
        unverified = jwt.decode(issuer_jwt, options={"verify_signature": False})
        if header.get("alg") != "ES256":
            raise ValueError("credential must be signed with ES256")
        if header.get("typ") not in ("vc+sd-jwt", "dc+sd-jwt"):
            raise ValueError("credential typ must be vc+sd-jwt")
        key = _issuer_public_key(header, unverified.get("iss"))
        payload = jwt.decode(
            issuer_jwt,
            key,
            algorithms=["ES256"],
            leeway=CLOCK_SKEW,
            options={"require": ["iss", "iat", "exp", "cnf", "_sd"], "verify_aud": False},
        )
    except jwt.ExpiredSignatureError:
        r.add("issuer_signature", True, "signed by trusted issuer")
        r.add("validity", False, "credential has expired")
        r.status = "expired"
        return r
    except (jwt.PyJWTError, ValueError) as e:
        r.add("issuer_signature", False, str(e))
        return r
    r.add("issuer_signature", True, "signed by trusted issuer")
    r.add("validity", True, "within validity period")
    r.credential_id = payload.get("credential_id")

    if not r.add("credential_type", payload.get("vct") == campus_id.VCT, f"vct is {payload.get('vct')!r}"):
        return r
    if not r.add("digest_alg", payload.get("_sd_alg", "sha-256") == "sha-256", "only sha-256 is supported"):
        return r

    # 3. disclosures
    allowed_digests = set(payload.get("_sd") or [])
    seen: set[str] = set()
    disclosed: dict[str, Any] = {}
    for d in disclosures:
        digest = disclosure_digest(d)
        try:
            _, name, value = decode_disclosure(d)
        except (ValueError, json.JSONDecodeError, TypeError):
            r.add("disclosures", False, "a disclosure could not be decoded")
            return r
        if digest not in allowed_digests:
            r.add("disclosures", False, f"disclosure for {name!r} was not signed by the issuer")
            return r
        if digest in seen or name in disclosed:
            r.add("disclosures", False, f"disclosure for {name!r} appears twice")
            return r
        if name in _RESERVED or name not in campus_id.DISCLOSABLE:
            r.add("disclosures", False, f"unexpected claim {name!r}")
            return r
        seen.add(digest)
        disclosed[name] = value
    r.add("disclosures", True, f"{len(disclosed)} field(s) disclosed, all signed by the issuer")

    # 4. key binding
    try:
        holder_jwk = (payload.get("cnf") or {}).get("jwk")
        if not isinstance(holder_jwk, dict):
            raise ValueError("credential is not bound to a holder key")
        kb_header = jwt.get_unverified_header(kb_jwt)
        if kb_header.get("typ") != "kb+jwt":
            raise ValueError("key binding typ must be kb+jwt")
        if kb_header.get("alg") != "ES256":
            raise ValueError("key binding must be signed with ES256")
        kb = jwt.decode(
            kb_jwt,
            jwt.PyJWK.from_dict({**holder_jwk, "alg": "ES256"}).key,
            algorithms=["ES256"],
            audience=audience,
            options={"require": ["aud", "iat", "nonce", "sd_hash"]},
        )
        if not secrets.compare_digest(str(kb["nonce"]), nonce):
            raise ValueError("nonce does not match this request (possible replay)")
        if kb["iat"] > now + CLOCK_SKEW or now - kb["iat"] > KB_MAX_AGE:
            raise ValueError("key binding is too old or from the future")
        presented = presentation.strip()[: -len(kb_jwt)]
        if not secrets.compare_digest(str(kb["sd_hash"]), sd_hash(presented)):
            raise ValueError("sd_hash does not match the presented credential")
    except (jwt.PyJWTError, ValueError) as e:
        r.add("holder_binding", False, str(e))
        return r
    r.add("holder_binding", True, "presented by the credential's holder for this request")

    # 5. requested claims
    missing = [c for c in required_claims if c not in disclosed]
    if not r.add("requested_fields", not missing, f"missing: {', '.join(missing)}" if missing else "all requested fields shared"):
        return r

    r.claims = disclosed
    r.status = "valid"
    return r
