"""OpenID4VCI issuer: credential offers (pre-authorized code), token and credential endpoints."""

import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import jwt
from fastapi import APIRouter, Depends, Form, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import campus_id
from app.audit import record
from app.config import settings
from app.db import get_session
from app.deps import require_admin
from app.errors import api_error
from app.issuance import build_sd_jwt, expiry_timestamp
from app.issuer_keys import issuer_key
from pydantic import ValidationError

from app.issuer_schemas import BulkOfferRequest, BulkRowResult, OfferCreate, OfferOut, OfferStatus
from app.models import CredentialOffer, CredentialRecord
from app.timeutil import aware, utcnow

router = APIRouter(tags=["issuer"])

PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
OFFER_TTL = timedelta(hours=24)
TOKEN_TTL = timedelta(minutes=10)
PROOF_MAX_AGE = 300


def _issuer_url() -> str:
    return settings.public_base_url


def _vci_error(status: int, error: str, description: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"error": error, "error_description": description})


# ---------------------------------------------------------------- metadata


@router.get("/.well-known/openid-credential-issuer")
async def credential_issuer_metadata() -> dict[str, Any]:
    base = _issuer_url()
    return {
        "credential_issuer": base,
        "authorization_servers": [base],
        "credential_endpoint": f"{base}/api/v1/issuer/credential",
        "display": [{"name": "OORU Campus ID Issuer", "locale": "en"}],
        "credential_configurations_supported": {
            campus_id.CONFIGURATION_ID: {
                "format": campus_id.FORMAT,
                "vct": campus_id.VCT,
                "cryptographic_binding_methods_supported": ["jwk"],
                "credential_signing_alg_values_supported": ["ES256"],
                "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}},
                "display": [{"name": "Campus ID", "locale": "en", "background_color": "#1e3a8a", "text_color": "#ffffff"}],
                "claims": {
                    name: {"display": [{"name": label, "locale": "en"}]}
                    for name, label in campus_id.DISPLAY_NAMES.items()
                },
            }
        },
    }


@router.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata() -> dict[str, Any]:
    base = _issuer_url()
    return {
        "issuer": base,
        "token_endpoint": f"{base}/api/v1/issuer/token",
        "grant_types_supported": [PRE_AUTH_GRANT],
        "pre-authorized_grant_anonymous_access_supported": True,
    }


@router.get("/.well-known/jwt-vc-issuer")
async def jwt_vc_issuer_metadata() -> dict[str, Any]:
    """Public keys a verifier uses to check Campus ID signatures."""
    return {"issuer": _issuer_url(), "jwks": issuer_key().jwks()}


# ---------------------------------------------------------------- offers (admin)


def _new_credential_id() -> str:
    return "CID-" + secrets.token_hex(6).upper()


def _offer_payload(code: str) -> dict[str, Any]:
    return {
        "credential_issuer": _issuer_url(),
        "credential_configuration_ids": [campus_id.CONFIGURATION_ID],
        "grants": {PRE_AUTH_GRANT: {"pre-authorized_code": code}},
    }


async def create_offer(session: AsyncSession, body: OfferCreate, actor: str) -> OfferOut:
    active = (
        await session.execute(
            select(CredentialRecord).where(
                CredentialRecord.roll_number == body.roll_number,
                CredentialRecord.revoked_at.is_(None),
            )
        )
    ).scalars().all()
    if active and not body.replace_existing:
        raise api_error(
            409,
            "ACTIVE_CREDENTIAL_EXISTS",
            f"Roll number {body.roll_number} already has an active Campus ID ({active[0].credential_id})",
        )
    now = utcnow()
    for old in active:
        old.revoked_at = now
        old.revocation_reason = "Replaced by a newly issued Campus ID"
        await record(session, actor, "revoke", old.credential_id, "replaced")

    credential_id = _new_credential_id()
    code = secrets.token_urlsafe(32)
    claims = body.model_dump(exclude={"replace_existing"}, exclude_none=True)
    claims["credential_id"] = credential_id

    session.add(
        CredentialRecord(
            credential_id=credential_id,
            roll_number=body.roll_number,
            expires_at=datetime.fromtimestamp(expiry_timestamp(body.valid_until), tz=timezone.utc),
        )
    )
    expires = now + OFFER_TTL
    session.add(
        CredentialOffer(
            pre_authorized_code=code,
            credential_id=credential_id,
            claims_json=json.dumps(claims),
            expires_at=expires,
        )
    )
    await record(session, actor, "issue_offer", credential_id, body.roll_number)

    offer = _offer_payload(code)
    return OfferOut(
        credential_id=credential_id,
        roll_number=body.roll_number,
        pre_authorized_code=code,
        credential_offer=offer,
        credential_offer_uri="openid-credential-offer://?credential_offer="
        + quote(json.dumps(offer, separators=(",", ":"))),
        expires_at=expires,
    )


@router.post("/api/v1/issuer/offers", response_model=OfferOut, status_code=201)
async def issue_offer(
    body: OfferCreate,
    user: dict = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    out = await create_offer(session, body, user["sub"])
    await session.commit()
    return out


@router.post("/api/v1/issuer/offers/bulk", response_model=list[BulkRowResult])
async def issue_offers_bulk(
    body: BulkOfferRequest,
    user: dict = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    """Issue one offer per row. Rows are independent: one bad row never blocks the others."""
    results: list[BulkRowResult] = []
    seen: set[str] = set()
    for i, raw in enumerate(body.rows, start=1):
        roll = str(raw.get("roll_number") or "").strip() or None
        try:
            if roll and roll in seen:
                raise ValueError("Duplicate roll number in this file")
            data = OfferCreate(**{**raw, "replace_existing": body.replace_existing})
            async with session.begin_nested():
                out = await create_offer(session, data, user["sub"])
            results.append(
                BulkRowResult(row=i, roll_number=data.roll_number, ok=True,
                              credential_id=out.credential_id, credential_offer_uri=out.credential_offer_uri)
            )
        except ValidationError as e:
            err = e.errors()[0]
            field = ".".join(str(x) for x in err["loc"])
            results.append(BulkRowResult(row=i, roll_number=roll, ok=False, error=f"{field}: {err['msg']}"))
        except HTTPException as e:
            results.append(BulkRowResult(row=i, roll_number=roll, ok=False, error=e.detail["error"]["message"]))
        except ValueError as e:
            results.append(BulkRowResult(row=i, roll_number=roll, ok=False, error=str(e)))
        if roll:
            seen.add(roll)
    await record(session, user["sub"], "bulk_issue", f"{sum(r.ok for r in results)}/{len(results)} rows")
    await session.commit()
    return results


@router.get("/api/v1/issuer/offers/{credential_id}", response_model=OfferStatus)
async def offer_status(
    credential_id: str,
    _: dict = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    offer = (
        await session.execute(select(CredentialOffer).where(CredentialOffer.credential_id == credential_id))
    ).scalar_one_or_none()
    if not offer:
        raise api_error(404, "NOT_FOUND", "No offer for this credential")
    return OfferStatus(
        credential_id=credential_id,
        redeemed=offer.redeemed,
        expired=aware(offer.expires_at) < utcnow(),
    )


# ---------------------------------------------------------------- OpenID4VCI (wallet-facing)


@router.post("/api/v1/issuer/token")
async def token(
    grant_type: str = Form(...),
    pre_authorized_code: str = Form(..., alias="pre-authorized_code"),
    session: AsyncSession = Depends(get_session),
):
    if grant_type != PRE_AUTH_GRANT:
        raise _vci_error(400, "unsupported_grant_type", "Only the pre-authorized code grant is supported")

    offer = await session.get(CredentialOffer, pre_authorized_code)
    if not offer or offer.access_token is not None or offer.redeemed:
        raise _vci_error(400, "invalid_grant", "Unknown or already used pre-authorized code")
    if aware(offer.expires_at) < utcnow():
        raise _vci_error(400, "invalid_grant", "Credential offer has expired")

    offer.access_token = secrets.token_urlsafe(32)
    offer.c_nonce = secrets.token_urlsafe(16)
    offer.expires_at = min(aware(offer.expires_at), utcnow() + TOKEN_TTL)
    await session.commit()
    return {
        "access_token": offer.access_token,
        "token_type": "Bearer",
        "expires_in": int(TOKEN_TTL.total_seconds()),
        "c_nonce": offer.c_nonce,
        "c_nonce_expires_in": int(TOKEN_TTL.total_seconds()),
    }


def _verify_proof(proof_jwt: str, expected_nonce: str) -> dict[str, Any]:
    """Check the holder's proof of possession and return the holder public JWK."""
    try:
        header = jwt.get_unverified_header(proof_jwt)
    except jwt.PyJWTError:
        raise _vci_error(400, "invalid_proof", "Proof is not a valid JWT")
    if header.get("typ") != "openid4vci-proof+jwt":
        raise _vci_error(400, "invalid_proof", "Proof typ must be openid4vci-proof+jwt")
    if header.get("alg") != "ES256":
        raise _vci_error(400, "invalid_proof", "Proof must be signed with ES256")
    holder_jwk = header.get("jwk")
    if not isinstance(holder_jwk, dict) or "d" in holder_jwk:
        raise _vci_error(400, "invalid_proof", "Proof header must carry the holder public jwk")
    try:
        key = jwt.PyJWK.from_dict({**holder_jwk, "alg": "ES256"}).key
        claims = jwt.decode(
            proof_jwt,
            key,
            algorithms=["ES256"],
            audience=_issuer_url(),
            options={"require": ["aud", "iat", "nonce"]},
        )
    except jwt.PyJWTError as e:
        raise _vci_error(400, "invalid_proof", f"Proof signature or claims invalid: {e}")
    if abs(time.time() - claims["iat"]) > PROOF_MAX_AGE:
        raise _vci_error(400, "invalid_proof", "Proof is too old or from the future")
    if not secrets.compare_digest(str(claims["nonce"]), expected_nonce):
        raise _vci_error(400, "invalid_nonce", "Proof nonce does not match c_nonce")
    return holder_jwk


@router.post("/api/v1/issuer/credential")
async def credential(
    body: dict,
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
):
    if not authorization or not authorization.startswith("Bearer "):
        raise _vci_error(401, "invalid_token", "Missing access token")
    offer = (
        await session.execute(select(CredentialOffer).where(CredentialOffer.access_token == authorization[7:]))
    ).scalar_one_or_none()
    if not offer or offer.redeemed or aware(offer.expires_at) < utcnow():
        raise _vci_error(401, "invalid_token", "Access token is invalid, expired or already used")

    requested = body.get("credential_configuration_id") or body.get("format")
    if requested not in (campus_id.CONFIGURATION_ID, campus_id.FORMAT):
        raise _vci_error(400, "unsupported_credential_type", "Only Campus ID (vc+sd-jwt) is offered")

    proof = body.get("proof") or {}
    if proof.get("proof_type") != "jwt" or not proof.get("jwt"):
        raise _vci_error(400, "invalid_proof", "A jwt proof of possession is required")
    holder_jwk = _verify_proof(proof["jwt"], offer.c_nonce or "")

    record_ = await session.get(CredentialRecord, offer.credential_id)
    if record_ is None or record_.revoked_at is not None:
        raise _vci_error(400, "credential_request_denied", "This Campus ID has been revoked")

    claims = json.loads(offer.claims_json or "{}")
    sd_jwt = build_sd_jwt(claims, holder_jwk)

    offer.redeemed = True
    offer.claims_json = None  # do not keep student data once delivered
    offer.c_nonce = None
    record_.issued_at = utcnow()
    await record(session, "wallet", "credential_delivered", offer.credential_id)
    await session.commit()

    return {"credentials": [{"credential": sd_jwt}], "credential": sd_jwt, "format": campus_id.FORMAT}
