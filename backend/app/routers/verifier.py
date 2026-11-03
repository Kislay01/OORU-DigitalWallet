"""OpenID4VP verifier: presentation requests, wallet responses and verification history."""

import json
import secrets
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import campus_id
from app.audit import record
from app.config import settings
from app.db import get_session
from app.deps import require_verifier
from app.errors import api_error
from app.models import CredentialRecord, PresentationRequest
from app.routers.revocation import credential_status
from app.sdjwt_verify import VerificationResult, verify_presentation
from app.timeutil import aware, utcnow

router = APIRouter(prefix="/api/v1/verifier", tags=["verifier"])

REQUEST_TTL = timedelta(minutes=5)
RESULT_RETENTION = timedelta(minutes=10)


def client_id() -> str:
    return f"{settings.public_base_url}/verifier"


def response_uri() -> str:
    return f"{settings.public_base_url}/api/v1/verifier/response"


# ---------------------------------------------------------------- schemas


class RequestCreate(BaseModel):
    requested_claims: list[str] = Field(min_length=1)
    purpose: str | None = Field(default=None, max_length=120)

    @field_validator("requested_claims")
    @classmethod
    def _known(cls, v: list[str]) -> list[str]:
        unknown = [c for c in v if c not in campus_id.DISCLOSABLE]
        if unknown:
            raise ValueError(f"unknown field(s): {', '.join(unknown)}")
        return list(dict.fromkeys(v))


class ManualVerify(BaseModel):
    request_id: str
    presentation: str = Field(min_length=10)


# ---------------------------------------------------------------- helpers


def dcql_query(claims: list[str]) -> dict[str, Any]:
    return {
        "credentials": [
            {
                "id": "campus_id",
                "format": campus_id.FORMAT,
                "meta": {"vct_values": [campus_id.VCT]},
                "claims": [{"path": [c]} for c in claims],
            }
        ]
    }


def request_object(req: PresentationRequest) -> dict[str, Any]:
    claims = json.loads(req.requested_claims)
    return {
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "client_id": client_id(),
        "response_uri": response_uri(),
        "nonce": req.nonce,
        "state": req.request_id,
        "dcql_query": dcql_query(claims),
        "client_metadata": {"client_name": "OORU Campus ID Verifier", "vp_formats": {campus_id.FORMAT: {"sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"]}}},
    }


def authorization_uri(req: PresentationRequest) -> str:
    obj = request_object(req)
    params = {
        "client_id": obj["client_id"],
        "response_type": obj["response_type"],
        "response_mode": obj["response_mode"],
        "response_uri": obj["response_uri"],
        "nonce": obj["nonce"],
        "state": obj["state"],
        "dcql_query": json.dumps(obj["dcql_query"], separators=(",", ":")),
    }
    return "openid4vp://authorize?" + urlencode(params)


async def _expire_if_stale(req: PresentationRequest) -> None:
    if req.status == "pending" and aware(req.expires_at) < utcnow():
        req.status = "expired"


def _public_result(req: PresentationRequest, include_claims: bool) -> dict[str, Any]:
    result = json.loads(req.result_json) if req.result_json else None
    if result and not include_claims:
        result = {k: v for k, v in result.items() if k != "claims"}
        result["fields_shared"] = sorted((json.loads(req.result_json).get("claims") or {}).keys())
    return {
        "request_id": req.request_id,
        "status": req.status,
        "requested_claims": json.loads(req.requested_claims),
        "created_by": req.created_by,
        "created_at": req.created_at,
        "expires_at": req.expires_at,
        "result": result,
    }


async def _finish(session: AsyncSession, req: PresentationRequest, presentation: str, actor: str) -> dict[str, Any]:
    """Verify a presentation against a pending request. The request is consumed either way."""
    await _expire_if_stale(req)
    if req.status != "pending":
        raise api_error(409, "REQUEST_NOT_PENDING", f"This request is already {req.status}")

    result: VerificationResult = verify_presentation(
        presentation,
        nonce=req.nonce,
        audience=client_id(),
        required_claims=json.loads(req.requested_claims),
    )

    if result.credential_id and result.status in ("valid", "expired"):
        status = credential_status(await session.get(CredentialRecord, result.credential_id))
        if status == "revoked":
            result.add("revocation", False, "credential has been revoked by the issuer")
            result.status = "revoked"
            result.claims = {}
        elif status == "unknown":
            result.add("revocation", False, "issuer has no record of this credential")
            result.status = "invalid"
            result.claims = {}
        elif result.status == "valid":
            result.add("revocation", True, "not revoked")

    req.status = "verified" if result.status == "valid" else "failed"
    req.result_json = json.dumps(result.as_dict(), default=str)
    await record(session, actor, f"verify_{result.status}", req.request_id, result.credential_id)
    await session.commit()
    return result.as_dict()


# ---------------------------------------------------------------- verifier-facing


@router.post("/requests", status_code=201)
async def create_request(
    body: RequestCreate,
    user: dict = Depends(require_verifier),
    session: AsyncSession = Depends(get_session),
):
    req = PresentationRequest(
        request_id="REQ-" + secrets.token_hex(6).upper(),
        nonce=secrets.token_urlsafe(24),
        requested_claims=json.dumps(body.requested_claims),
        created_by=user["sub"],
        expires_at=utcnow() + REQUEST_TTL,
    )
    session.add(req)
    await record(session, user["sub"], "presentation_request", req.request_id, ",".join(body.requested_claims))
    await session.commit()
    return {
        "request_id": req.request_id,
        "nonce": req.nonce,
        "client_id": client_id(),
        "expires_at": req.expires_at,
        "authorization_request_uri": authorization_uri(req),
        "request_object": request_object(req),
    }


@router.get("/requests/{request_id}")
async def get_request(
    request_id: str,
    _: dict = Depends(require_verifier),
    session: AsyncSession = Depends(get_session),
):
    req = await session.get(PresentationRequest, request_id)
    if not req:
        raise api_error(404, "NOT_FOUND", "Unknown request")
    await _expire_if_stale(req)
    fresh = req.status in ("verified", "failed") and utcnow() - aware(req.created_at) < RESULT_RETENTION
    await session.commit()
    return _public_result(req, include_claims=fresh)


@router.post("/verify")
async def verify_manual(
    body: ManualVerify,
    user: dict = Depends(require_verifier),
    session: AsyncSession = Depends(get_session),
):
    """Verify a presentation pasted into the portal (fallback when the wallet can't post directly)."""
    req = await session.get(PresentationRequest, body.request_id)
    if not req:
        raise api_error(404, "NOT_FOUND", "Unknown request")
    return await _finish(session, req, body.presentation, user["sub"])


@router.get("/history")
async def history(
    q: str | None = None,
    status: str | None = Query(default=None, pattern="^(pending|verified|failed|expired)$"),
    limit: int = Query(default=100, ge=1, le=500),
    _: dict = Depends(require_verifier),
    session: AsyncSession = Depends(get_session),
):
    """Recent checks. Shows which fields were shared, never their values."""
    stmt = select(PresentationRequest).order_by(PresentationRequest.created_at.desc()).limit(limit)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(PresentationRequest.request_id.ilike(like), PresentationRequest.result_json.ilike(f'%"credential_id": "{q.strip()}%')))
    rows = (await session.execute(stmt)).scalars().all()
    for r in rows:
        await _expire_if_stale(r)
    await session.commit()
    out = [_public_result(r, include_claims=False) for r in rows]
    if status:
        out = [r for r in out if r["status"] == status]
    return out


@router.get("/summary")
async def summary(_: dict = Depends(require_verifier), session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(select(PresentationRequest))).scalars().all()
    counts = {"total": len(rows), "verified": 0, "failed": 0, "pending": 0, "expired": 0}
    for r in rows:
        await _expire_if_stale(r)
        counts[r.status] += 1
    await session.commit()
    return counts


# ---------------------------------------------------------------- wallet-facing


@router.get("/requests/{request_id}/object")
async def get_request_object(request_id: str, session: AsyncSession = Depends(get_session)):
    """Request object for wallets that resolve `request_uri` instead of reading query parameters."""
    req = await session.get(PresentationRequest, request_id)
    if not req:
        raise api_error(404, "NOT_FOUND", "Unknown request")
    await _expire_if_stale(req)
    await session.commit()
    if req.status != "pending":
        raise api_error(410, "REQUEST_CLOSED", f"This request is {req.status}")
    return request_object(req)


@router.post("/response")
async def wallet_response(request: Request, session: AsyncSession = Depends(get_session)):
    """OpenID4VP direct_post endpoint. Accepts form-encoded or JSON `vp_token` + `state`."""
    if request.headers.get("content-type", "").startswith("application/json"):
        data = await request.json()
    else:
        data = dict(await request.form())

    state, vp_token = data.get("state"), data.get("vp_token")
    if isinstance(vp_token, str) and vp_token.startswith("{"):
        try:
            vp_token = json.loads(vp_token)
        except json.JSONDecodeError:
            pass
    if isinstance(vp_token, dict):  # DCQL response: {"campus_id": ["<sd-jwt>"]} or {"campus_id": "<sd-jwt>"}
        vp_token = vp_token.get("campus_id")
        if isinstance(vp_token, list):
            vp_token = vp_token[0] if vp_token else None
    if not state or not isinstance(vp_token, str):
        raise api_error(400, "INVALID_REQUEST", "state and vp_token are required")

    req = await session.get(PresentationRequest, str(state))
    if not req:
        raise api_error(400, "INVALID_REQUEST", "Unknown state")
    result = await _finish(session, req, vp_token, "wallet")
    return {"status": result["status"], "request_id": req.request_id}
