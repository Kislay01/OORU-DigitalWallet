"""Credential registry, revocation, public status check and audit log."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import record
from app.db import get_session
from app.deps import require_admin
from app.errors import api_error
from app.issuer_schemas import AuditOut, CredentialOut, RevokeRequest, StatusOut
from app.models import AuditLog, CredentialRecord
from app.timeutil import aware, utcnow

router = APIRouter(tags=["revocation"])


def credential_status(rec: CredentialRecord | None) -> str:
    if rec is None:
        return "unknown"
    if rec.revoked_at is not None:
        return "revoked"
    if rec.expires_at is not None and aware(rec.expires_at) < utcnow():
        return "expired"
    return "active"


@router.get("/api/v1/credentials", response_model=list[CredentialOut])
async def list_credentials(
    q: str | None = Query(default=None, description="Search credential ID or roll number"),
    status: str | None = Query(default=None, pattern="^(active|revoked|expired)$"),
    limit: int = Query(default=200, ge=1, le=1000),
    _: dict = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    stmt = select(CredentialRecord).order_by(CredentialRecord.issued_at.desc())
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(CredentialRecord.credential_id.ilike(like), CredentialRecord.roll_number.ilike(like)))
    rows = (await session.execute(stmt)).scalars().all()
    if status:
        rows = [r for r in rows if credential_status(r) == status]
    return rows[:limit]


@router.get("/api/v1/credentials/summary")
async def summary(_: dict = Depends(require_admin), session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(select(CredentialRecord))).scalars().all()
    counts = {"total": len(rows), "active": 0, "revoked": 0, "expired": 0}
    for r in rows:
        counts[credential_status(r)] += 1
    return counts


@router.get("/api/v1/credentials/{credential_id}", response_model=CredentialOut)
async def get_credential(
    credential_id: str,
    _: dict = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    rec = await session.get(CredentialRecord, credential_id)
    if not rec:
        raise api_error(404, "NOT_FOUND", "Unknown credential")
    return rec


@router.post("/api/v1/credentials/{credential_id}/revoke", response_model=CredentialOut)
async def revoke(
    credential_id: str,
    body: RevokeRequest | None = None,
    user: dict = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    rec = await session.get(CredentialRecord, credential_id)
    if not rec:
        raise api_error(404, "NOT_FOUND", "Unknown credential")
    if rec.revoked_at is not None:
        raise api_error(409, "ALREADY_REVOKED", "Credential is already revoked")
    rec.revoked_at = utcnow()
    rec.revocation_reason = (body.reason if body else None) or "Revoked by issuer"
    await record(session, user["sub"], "revoke", credential_id, rec.revocation_reason[:256])
    await session.commit()
    await session.refresh(rec)
    return rec


@router.get("/api/v1/status/{credential_id}", response_model=StatusOut)
async def public_status(credential_id: str, session: AsyncSession = Depends(get_session)):
    """Public revocation check referenced from the credential's `status.url` claim.

    Reveals only the status of an ID the caller already holds; no student data.
    """
    rec = await session.get(CredentialRecord, credential_id)
    return StatusOut(
        credential_id=credential_id,
        status=credential_status(rec),
        revoked_at=rec.revoked_at if rec else None,
    )


@router.get("/api/v1/revocations", response_model=list[str])
async def revoked_ids(session: AsyncSession = Depends(get_session)):
    """Public list of revoked credential IDs, for verifiers that cache revocation state."""
    rows = await session.execute(
        select(CredentialRecord.credential_id).where(CredentialRecord.revoked_at.is_not(None))
    )
    return sorted(rows.scalars().all())


@router.get("/api/v1/audit", response_model=list[AuditOut])
async def audit_log(
    action: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    _: dict = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    return (await session.execute(stmt)).scalars().all()
