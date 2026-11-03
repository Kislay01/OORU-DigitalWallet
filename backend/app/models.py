"""Shared data model.

Credential contents (name, branch, photo...) are never stored here. The backend
keeps only what it needs to issue, revoke and audit.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(16))  # admin | verifier


class CredentialRecord(Base):
    """One row per issued Campus ID. Metadata only."""

    __tablename__ = "credential_records"

    credential_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    roll_number: Mapped[str] = mapped_column(String(64), index=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)


class CredentialOffer(Base):
    """OpenID4VCI pre-authorized code offer. Claims are held only until redeemed."""

    __tablename__ = "credential_offers"

    pre_authorized_code: Mapped[str] = mapped_column(String(128), primary_key=True)
    credential_id: Mapped[str] = mapped_column(String(64), index=True)
    claims_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    access_token: Mapped[str | None] = mapped_column(String(128), unique=True, nullable=True)
    c_nonce: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    redeemed: Mapped[bool] = mapped_column(Boolean, default=False)


class PresentationRequest(Base):
    """OpenID4VP request created by a verifier. Single-use."""

    __tablename__ = "presentation_requests"

    request_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(128), unique=True)
    requested_claims: Mapped[str] = mapped_column(Text)  # JSON list
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | verified | failed | expired
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(32))
    target: Mapped[str] = mapped_column(String(128))
    detail: Mapped[str | None] = mapped_column(String(256), nullable=True)
