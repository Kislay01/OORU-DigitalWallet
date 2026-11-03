import re
from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app import campus_id

_MAX_PHOTO_B64 = 300_000


class StudentClaims(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    roll_number: str = Field(min_length=1, max_length=64)
    branch: str = Field(min_length=1, max_length=128)
    enrollment_status: str = "active"
    valid_until: str
    photo: str | None = None

    @field_validator("name", "roll_number", "branch")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be blank")
        return v

    @field_validator("roll_number")
    @classmethod
    def _roll(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9\-/_.]+", v):
            raise ValueError("only letters, digits and - / _ . are allowed")
        return v

    @field_validator("enrollment_status")
    @classmethod
    def _status(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in campus_id.ENROLLMENT_STATUSES:
            raise ValueError(f"must be one of {', '.join(campus_id.ENROLLMENT_STATUSES)}")
        return v

    @field_validator("valid_until")
    @classmethod
    def _valid_until(cls, v: str) -> str:
        d = date.fromisoformat(v.strip())
        if d <= date.today():
            raise ValueError("must be a future date")
        return d.isoformat()

    @field_validator("photo")
    @classmethod
    def _photo(cls, v: str | None) -> str | None:
        if v and len(v) > _MAX_PHOTO_B64:
            raise ValueError("photo is too large (max ~200 KB)")
        return v or None


class OfferCreate(StudentClaims):
    replace_existing: bool = False


class OfferOut(BaseModel):
    credential_id: str
    roll_number: str
    pre_authorized_code: str
    credential_offer: dict
    credential_offer_uri: str
    expires_at: datetime


class OfferStatus(BaseModel):
    credential_id: str
    redeemed: bool
    expired: bool


class CredentialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    credential_id: str
    roll_number: str
    issued_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    revocation_reason: str | None


class RevokeRequest(BaseModel):
    reason: str = Field(default="Revoked by issuer", max_length=256)


class StatusOut(BaseModel):
    credential_id: str
    status: str  # active | revoked | expired | unknown
    revoked_at: datetime | None = None


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    at: datetime
    actor: str
    action: str
    target: str
    detail: str | None


class BulkOfferRequest(BaseModel):
    rows: list[dict] = Field(min_length=1, max_length=500)
    replace_existing: bool = False


class BulkRowResult(BaseModel):
    row: int
    roll_number: str | None
    ok: bool
    credential_id: str | None = None
    credential_offer_uri: str | None = None
    error: str | None = None
