from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import record
from app.db import get_session
from app.deps import current_user
from app.errors import api_error
from app.models import Account
from app.security import clear_failed_logins, create_token, login_allowed, record_failed_login, verify_password

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, session: AsyncSession = Depends(get_session)):
    key = f"{request.client.host if request.client else '-'}:{body.username}"
    if not login_allowed(key):
        raise api_error(429, "TOO_MANY_ATTEMPTS", "Too many failed attempts, try again later")

    account = (await session.execute(select(Account).where(Account.username == body.username))).scalar_one_or_none()
    if not account or not verify_password(body.password, account.password_hash):
        record_failed_login(key)
        raise api_error(401, "INVALID_CREDENTIALS", "Wrong username or password")

    clear_failed_logins(key)
    await record(session, account.username, "login", account.role)
    await session.commit()
    return TokenResponse(access_token=create_token(account.username, account.role), role=account.role)


@router.get("/me")
async def me(user: dict = Depends(current_user)):
    return {"username": user["sub"], "role": user["role"]}
