from fastapi import Depends, Header

from app.errors import api_error
from app.security import decode_token


def current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise api_error(401, "UNAUTHENTICATED", "Missing bearer token")
    data = decode_token(authorization[7:])
    if not data:
        raise api_error(401, "INVALID_TOKEN", "Invalid or expired token")
    return data


def require_admin(user: dict = Depends(current_user)) -> dict:
    if user["role"] != "admin":
        raise api_error(403, "FORBIDDEN", "Admin role required")
    return user


def require_verifier(user: dict = Depends(current_user)) -> dict:
    if user["role"] not in ("admin", "verifier"):
        raise api_error(403, "FORBIDDEN", "Verifier role required")
    return user
