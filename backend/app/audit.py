from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog


async def record(session: AsyncSession, actor: str, action: str, target: str, detail: str | None = None) -> None:
    """Append an audit entry. Never pass credential contents as detail."""
    session.add(AuditLog(actor=actor, action=action, target=target, detail=detail))
