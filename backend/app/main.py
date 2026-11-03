import importlib
import pkgutil
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

import app.routers as routers_pkg
from app.config import settings
from app.db import Base, SessionLocal, engine
from app.models import Account
from app.security import hash_password


async def seed() -> None:
    async with SessionLocal() as session:
        for username, password, role in (
            (settings.seed_admin_username, settings.seed_admin_password, "admin"),
            (settings.seed_verifier_username, settings.seed_verifier_password, "verifier"),
        ):
            exists = (await session.execute(select(Account).where(Account.username == username))).scalar_one_or_none()
            if not exists:
                session.add(Account(username=username, password_hash=hash_password(password), role=role))
        await session.commit()


@asynccontextmanager
async def lifespan(_: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await seed()
    yield


app = FastAPI(title="OORU Campus ID", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _register_routers() -> list[str]:
    loaded = []
    for info in sorted(pkgutil.iter_modules(routers_pkg.__path__), key=lambda m: m.name):
        module = importlib.import_module(f"{routers_pkg.__name__}.{info.name}")
        router = getattr(module, "router", None)
        if router is not None:
            app.include_router(router)
            loaded.append(info.name)
    return loaded


def _portals_dir() -> Path | None:
    candidates = [settings.portals_dir, Path(__file__).resolve().parents[2] / "portals", "/portals"]
    for c in candidates:
        if c and Path(c).is_dir():
            return Path(c)
    return None


def _mount_portals() -> list[str]:
    root = _portals_dir()
    if root is None:
        return []
    mounted = []
    for portal in sorted(p for p in root.iterdir() if p.is_dir() and (p / "index.html").is_file()):
        app.mount(f"/{portal.name}", StaticFiles(directory=portal, html=True), name=f"portal-{portal.name}")
        mounted.append(portal.name)
    return mounted


LOADED_ROUTERS = _register_routers()
MOUNTED_PORTALS = _mount_portals()
