from __future__ import annotations

from contextlib import asynccontextmanager

import redis
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api import router
from app.audit import append_event
from app.config import settings
from app.database import Base, SessionLocal, engine
from app.models import User, UserRole
from app.security import hash_password


def bootstrap() -> None:
    settings.validate_production_secrets()
    settings.ensure_directories()
    Base.metadata.create_all(bind=engine)
    if settings.bootstrap_admin_username and settings.bootstrap_admin_password:
        db = SessionLocal()
        try:
            exists = db.query(User).filter(User.username == settings.bootstrap_admin_username.lower()).first()
            if not exists:
                admin = User(
                    username=settings.bootstrap_admin_username.lower(),
                    full_name=settings.bootstrap_admin_full_name,
                    password_hash=hash_password(settings.bootstrap_admin_password),
                    role=UserRole.ADMIN,
                )
                db.add(admin)
                db.flush()
                append_event(
                    db,
                    actor_id=admin.id,
                    action="system.admin_bootstrapped",
                    target_type="user",
                    target_id=admin.id,
                    payload={"username": admin.username},
                )
                db.commit()
        finally:
            db.close()


@asynccontextmanager
async def lifespan(_: FastAPI):
    bootstrap()
    yield


app = FastAPI(
    title="MICEPP Scanner API",
    version="1.0.0",
    docs_url="/api/docs" if settings.environment != "production" else None,
    openapi_url="/api/openapi.json" if settings.environment != "production" else None,
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in settings.allowed_origins.split(",") if origin.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(router, prefix=settings.api_prefix)


@app.get("/health/live")
def live() -> dict:
    return {"status": "ok", "service": "micepp-api"}


@app.get("/health/ready")
def ready(response: Response) -> dict:
    checks: dict[str, str] = {}
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error:{type(exc).__name__}"
    try:
        redis.from_url(settings.redis_url, socket_connect_timeout=2).ping()
        checks["redis"] = "ok"
    except Exception as exc:
        checks["redis"] = f"error:{type(exc).__name__}"
    status_value = "ok" if all(value == "ok" for value in checks.values()) else "degraded"
    if status_value != "ok":
        response.status_code = 503
    return {"status": status_value, "checks": checks, "cape_configured": bool(settings.cape_base_url)}
