"""
Point d'entrée de l'application FastAPI.

Assemble : middleware de session (authentification), fichiers statiques,
routeurs (auth, dashboard), et le handler qui transforme une tentative
d'accès non authentifiée en redirection propre vers /login.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.core.config import settings
from app.core.csrf import validate_csrf_request
from app.core.deps import RedirectToLogin
from app.db.database import create_database_tables, get_safe_database_url
from app.routers import (
    alerts,
    assets,
    auth,
    bulletins,
    correlations,
    dashboard,
    notifications,
    siem,
    settings as settings_router,
    synchronizations,
    threat_sources,
    treatments,
    users,
    vulnerabilities,
)
from app.services.scheduler_service import start_scheduler, stop_scheduler

# Crée les tables si elles n'existent pas encore (pratique pour la démo ;
# les prochaines phases pourront basculer entièrement sur Alembic).
try:
    create_database_tables()
except Exception:
    raise RuntimeError(
        "Initialisation PostgreSQL impossible pour ThreatWatch. "
        f"DATABASE_URL={get_safe_database_url()}. "
        "Verifiez le mot de passe dans .env, le port 5432, le service PostgreSQL "
        "et l'existence de la base threatwatch."
    ) from None


@asynccontextmanager
async def lifespan(app: FastAPI):
    start_scheduler()
    try:
        yield
    finally:
        stop_scheduler()


app = FastAPI(title=settings.APP_NAME, lifespan=lifespan)


@app.middleware("http")
async def csrf_protection(request: Request, call_next):
    try:
        await validate_csrf_request(request)
    except HTTPException as exc:
        return PlainTextResponse(str(exc.detail), status_code=exc.status_code)
    return await call_next(request)

# --- Session sécurisée (cookie signé côté serveur via SESSION_SECRET_KEY) ---
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SESSION_SECRET_KEY,
    session_cookie=settings.SESSION_COOKIE_NAME,
    max_age=settings.SESSION_MAX_AGE,
    https_only=settings.SESSION_HTTPS_ONLY,
    same_site="lax",
)

# --- Fichiers statiques (CSS/JS) ---
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok", "service": settings.APP_NAME}


@app.exception_handler(RedirectToLogin)
def handle_redirect_to_login(request: Request, exc: RedirectToLogin):
    url = "/login"
    if exc.next_url:
        url = f"/login?next={exc.next_url}"
    return RedirectResponse(url=url, status_code=303)


# --- Routeurs ---
app.include_router(auth.router)
app.include_router(alerts.router)
app.include_router(assets.router)
app.include_router(bulletins.router)
app.include_router(correlations.router)
app.include_router(dashboard.router)
app.include_router(notifications.router)
app.include_router(siem.router)
app.include_router(settings_router.router)
app.include_router(synchronizations.router)
app.include_router(threat_sources.router)
app.include_router(treatments.router)
app.include_router(users.router)
app.include_router(vulnerabilities.router)
