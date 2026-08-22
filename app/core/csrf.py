"""
Protection CSRF centralisee pour les formulaires POST.

Le token est conserve dans la session signee. Les routes metier restent
inchangees : la validation est appliquee au niveau middleware.
"""
from __future__ import annotations

import html
import secrets
from urllib.parse import parse_qs

from fastapi import HTTPException, Request


CSRF_SESSION_KEY = "_csrf_token"
CSRF_FORM_FIELD = "_csrf_token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def ensure_csrf_token(request: Request) -> str:
    token = request.session.get(CSRF_SESSION_KEY)
    if not token:
        token = generate_csrf_token()
        request.session[CSRF_SESSION_KEY] = token
    return token


def rotate_csrf_token(request: Request) -> str:
    token = generate_csrf_token()
    request.session[CSRF_SESSION_KEY] = token
    return token


def csrf_input(request: Request) -> str:
    token = ensure_csrf_token(request)
    escaped = html.escape(token, quote=True)
    return f'<input type="hidden" name="{CSRF_FORM_FIELD}" value="{escaped}" />'


async def validate_csrf_request(request: Request) -> None:
    if request.method.upper() in SAFE_METHODS:
        return

    expected_token = request.session.get(CSRF_SESSION_KEY)
    if not expected_token:
        return

    body = await request.body()
    submitted_token = request.headers.get("x-csrf-token") or extract_form_token(
        body,
        request.headers.get("content-type", ""),
    )
    restore_request_body(request, body)

    if not submitted_token or not secrets.compare_digest(
        submitted_token,
        expected_token,
    ):
        raise HTTPException(status_code=403, detail="Jeton CSRF invalide.")


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def extract_form_token(body: bytes, content_type: str) -> str | None:
    if not content_type.lower().startswith("application/x-www-form-urlencoded"):
        return None

    parsed = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    values = parsed.get(CSRF_FORM_FIELD)
    if not values:
        return None
    return values[0]


def restore_request_body(request: Request, body: bytes) -> None:
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    request._receive = receive  # type: ignore[attr-defined]
