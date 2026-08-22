"""
Service d'envoi email SMTP.

Phase 6.2.3: canal email controle, sans provider externe et sans scheduler.
"""
from __future__ import annotations

import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr

from app.core.config import settings


class EmailDeliveryError(RuntimeError):
    """Erreur controlee lors de la preparation ou de l'envoi SMTP."""


@dataclass(frozen=True)
class EmailDeliveryResult:
    attempted: bool
    sent: bool
    reason: str = ""


class EmailService:
    def __init__(self, smtp_settings=settings):
        self.settings = smtp_settings

    def send_email(
        self,
        *,
        to_email: str | None,
        subject: str,
        body: str,
    ) -> EmailDeliveryResult:
        if not self.settings.SMTP_ENABLED:
            return EmailDeliveryResult(
                attempted=False,
                sent=False,
                reason="SMTP disabled",
            )

        self._validate_settings(to_email)
        message = self._build_message(
            to_email=to_email or "",
            subject=subject,
            body=body,
        )

        try:
            with smtplib.SMTP(
                self.settings.SMTP_HOST,
                self.settings.SMTP_PORT,
                timeout=self.settings.SMTP_TIMEOUT,
            ) as smtp:
                if self.settings.SMTP_USE_TLS:
                    smtp.starttls()
                if self.settings.SMTP_USERNAME and self.settings.SMTP_PASSWORD:
                    smtp.login(
                        self.settings.SMTP_USERNAME,
                        self.settings.SMTP_PASSWORD,
                    )
                smtp.send_message(message)
        except Exception as exc:
            raise EmailDeliveryError(safe_error(exc)) from exc

        return EmailDeliveryResult(attempted=True, sent=True, reason="SENT")

    def _validate_settings(self, to_email: str | None) -> None:
        if not self.settings.SMTP_HOST:
            raise EmailDeliveryError("SMTP host missing")
        if not self.settings.SMTP_FROM_EMAIL:
            raise EmailDeliveryError("SMTP sender missing")
        if not to_email:
            raise EmailDeliveryError("SMTP recipient missing")

    def _build_message(
        self,
        *,
        to_email: str,
        subject: str,
        body: str,
    ) -> EmailMessage:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = formataddr(
            (self.settings.SMTP_FROM_NAME, self.settings.SMTP_FROM_EMAIL)
        )
        message["To"] = to_email
        message.set_content(body)
        return message


def safe_error(exc: Exception) -> str:
    text = f"{exc.__class__.__name__}: {exc}"
    password = getattr(settings, "SMTP_PASSWORD", "")
    if password:
        text = text.replace(password, "***")
    return text[:240]
