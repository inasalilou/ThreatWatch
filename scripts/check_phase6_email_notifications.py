"""
Verification locale de la phase 6.2.3.

Controle les notifications EMAIL sans envoyer de vrai email. Les envois SMTP
sont simules ou desactives, puis toute donnee de test est annulee.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.core.config import settings  # noqa: E402
from app.db.database import SessionLocal, get_safe_database_url, test_database_connection  # noqa: E402
from app.models.alert import Alert, AlertPriority, AlertSeverity, AlertStatus  # noqa: E402
from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType  # noqa: E402
from app.models.asset_vulnerability_correlation import (  # noqa: E402
    AssetVulnerabilityCorrelation,
    CorrelationPersistenceStatus,
)
from app.models.notification import (  # noqa: E402
    Notification,
    NotificationChannel,
    NotificationStatus,
)
from app.models.vulnerability import EnrichmentStatus, Vulnerability  # noqa: E402
from app.services import email_service as email_module  # noqa: E402
from app.services.email_service import EmailDeliveryError, EmailDeliveryResult, EmailService, safe_error  # noqa: E402
from app.services.notification_service import (  # noqa: E402
    create_email_notification_from_alert,
    create_notifications_from_alert,
)


def main() -> int:
    print(
        "Verification phase 6.2.3 notifications email avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        with SessionLocal() as db:
            initial_count = count_notifications(db)
            checks = [
                check_smtp_disabled_no_network(),
                check_high_critical_create_email(db),
                check_low_medium_create_no_email(db),
                check_email_dedup(db),
                check_mock_success_sent(db),
                check_mock_error_failed(db),
                check_secret_is_masked(),
                check_in_app_still_works(db),
            ]
            db.rollback()

        with SessionLocal() as verification_db:
            if count_notifications(verification_db) != initial_count:
                print("Rollback final email notifications: FAILED")
                return 1

        if not all(checks):
            return 1

        print("Rollback final email notifications: OK")
        print("PHASE 6.2.3 EMAIL NOTIFICATIONS CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR SQLAlchemy: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def check_smtp_disabled_no_network() -> bool:
    original_enabled = settings.SMTP_ENABLED
    original_smtp = email_module.smtplib.SMTP
    settings.SMTP_ENABLED = False

    def forbidden_smtp(*args, **kwargs):
        raise RuntimeError("SMTP network call should not happen")

    email_module.smtplib.SMTP = forbidden_smtp
    try:
        result = EmailService().send_email(
            to_email="soc@example.test",
            subject="TEST",
            body="TEST",
        )
    finally:
        email_module.smtplib.SMTP = original_smtp
        settings.SMTP_ENABLED = original_enabled

    if result.attempted or result.sent:
        print("SMTP disabled -> aucun appel reseau: FAILED")
        return False

    print("SMTP disabled -> aucun appel reseau: OK")
    return True


def check_high_critical_create_email(db) -> bool:
    high_alert = create_test_alert(db, "HIGH", AlertPriority.HIGH)
    critical_alert = create_test_alert(db, "CRITICAL", AlertPriority.CRITICAL)
    high_notification = create_email_notification_from_alert(
        db,
        high_alert,
        email_service=DisabledEmailService(),
    )
    critical_notification = create_email_notification_from_alert(
        db,
        critical_alert,
        email_service=DisabledEmailService(),
    )

    if (
        high_notification is None
        or critical_notification is None
        or high_notification.channel != NotificationChannel.EMAIL
        or critical_notification.channel != NotificationChannel.EMAIL
        or high_notification.status != NotificationStatus.PENDING
        or critical_notification.status != NotificationStatus.PENDING
    ):
        print("HIGH/CRITICAL -> notification EMAIL: FAILED")
        return False

    print("HIGH/CRITICAL -> notification EMAIL: OK")
    return True


def check_low_medium_create_no_email(db) -> bool:
    low_alert = create_test_alert(db, "LOW", AlertPriority.LOW)
    medium_alert = create_test_alert(db, "MEDIUM", AlertPriority.MEDIUM)
    low_notification = create_email_notification_from_alert(
        db,
        low_alert,
        email_service=SuccessEmailService(),
    )
    medium_notification = create_email_notification_from_alert(
        db,
        medium_alert,
        email_service=SuccessEmailService(),
    )

    if low_notification is not None or medium_notification is not None:
        print("LOW/MEDIUM -> pas d'email: FAILED")
        return False

    print("LOW/MEDIUM -> pas d'email: OK")
    return True


def check_email_dedup(db) -> bool:
    alert = create_test_alert(db, "DEDUP", AlertPriority.CRITICAL)
    first = create_email_notification_from_alert(
        db,
        alert,
        email_service=SuccessEmailService(),
    )
    second = create_email_notification_from_alert(
        db,
        alert,
        email_service=SuccessEmailService(),
    )

    if (
        first is None
        or second is None
        or first.id != second.id
        or count_notifications_for_alert(db, alert.id, NotificationChannel.EMAIL) != 1
    ):
        print("Anti-doublon EMAIL: FAILED")
        return False

    print("Anti-doublon EMAIL: OK")
    return True


def check_mock_success_sent(db) -> bool:
    alert = create_test_alert(db, "SENT", AlertPriority.CRITICAL)
    notification = create_email_notification_from_alert(
        db,
        alert,
        email_service=SuccessEmailService(),
    )

    if (
        notification is None
        or notification.status != NotificationStatus.SENT
        or notification.sent_at is None
        or "[ThreatWatch]" not in notification.title
        or alert.id not in notification.message
    ):
        print("Mock succes -> SENT: FAILED")
        return False

    print("Mock succes -> SENT: OK")
    return True


def check_mock_error_failed(db) -> bool:
    alert = create_test_alert(db, "FAILED", AlertPriority.HIGH)
    notification = create_email_notification_from_alert(
        db,
        alert,
        email_service=FailingEmailService(),
    )

    if (
        notification is None
        or notification.status != NotificationStatus.FAILED
        or notification.sent_at is not None
    ):
        print("Mock erreur -> FAILED: FAILED")
        return False

    print("Mock erreur -> FAILED: OK")
    return True


def check_secret_is_masked() -> bool:
    original_password = settings.SMTP_PASSWORD
    settings.SMTP_PASSWORD = "SUPER-SECRET-PASSWORD"
    try:
        masked = safe_error(RuntimeError("failure SUPER-SECRET-PASSWORD"))
    finally:
        settings.SMTP_PASSWORD = original_password

    if "SUPER-SECRET-PASSWORD" in masked:
        print("Secret SMTP jamais affiche: FAILED")
        return False

    print("Secret SMTP jamais affiche: OK")
    return True


def check_in_app_still_works(db) -> bool:
    alert = create_test_alert(db, "INAPP", AlertPriority.CRITICAL)
    in_app, email = create_notifications_from_alert(
        db,
        alert,
        email_service=DisabledEmailService(),
    )

    if (
        in_app is None
        or email is None
        or in_app.channel != NotificationChannel.IN_APP
        or in_app.status != NotificationStatus.SENT
        or email.channel != NotificationChannel.EMAIL
    ):
        print("IN_APP reste fonctionnel: FAILED")
        return False

    print("IN_APP reste fonctionnel: OK")
    return True


class DisabledEmailService:
    settings = SimpleNamespace(SOC_NOTIFICATION_EMAIL="soc@example.test")

    def send_email(self, *, to_email: str | None, subject: str, body: str):
        return EmailDeliveryResult(attempted=False, sent=False, reason="disabled")


class SuccessEmailService:
    settings = SimpleNamespace(SOC_NOTIFICATION_EMAIL="soc@example.test")

    def send_email(self, *, to_email: str | None, subject: str, body: str):
        if not to_email or "[ThreatWatch]" not in subject or "CVE-" not in body:
            raise EmailDeliveryError("Email content invalid")
        return EmailDeliveryResult(attempted=True, sent=True, reason="sent")


class FailingEmailService:
    settings = SimpleNamespace(SOC_NOTIFICATION_EMAIL="soc@example.test")

    def send_email(self, *, to_email: str | None, subject: str, body: str):
        raise EmailDeliveryError("SMTP failure")


def create_test_alert(
    db,
    suffix: str,
    priority: AlertPriority,
) -> Alert:
    token = uuid4().hex[:8].upper()
    now = utcnow_naive()
    asset = Asset(
        name=f"TEST-EMAIL-{suffix}-{token}",
        asset_type=AssetType.APPLICATION,
        vendor="EmailVendor",
        product="EmailProduct",
        product_version="1.0.0",
        criticality=AssetCriticality.CRITICAL,
        environment=AssetEnvironment.PRODUCTION,
        is_active=True,
    )
    vulnerability = Vulnerability(
        cve_id=f"CVE-2100-{token[:4]}",
        description="Vulnerabilite temporaire de test email.",
        cvss_score=Decimal("9.8"),
        cvss_severity="CRITICAL",
        enrichment_status=EnrichmentStatus.SUCCESS,
    )
    db.add_all([asset, vulnerability])
    db.flush()

    correlation = AssetVulnerabilityCorrelation(
        asset_id=asset.id,
        vulnerability_id=vulnerability.id,
        status=CorrelationPersistenceStatus.MATCH,
        reason="Correlation MATCH de test email.",
        first_detected_at=now,
        last_evaluated_at=now,
        is_active=True,
    )
    db.add(correlation)
    db.flush()

    alert = Alert(
        correlation_id=correlation.id,
        asset_id=asset.id,
        vulnerability_id=vulnerability.id,
        title=f"TEST-EMAIL-{suffix}-{vulnerability.cve_id}",
        description="Alerte temporaire de test email.",
        severity=AlertSeverity.CRITICAL
        if priority in {AlertPriority.HIGH, AlertPriority.CRITICAL}
        else AlertSeverity.MEDIUM,
        priority_score=priority_score_for(priority),
        priority_level=priority,
        priority_reason=f"Priorite {priority.value} de test email.",
        status=AlertStatus.NEW,
        source="TEST",
        reason="Correlation MATCH de test email.",
        first_detected_at=now,
        last_seen_at=now,
        is_active=True,
    )
    db.add(alert)
    db.flush()
    return alert


def priority_score_for(priority: AlertPriority) -> Decimal:
    return {
        AlertPriority.LOW: Decimal("20.00"),
        AlertPriority.MEDIUM: Decimal("45.00"),
        AlertPriority.HIGH: Decimal("65.00"),
        AlertPriority.CRITICAL: Decimal("90.00"),
    }[priority]


def count_notifications_for_alert(
    db,
    alert_id: str,
    channel: NotificationChannel,
) -> int:
    return (
        db.scalar(
            select(func.count(Notification.id)).where(
                Notification.alert_id == alert_id,
                Notification.channel == channel,
            )
        )
        or 0
    )


def count_notifications(db) -> int:
    return db.scalar(select(func.count(Notification.id))) or 0


def utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


if __name__ == "__main__":
    raise SystemExit(main())
