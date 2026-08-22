"""
Verification locale de la phase 6.2.1.

Controle le modele Notification et la creation controlee des notifications
IN_APP depuis les alertes SOC. Aucun email, aucun scheduler, rollback final.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

from sqlalchemy import func, inspect, select
from sqlalchemy.exc import SQLAlchemyError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, engine, get_safe_database_url, test_database_connection  # noqa: E402
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
    NotificationType,
)
from app.models.vulnerability import EnrichmentStatus, Vulnerability  # noqa: E402
from app.models.vulnerability_affected_product import VulnerabilityAffectedProduct  # noqa: E402
from app.services.alert_service import close_alert, create_alert_from_correlation, resolve_alert, start_alert  # noqa: E402
from app.services.notification_service import create_notification_from_alert, list_notifications  # noqa: E402


def main() -> int:
    print(
        "Verification phase 6.2.1 notifications avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        checks = [
            check_table_structure(),
            check_notification_rules(),
        ]
        if not all(checks):
            return 1

        print("PHASE 6.2.1 NOTIFICATIONS CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR SQLAlchemy: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def check_table_structure() -> bool:
    inspector = inspect(engine)
    if "notifications" not in inspector.get_table_names():
        print("Table notifications presente: FAILED")
        return False

    columns = {column["name"] for column in inspector.get_columns("notifications")}
    expected_columns = {
        "id",
        "alert_id",
        "recipient_user_id",
        "notification_type",
        "channel",
        "title",
        "message",
        "severity",
        "status",
        "created_at",
        "sent_at",
        "read_at",
        "is_read",
        "updated_at",
    }
    missing_columns = expected_columns - columns
    if missing_columns:
        print("Colonnes notifications: FAILED " + ", ".join(sorted(missing_columns)))
        return False

    foreign_keys = inspector.get_foreign_keys("notifications")
    fk_targets = {
        (fk["constrained_columns"][0], fk["referred_table"])
        for fk in foreign_keys
        if fk.get("constrained_columns")
    }
    if ("alert_id", "alerts") not in fk_targets or (
        "recipient_user_id",
        "utilisateurs",
    ) not in fk_targets:
        print("FK notifications: FAILED")
        return False

    unique_constraints = inspector.get_unique_constraints("notifications")
    unique_columns = {tuple(item["column_names"]) for item in unique_constraints}
    if ("alert_id", "notification_type", "channel") not in unique_columns:
        print("Anti-doublon notifications: FAILED")
        return False

    print("Table notifications presente: OK")
    print("FK notifications: OK")
    print("Anti-doublon notifications: OK")
    return True


def check_notification_rules() -> bool:
    with SessionLocal() as db:
        initial_count = count_notifications(db)
        checks = [
            check_critical_alert_creates_notification(db),
            check_high_alert_creates_notification(db),
            check_low_medium_create_no_notification(db),
            check_duplicate_is_not_created(db),
            check_closed_alert_is_ignored(db),
            check_list_notifications(db),
        ]
        db.rollback()

        with SessionLocal() as verification_db:
            if count_notifications(verification_db) != initial_count:
                print("Rollback final notifications: FAILED")
                return False

    if not all(checks):
        return False

    print("Rollback final notifications: OK")
    return True


def check_critical_alert_creates_notification(db) -> bool:
    alert = create_alert_with_priority(db, "CRITICAL", AlertPriority.CRITICAL)
    notification = get_notification_for_alert(db, alert.id)

    if (
        notification is None
        or notification.notification_type != NotificationType.ALERT_CREATED
        or notification.channel != NotificationChannel.IN_APP
        or notification.status != NotificationStatus.SENT
        or notification.severity != AlertPriority.CRITICAL.value
        or notification.is_read is not False
        or notification.read_at is not None
        or notification.sent_at is None
        or "CVE-" not in notification.message
    ):
        print("CRITICAL -> notification IN_APP: FAILED")
        return False

    print("CRITICAL -> notification IN_APP: OK")
    print("is_read=False: OK")
    print("status/sent_at IN_APP: OK")
    return True


def check_high_alert_creates_notification(db) -> bool:
    alert = create_alert_with_priority(db, "HIGH", AlertPriority.HIGH)
    notification = get_notification_for_alert(db, alert.id)

    if (
        notification is None
        or notification.status != NotificationStatus.SENT
        or notification.severity != AlertPriority.HIGH.value
    ):
        print("HIGH -> notification IN_APP: FAILED")
        return False

    print("HIGH -> notification IN_APP: OK")
    return True


def check_low_medium_create_no_notification(db) -> bool:
    low_alert = create_alert_with_priority(db, "LOW", AlertPriority.LOW)
    medium_alert = create_alert_with_priority(db, "MEDIUM", AlertPriority.MEDIUM)

    if (
        count_notifications_for_alert(db, low_alert.id) != 0
        or count_notifications_for_alert(db, medium_alert.id) != 0
    ):
        print("LOW/MEDIUM -> aucune notification: FAILED")
        return False

    print("LOW/MEDIUM -> aucune notification: OK")
    return True


def check_duplicate_is_not_created(db) -> bool:
    alert = create_alert_with_priority(db, "DEDUP", AlertPriority.CRITICAL)
    first_notification = get_notification_for_alert(db, alert.id)
    create_notification_from_alert(db, alert)
    create_alert_from_correlation(db, alert.correlation_id)

    if (
        first_notification is None
        or count_notifications_for_alert(
            db,
            alert.id,
            NotificationChannel.IN_APP,
        )
        != 1
        or get_notification_for_alert(db, alert.id).id != first_notification.id
    ):
        print("Anti-doublon service/re-evaluation: FAILED")
        return False

    print("Anti-doublon service/re-evaluation: OK")
    return True


def check_closed_alert_is_ignored(db) -> bool:
    alert = create_alert_with_priority(db, "CLOSED", AlertPriority.CRITICAL)
    initial_count = count_notifications_for_alert(db, alert.id)
    start_alert(db, alert.id)
    resolve_alert(db, alert.id)
    close_alert(db, alert.id)
    create_notification_from_alert(db, alert)
    create_alert_from_correlation(db, alert.correlation_id)

    if (
        alert.status != AlertStatus.CLOSED
        or alert.is_active is not False
        or count_notifications_for_alert(db, alert.id) != initial_count
    ):
        print("Alerte CLOSED -> aucune nouvelle notification: FAILED")
        return False

    print("Alerte CLOSED -> aucune nouvelle notification: OK")
    return True


def check_list_notifications(db) -> bool:
    alert = create_alert_with_priority(db, "LIST", AlertPriority.CRITICAL)
    result = list_notifications(db, search=alert.title, per_page=1)
    if (
        result.total < 1
        or not result.items
        or result.items[0].notification.alert_id != alert.id
    ):
        print("list_notifications: FAILED")
        return False

    print("list_notifications: OK")
    return True


def create_alert_with_priority(
    db,
    suffix: str,
    priority: AlertPriority,
) -> Alert:
    asset, vulnerability, correlation = create_asset_vulnerability_correlation(
        db,
        suffix=suffix,
    )
    alert = Alert(
        correlation_id=correlation.id,
        asset_id=asset.id,
        vulnerability_id=vulnerability.id,
        title=f"TEST-NOTIFICATION-{suffix}-{vulnerability.cve_id}",
        description="Alerte temporaire de test notification.",
        severity=AlertSeverity.CRITICAL
        if priority in {AlertPriority.HIGH, AlertPriority.CRITICAL}
        else AlertSeverity.MEDIUM,
        priority_score=priority_score_for(priority),
        priority_level=priority,
        priority_reason=f"Priorite {priority.value} de test notification.",
        status=AlertStatus.NEW,
        source="TEST",
        reason="Correlation MATCH de test notification.",
        first_detected_at=correlation.first_detected_at,
        last_seen_at=correlation.last_evaluated_at,
        is_active=True,
    )
    db.add(alert)
    db.flush()
    create_notification_from_alert(db, alert)
    return alert


def create_asset_vulnerability_correlation(
    db,
    suffix: str,
) -> tuple[Asset, Vulnerability, AssetVulnerabilityCorrelation]:
    token = uuid4().hex[:8].upper()
    now = utcnow_naive()
    asset = Asset(
        name=f"TEST-NOTIF-{suffix}-{token}",
        asset_type=AssetType.APPLICATION,
        vendor="NotifyVendor",
        product="NotifyProduct",
        product_version="1.0.0",
        criticality=AssetCriticality.CRITICAL,
        environment=AssetEnvironment.PRODUCTION,
        is_active=True,
    )
    vulnerability = Vulnerability(
        cve_id=f"CVE-2098-{token[:4]}",
        description="Vulnerabilite temporaire de test notification.",
        cvss_score=Decimal("9.8"),
        cvss_severity="CRITICAL",
        enrichment_status=EnrichmentStatus.SUCCESS,
    )
    vulnerability.affected_products.append(
        VulnerabilityAffectedProduct(
            cpe=f"cpe:2.3:a:notifyvendor:notifyproduct:*:*:*:*:*:*:*:*:{token}",
            cpe_part="a",
            vendor="NotifyVendor",
            product="NotifyProduct",
            version="*",
            vulnerable=True,
        )
    )
    db.add_all([asset, vulnerability])
    db.flush()

    correlation = AssetVulnerabilityCorrelation(
        asset_id=asset.id,
        vulnerability_id=vulnerability.id,
        status=CorrelationPersistenceStatus.MATCH,
        reason="Correspondance de test notification.",
        vendor_result="MATCH",
        product_result="MATCH",
        version_result="MATCH",
        cpe_result="MATCH",
        first_detected_at=now,
        last_evaluated_at=now,
        is_active=True,
    )
    db.add(correlation)
    db.flush()
    return asset, vulnerability, correlation


def priority_score_for(priority: AlertPriority) -> Decimal:
    return {
        AlertPriority.LOW: Decimal("20.00"),
        AlertPriority.MEDIUM: Decimal("45.00"),
        AlertPriority.HIGH: Decimal("65.00"),
        AlertPriority.CRITICAL: Decimal("90.00"),
    }[priority]


def get_notification_for_alert(db, alert_id: str) -> Notification | None:
    return db.execute(
        select(Notification).where(
            Notification.alert_id == alert_id,
            Notification.channel == NotificationChannel.IN_APP,
        )
    ).scalar_one_or_none()


def count_notifications_for_alert(
    db,
    alert_id: str,
    channel: NotificationChannel | None = None,
) -> int:
    filters = [Notification.alert_id == alert_id]
    if channel is not None:
        filters.append(Notification.channel == channel)
    return (
        db.scalar(
            select(func.count(Notification.id)).where(*filters)
        )
        or 0
    )


def count_notifications(db) -> int:
    return db.scalar(select(func.count(Notification.id))) or 0


def utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


if __name__ == "__main__":
    raise SystemExit(main())
