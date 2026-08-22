"""
Verification locale de la phase 6.2.2.

Controle la page /notifications, la visibilite globale/privee, le compteur non
lu, les actions de lecture et la pagination. Les commits des routes sont
isoles dans une transaction externe annulee a la fin.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.core.deps import require_authenticated_user  # noqa: E402
from app.db.database import SessionLocal, engine, get_db, get_safe_database_url, test_database_connection  # noqa: E402
from app.main import app  # noqa: E402
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
from app.models.user import RoleUtilisateur, Utilisateur  # noqa: E402
from app.models.vulnerability import EnrichmentStatus, Vulnerability  # noqa: E402
from app.services.notification_service import (  # noqa: E402
    count_unread_notifications,
    list_notifications,
)


def main() -> int:
    print(
        "Verification phase 6.2.2 notifications UI avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        initial_count = count_persistent_notifications()
        connection = engine.connect()
        transaction = connection.begin()
        db = Session(bind=connection, join_transaction_mode="create_savepoint")
        try:
            context = create_test_context(db)
            checks = [
                check_service_visibility_and_counters(db, context),
                check_routes(db, context),
            ]
            db.close()
            transaction.rollback()
        finally:
            connection.close()
            app.dependency_overrides.clear()

        if count_persistent_notifications() != initial_count:
            print("Rollback final notifications UI: FAILED")
            return 1
        if not all(checks):
            return 1

        print("Rollback final notifications UI: OK")
        print("PHASE 6.2.2 NOTIFICATIONS UI CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR SQLAlchemy: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def check_service_visibility_and_counters(db: Session, context: dict) -> bool:
    analyst_one = context["analyst_one"]
    analyst_two = context["analyst_two"]
    global_notification = context["global_notification"]
    private_one = context["private_one"]
    private_two = context["private_two"]

    result_one = list_notifications(
        db,
        visible_to_user_id=analyst_one.id,
        per_page=100,
    )
    result_two = list_notifications(
        db,
        visible_to_user_id=analyst_two.id,
        per_page=100,
    )
    ids_one = {item.notification.id for item in result_one.items}
    ids_two = {item.notification.id for item in result_two.items}

    unread_one = count_unread_notifications(db, analyst_one)
    unread_two = count_unread_notifications(db, analyst_two)

    if (
        global_notification.id not in ids_one
        or private_one.id not in ids_one
        or private_two.id in ids_one
        or global_notification.id not in ids_two
        or private_one.id in ids_two
        or private_two.id not in ids_two
        or unread_one < 2
        or unread_two < 2
    ):
        print("Service notifications visibilite/compteur: FAILED")
        return False

    filtered = list_notifications(
        db,
        visible_to_user_id=analyst_one.id,
        read_filter="unread",
        severity=AlertPriority.CRITICAL.value,
        search="TEST-NOTIFICATIONS-UI",
        per_page=1,
    )
    if filtered.total < 1 or filtered.per_page != 1:
        print("Service notifications filtres/pagination: FAILED")
        return False

    print("Service notifications visibilite/compteur: OK")
    print("Service notifications filtres/pagination: OK")
    return True


def check_routes(db: Session, context: dict) -> bool:
    client = TestClient(app, follow_redirects=False)
    response = client.get("/notifications")
    if response.status_code != 303 or "/login" not in response.headers.get("location", ""):
        print("Route /notifications hors session: FAILED")
        return False

    if not route_returns_200(db, context["admin"]):
        print("Route /notifications ADMIN: FAILED")
        return False
    if not route_returns_200(db, context["analyst_one"]):
        print("Route /notifications ANALYSTE: FAILED")
        return False

    if not check_route_content_and_visibility(db, context):
        return False
    if not check_route_filters_and_pagination(db, context):
        return False
    if not check_mark_read_routes(db, context):
        return False

    print("Route /notifications hors session: OK")
    print("Route /notifications ADMIN: OK")
    print("Route /notifications ANALYSTE: OK")
    return True


def route_returns_200(db: Session, user: Utilisateur) -> bool:
    install_overrides(db, user)
    try:
        client = TestClient(app, follow_redirects=False)
        response = client.get("/notifications")
        return response.status_code == 200
    finally:
        app.dependency_overrides.clear()


def check_route_content_and_visibility(db: Session, context: dict) -> bool:
    analyst_one = context["analyst_one"]
    install_overrides(db, analyst_one)
    try:
        client = TestClient(app, follow_redirects=False)
        global_response = client.get("/notifications?q=TEST-NOTIFICATIONS-UI-GLOBAL")
        private_one_response = client.get(
            "/notifications?q=TEST-NOTIFICATIONS-UI-PRIVATE-ONE"
        )
        private_two_response = client.get(
            "/notifications?q=TEST-NOTIFICATIONS-UI-PRIVATE-TWO"
        )
        if (
            global_response.status_code != 200
            or private_one_response.status_code != 200
            or private_two_response.status_code != 200
        ):
            print("Route /notifications listing: FAILED (HTTP)")
            return False
        if (
            "TEST-NOTIFICATIONS-UI-GLOBAL" not in global_response.text
            or "TEST-NOTIFICATIONS-UI-PRIVATE-ONE" not in private_one_response.text
            or f"/alerts/{context['private_two'].alert_id}" in private_two_response.text
            or f"/alerts/{context['alert'].id}" not in global_response.text
            or "icon-btn__badge" not in global_response.text
        ):
            print("Route /notifications listing/visibilite: FAILED")
            return False
    finally:
        app.dependency_overrides.clear()

    print("Route /notifications listing/visibilite: OK")
    print("Cloche compteur non lu: OK")
    return True


def check_route_filters_and_pagination(db: Session, context: dict) -> bool:
    install_overrides(db, context["analyst_one"])
    try:
        client = TestClient(app, follow_redirects=False)
        unread = client.get("/notifications?read=unread")
        read = client.get("/notifications?read=read")
        critical = client.get("/notifications?severity=CRITICAL")
        notification_type = client.get("/notifications?notification_type=ALERT_CREATED")
        page = client.get("/notifications?page=1")
        if not all(
            response.status_code == 200
            for response in [unread, read, critical, notification_type, page]
        ):
            print("Route /notifications filtres: FAILED (HTTP)")
            return False
        if "Page 1 /" not in page.text or "Suivant" not in page.text:
            print("Route /notifications pagination: FAILED")
            return False
    finally:
        app.dependency_overrides.clear()

    print("Route /notifications filtres: OK")
    print("Route /notifications pagination: OK")
    return True


def check_mark_read_routes(db: Session, context: dict) -> bool:
    analyst_one = context["analyst_one"]
    private_one = context["private_one"]
    private_two = context["private_two"]

    install_overrides(db, analyst_one)
    try:
        client = TestClient(app, follow_redirects=False)
        first = client.post(f"/notifications/{private_one.id}/read")
        second = client.post(f"/notifications/{private_one.id}/read")
        forbidden = client.post(f"/notifications/{private_two.id}/read")
        db.refresh(private_one)
        db.refresh(private_two)
        if (
            first.status_code != 303
            or second.status_code != 303
            or forbidden.status_code != 303
            or private_one.is_read is not True
            or private_one.read_at is None
            or private_two.is_read is not False
        ):
            print("Route mark as read/idempotence: FAILED")
            return False

        read_all = client.post("/notifications/read-all")
        db.refresh(private_two)
        if read_all.status_code != 303 or private_two.is_read is not False:
            print("Route read-all visible seulement: FAILED")
            return False
    finally:
        app.dependency_overrides.clear()

    print("Route mark as read/idempotence: OK")
    print("Route read-all visible seulement: OK")
    return True


def install_overrides(db: Session, user: Utilisateur) -> None:
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[require_authenticated_user] = lambda: user


def create_test_context(db: Session) -> dict:
    admin = create_test_user(db, RoleUtilisateur.ADMIN, "ADMIN")
    analyst_one = create_test_user(db, RoleUtilisateur.ANALYSTE, "ONE")
    analyst_two = create_test_user(db, RoleUtilisateur.ANALYSTE, "TWO")
    alert = create_test_alert(db, "MAIN")
    alert_two = create_test_alert(db, "PRIVATE-TWO")

    global_notification = create_notification(
        db,
        alert,
        title="TEST-NOTIFICATIONS-UI-GLOBAL",
        notification_type=NotificationType.ALERT_CREATED,
    )
    private_one = create_notification(
        db,
        alert,
        title="TEST-NOTIFICATIONS-UI-PRIVATE-ONE",
        recipient_user_id=analyst_one.id,
        notification_type=NotificationType.ALERT_CRITICAL,
    )
    private_two = create_notification(
        db,
        alert_two,
        title="TEST-NOTIFICATIONS-UI-PRIVATE-TWO",
        recipient_user_id=analyst_two.id,
        notification_type=NotificationType.ALERT_CREATED,
    )

    for index in range(22):
        bulk_alert = create_test_alert(db, f"BULK-{index}")
        create_notification(
            db,
            bulk_alert,
            title=f"TEST-NOTIFICATIONS-UI-BULK-{index:02d}",
            notification_type=NotificationType.ALERT_CREATED,
        )

    return {
        "admin": admin,
        "analyst_one": analyst_one,
        "analyst_two": analyst_two,
        "alert": alert,
        "global_notification": global_notification,
        "private_one": private_one,
        "private_two": private_two,
    }


def create_test_user(
    db: Session,
    role: RoleUtilisateur,
    suffix: str,
) -> Utilisateur:
    token = uuid4().hex
    user = Utilisateur(
        nom=f"TEST NOTIFICATIONS UI {suffix} {token[:6]}",
        email=f"test-notifications-ui-{suffix.lower()}-{token}@example.test",
        mot_de_passe_hash="not-used",
        role=role,
        actif=True,
    )
    db.add(user)
    db.flush()
    return user


def create_test_alert(db: Session, suffix: str) -> Alert:
    token = uuid4().hex[:8].upper()
    now = utcnow_naive()
    asset = Asset(
        name=f"TEST-NOTIFICATIONS-UI-ASSET-{suffix}-{token}",
        asset_type=AssetType.APPLICATION,
        vendor="NotifyUiVendor",
        product="NotifyUiProduct",
        product_version="1.0.0",
        criticality=AssetCriticality.CRITICAL,
        environment=AssetEnvironment.PRODUCTION,
        is_active=True,
    )
    vulnerability = Vulnerability(
        cve_id=f"CVE-2099-{token[:4]}",
        description="Vulnerabilite de test pour interface notifications.",
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
        reason="Correlation MATCH de test notifications UI.",
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
        title=f"TEST-NOTIFICATIONS-UI-ALERT-{suffix}-{token}",
        description="Alerte de test pour interface notifications.",
        severity=AlertSeverity.CRITICAL,
        priority_score=Decimal("90.00"),
        priority_level=AlertPriority.CRITICAL,
        priority_reason="Priorite CRITICAL de test notifications UI.",
        status=AlertStatus.NEW,
        source="TEST",
        reason="Notification UI test.",
        first_detected_at=now,
        last_seen_at=now,
        is_active=True,
    )
    db.add(alert)
    db.flush()
    return alert


def create_notification(
    db: Session,
    alert: Alert,
    *,
    title: str,
    notification_type: NotificationType,
    recipient_user_id: str | None = None,
) -> Notification:
    now = utcnow_naive()
    notification = Notification(
        alert_id=alert.id,
        recipient_user_id=recipient_user_id,
        notification_type=notification_type,
        channel=NotificationChannel.IN_APP,
        title=title,
        message=f"{title} pour {alert.title}",
        severity=alert.priority_level.value,
        status=NotificationStatus.SENT,
        created_at=now,
        sent_at=now,
        is_read=False,
    )
    db.add(notification)
    db.flush()
    return notification


def count_persistent_notifications() -> int:
    with SessionLocal() as db:
        return db.scalar(select(func.count(Notification.id))) or 0


def utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


if __name__ == "__main__":
    raise SystemExit(main())
