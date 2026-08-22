"""
Verification locale de la phase 6.6.2 Dashboard SOC final.

Le script cree des donnees temporaires dans une transaction rollback pour
verifier les compteurs et le rendu sans polluer la base permanente.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

from sqlalchemy import func, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.core.deps import require_authenticated_user  # noqa: E402
from app.db.database import SessionLocal, engine, get_db, get_safe_database_url, test_database_connection  # noqa: E402
from app.main import app  # noqa: E402
from app.models.alert import Alert, AlertPriority, AlertSeverity, AlertStatus  # noqa: E402
from app.models.alert_treatment import AlertTreatment, AlertTreatmentActionType  # noqa: E402
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
from app.models.sync_history import SyncHistory, SyncStatus  # noqa: E402
from app.models.user import RoleUtilisateur, Utilisateur  # noqa: E402
from app.models.vulnerability import EnrichmentStatus, Vulnerability  # noqa: E402
from app.services.dashboard_service import get_dashboard_data  # noqa: E402


def main() -> int:
    print(
        "Verification phase 6.6.2 dashboard avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        initial_counts = count_persistent_objects()
        connection = engine.connect()
        transaction = connection.begin()
        db = Session(bind=connection, join_transaction_mode="create_savepoint")
        try:
            admin = create_test_user(db, RoleUtilisateur.ADMIN)
            analyst = create_test_user(db, RoleUtilisateur.ANALYSTE)

            checks = [
                check_service_with_temporary_data(db, admin),
                check_route_permissions(db, admin, analyst),
                check_empty_alert_state(db, admin),
            ]
            db.close()
            transaction.rollback()
        finally:
            connection.close()
            app.dependency_overrides.clear()

        if count_persistent_objects() != initial_counts:
            print("Rollback final dashboard: FAILED")
            return 1
        if not all(checks):
            return 1

        print("Rollback final dashboard: OK")
        print("PHASE 6.6.2 DASHBOARD CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR SQLAlchemy: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def check_service_with_temporary_data(db: Session, admin: Utilisateur) -> bool:
    before = get_dashboard_data(db, admin)
    context = create_dashboard_fixture(db, admin)
    after = get_dashboard_data(db, admin)

    alert_found = any(item.alert_id == context["alert"].id for item in after.recent_alerts)
    exposed_found = any(
        item.asset_id == context["asset"].id and item.match_count >= 1
        for item in after.top_exposed_assets
    )
    treatment_found = any(
        item.treatment_id == context["treatment"].id for item in after.recent_treatments
    )
    notification_found = any(
        item.notification_id == context["notification"].id
        for item in after.recent_notifications
    )
    critical_stat = next(
        item.count for item in after.vulnerability_severity_stats if item.severity == "CRITICAL"
    )

    checks = [
        after.counters.active_alerts == before.counters.active_alerts + 1,
        after.counters.critical_alerts == before.counters.critical_alerts + 1,
        after.counters.vulnerabilities_detected
        == before.counters.vulnerabilities_detected + 1,
        after.counters.active_assets == before.counters.active_assets + 1,
        after.counters.active_match_correlations
        == before.counters.active_match_correlations + 1,
        after.counters.unread_notifications == before.counters.unread_notifications + 1,
        after.counters.nvd_success_vulnerabilities
        == before.counters.nvd_success_vulnerabilities + 1,
        alert_found,
        exposed_found,
        treatment_found,
        notification_found,
        critical_stat >= 1,
        after.sync_summary.sync_id == context["sync"].id,
    ]

    if not all(checks):
        print("Service dashboard donnees temporaires: FAILED")
        return False

    print("Compteurs dashboard reels: OK")
    print("Dernieres alertes dashboard: OK")
    print("Vulnerabilites par severite: OK")
    print("Actifs exposes: OK")
    print("Traitements recents: OK")
    print("Notifications recentes: OK")
    print("Synchronisation DGSSI: OK")
    return True


def check_route_permissions(
    db: Session,
    admin: Utilisateur,
    analyst: Utilisateur,
) -> bool:
    client = TestClient(app, follow_redirects=False)
    response = client.get("/dashboard")
    if response.status_code != 303 or "/login" not in response.headers.get("location", ""):
        print("Route /dashboard hors session: FAILED")
        return False

    if not route_with_user_returns_200(db, admin):
        print("Route /dashboard ADMIN: FAILED")
        return False
    if not route_with_user_returns_200(db, analyst):
        print("Route /dashboard ANALYSTE: FAILED")
        return False

    print("Route /dashboard hors session: OK")
    print("Route /dashboard ADMIN: OK")
    print("Route /dashboard ANALYSTE: OK")
    return True


def check_empty_alert_state(db: Session, admin: Utilisateur) -> bool:
    db.execute(update(Alert).values(is_active=False))
    db.flush()
    install_overrides(db, admin)
    try:
        client = TestClient(app, follow_redirects=False)
        response = client.get("/dashboard")
        body = response.text
        ok = (
            response.status_code == 200
            and "Aucune alerte SOC active" in body
            and "collecte automatique des bulletins DGSSI" not in body
        )
        if not ok:
            print("Etat vide dashboard alertes: FAILED")
            return False
    finally:
        app.dependency_overrides.clear()

    print("Etat vide dashboard alertes: OK")
    return True


def route_with_user_returns_200(db: Session, user: Utilisateur) -> bool:
    install_overrides(db, user)
    try:
        client = TestClient(app, follow_redirects=False)
        response = client.get("/dashboard")
        body = response.text
        return (
            response.status_code == 200
            and "Vue d'ensemble SOC" in body
            and "Alertes actives" in body
            and "Vulnerabilites detectees" in body
        )
    finally:
        app.dependency_overrides.clear()


def create_dashboard_fixture(db: Session, analyst: Utilisateur) -> dict:
    token = uuid4().hex[:8].upper()
    asset = Asset(
        name=f"TEST-DASHBOARD-ASSET-{token}",
        asset_type=AssetType.APPLICATION,
        vendor="dashboardvendor",
        product="dashboardproduct",
        product_version="1.0",
        criticality=AssetCriticality.CRITICAL,
        environment=AssetEnvironment.PRODUCTION,
        is_active=True,
    )
    vulnerability = Vulnerability(
        cve_id=f"CVE-2097-{1000 + (uuid4().int % 8999)}",
        description="Vulnerabilite temporaire dashboard.",
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
        reason="Correlation dashboard temporaire.",
        first_detected_at=utcnow_naive(),
        last_evaluated_at=utcnow_naive(),
        is_active=True,
    )
    db.add(correlation)
    db.flush()

    alert = Alert(
        correlation_id=correlation.id,
        asset_id=asset.id,
        vulnerability_id=vulnerability.id,
        title=f"TEST-DASHBOARD-ALERT-{token}",
        description="Alerte temporaire dashboard.",
        severity=AlertSeverity.CRITICAL,
        priority_score=Decimal("95.00"),
        priority_level=AlertPriority.CRITICAL,
        priority_reason="Priorite temporaire dashboard.",
        status=AlertStatus.NEW,
        source="CORRELATION",
        reason=correlation.reason,
        first_detected_at=correlation.first_detected_at,
        last_seen_at=correlation.last_evaluated_at,
        is_active=True,
    )
    db.add(alert)
    db.flush()

    treatment = AlertTreatment(
        alert_id=alert.id,
        analyst_id=analyst.id,
        action_type=AlertTreatmentActionType.COMMENTED,
        comment="Traitement temporaire dashboard.",
        previous_status=AlertStatus.NEW,
        new_status=AlertStatus.NEW,
    )
    notification = Notification(
        alert_id=alert.id,
        notification_type=NotificationType.ALERT_CREATED,
        channel=NotificationChannel.IN_APP,
        title=f"TEST-DASHBOARD-NOTIFICATION-{token}",
        message="Notification temporaire dashboard.",
        severity=AlertPriority.CRITICAL.value,
        status=NotificationStatus.SENT,
        is_read=False,
    )
    sync = SyncHistory(
        source="DGSSI",
        started_at=utcnow_naive(),
        finished_at=utcnow_naive(),
        status=SyncStatus.SUCCESS,
        items_found=10,
        items_created=1,
        items_updated=0,
    )
    db.add_all([treatment, notification, sync])
    db.flush()
    return {
        "asset": asset,
        "vulnerability": vulnerability,
        "correlation": correlation,
        "alert": alert,
        "treatment": treatment,
        "notification": notification,
        "sync": sync,
    }


def install_overrides(db: Session, user: Utilisateur) -> None:
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[require_authenticated_user] = lambda: user


def create_test_user(db: Session, role: RoleUtilisateur) -> Utilisateur:
    token = uuid4().hex
    user = Utilisateur(
        nom=f"TEST DASHBOARD {role.value} {token[:6]}",
        email=f"test-dashboard-{role.value.lower()}-{token}@example.test",
        mot_de_passe_hash="not-used",
        role=role,
        actif=True,
    )
    db.add(user)
    db.flush()
    return user


def utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def count_persistent_objects() -> tuple[int, ...]:
    with SessionLocal() as db:
        return (
            db.scalar(select(func.count(Asset.id))) or 0,
            db.scalar(select(func.count(Vulnerability.id))) or 0,
            db.scalar(select(func.count(AssetVulnerabilityCorrelation.id))) or 0,
            db.scalar(select(func.count(Alert.id))) or 0,
            db.scalar(select(func.count(AlertTreatment.id))) or 0,
            db.scalar(select(func.count(Notification.id))) or 0,
            db.scalar(select(func.count(SyncHistory.id))) or 0,
        )


if __name__ == "__main__":
    raise SystemExit(main())
