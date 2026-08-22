"""
Verification locale de la phase 5.3.

Controle l'interface /alerts, le detail et le workflow analyste de base.
Les donnees de test sont creees dans une transaction externe puis annulees.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.core.deps import require_authenticated_user  # noqa: E402
from app.db.database import engine, get_db, get_safe_database_url, test_database_connection  # noqa: E402
from app.main import app  # noqa: E402
from app.models.alert import Alert, AlertPriority, AlertStatus  # noqa: E402
from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType  # noqa: E402
from app.models.asset_vulnerability_correlation import (  # noqa: E402
    AssetVulnerabilityCorrelation,
    CorrelationPersistenceStatus,
)
from app.models.user import RoleUtilisateur, Utilisateur  # noqa: E402
from app.models.vulnerability import EnrichmentStatus, Vulnerability  # noqa: E402
from app.services.alert_service import (  # noqa: E402
    close_alert,
    create_alert_from_correlation,
    list_alerts,
    resolve_alert,
    start_alert,
)


def main() -> int:
    print(
        "Verification phase 5.3 interface alertes avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    connection = None
    transaction = None
    db = None
    try:
        test_database_connection()
        connection = engine.connect()
        transaction = connection.begin()
        db = Session(bind=connection)

        alert = create_alert_context(db)
        if not check_listing_service(db, alert.id):
            return 1
        if not check_workflow_service(db):
            return 1
        if not check_routes(db, alert.id):
            return 1

        print("PHASE 5.3 ALERTS UI CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR SQLAlchemy: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1
    finally:
        app.dependency_overrides.clear()
        if db is not None:
            db.close()
        if transaction is not None:
            transaction.rollback()
        if connection is not None:
            connection.close()


def check_listing_service(db: Session, alert_id: str) -> bool:
    result = list_alerts(
        db,
        search="TEST-ALERT-UI",
        status="NEW",
        priority="CRITICAL",
        severity="CRITICAL",
        is_active="active",
        per_page=1,
    )
    if result.total < 1 or not any(item.alert.id == alert_id for item in result.items):
        print("Listing alertes: FAILED")
        return False
    if result.items[0].alert.priority_level != AlertPriority.CRITICAL:
        print("Priorite SOC listing: FAILED")
        return False

    print("Listing alertes: OK")
    print("Filtres alertes: OK")
    return True


def check_workflow_service(db: Session) -> bool:
    alert = create_alert_context(db, suffix="WORKFLOW")
    started = start_alert(db, alert.id)
    resolved = resolve_alert(db, alert.id)
    closed = close_alert(db, alert.id)

    if (
        started is None
        or resolved is None
        or closed is None
        or closed.status != AlertStatus.CLOSED
        or closed.is_active is not False
    ):
        print("Workflow service: FAILED")
        return False

    print("Workflow service NEW -> IN_PROGRESS -> RESOLVED -> CLOSED: OK")
    return True


def check_routes(db: Session, alert_id: str) -> bool:
    client = TestClient(app, follow_redirects=False)
    response = client.get("/alerts")
    if response.status_code != 303 or "/login" not in response.headers.get("location", ""):
        print("Route unauthenticated: FAILED")
        return False

    if not route_with_user_returns_200(db, RoleUtilisateur.ADMIN, alert_id):
        print("Route ADMIN: FAILED")
        return False
    if not route_with_user_returns_200(db, RoleUtilisateur.ANALYSTE, alert_id):
        print("Route ANALYSTE: FAILED")
        return False

    route_alert = create_alert_context(db, suffix="ROUTE-WORKFLOW")
    if not route_workflow(db, route_alert.id):
        return False

    print("Route unauthenticated redirect: OK")
    print("Route ADMIN: OK")
    print("Route ANALYSTE: OK")
    print("Routes workflow: OK")
    return True


def route_with_user_returns_200(
    db: Session,
    role: RoleUtilisateur,
    alert_id: str,
) -> bool:
    install_overrides(db, build_user(db, role))
    try:
        client = TestClient(app, follow_redirects=False)
        list_response = client.get("/alerts")
        detail_response = client.get(f"/alerts/{alert_id}")
        return list_response.status_code == 200 and detail_response.status_code == 200
    finally:
        app.dependency_overrides.clear()


def route_workflow(db: Session, alert_id: str) -> bool:
    install_overrides(db, build_user(db, RoleUtilisateur.ANALYSTE))
    try:
        client = TestClient(app, follow_redirects=False)
        start_response = client.post(f"/alerts/{alert_id}/start")
        db.expire_all()
        started = db.get(Alert, alert_id)
        started_status = started.status if started is not None else None
        resolve_response = client.post(f"/alerts/{alert_id}/resolve")
        db.expire_all()
        resolved = db.get(Alert, alert_id)
        resolved_status = resolved.status if resolved is not None else None
        close_response = client.post(f"/alerts/{alert_id}/close")
        db.expire_all()
        closed = get_alert_object(db, alert_id)
        closed_status = closed.status
        closed_is_active = closed.is_active

        if (
            start_response.status_code != 303
            or resolve_response.status_code != 303
            or close_response.status_code != 303
        ):
            print("Routes workflow: FAILED (status HTTP)")
            return False
        if (
            started_status != AlertStatus.IN_PROGRESS
            or resolved_status != AlertStatus.RESOLVED
            or closed_status != AlertStatus.CLOSED
            or closed_is_active is not False
        ):
            print("Routes workflow: FAILED (transition)")
            return False

        return True
    finally:
        app.dependency_overrides.clear()


def install_overrides(db: Session, user: Utilisateur) -> None:
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[require_authenticated_user] = lambda: user


def create_alert_context(db: Session, suffix: str = "MAIN"):
    token = uuid4().hex[:8].upper()
    asset = Asset(
        name=f"TEST-ALERT-UI-{suffix}-{token}",
        asset_type=AssetType.APPLICATION,
        vendor="UiVendor",
        product="UiProduct",
        product_version="1.0.0",
        criticality=AssetCriticality.CRITICAL,
        environment=AssetEnvironment.PRODUCTION,
        is_active=True,
    )
    vulnerability = Vulnerability(
        cve_id=f"CVE-2098-{token[:4]}",
        description="Vulnerabilite de test pour l'interface alertes.",
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
        reason="Correlation MATCH de test pour l'interface alertes.",
        first_detected_at=utcnow_naive(),
        last_evaluated_at=utcnow_naive(),
        is_active=True,
    )
    db.add(correlation)
    db.flush()

    alert = create_alert_from_correlation(db, correlation.id)
    if alert is None:
        raise RuntimeError("Alerte de test non creee.")
    return alert


def get_alert_object(db: Session, alert_id: str):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise RuntimeError("Alerte de test introuvable.")
    return alert


def build_user(db: Session, role: RoleUtilisateur) -> Utilisateur:
    user = Utilisateur(
        nom=f"{role.value.title()} Route",
        email=f"{role.value.lower()}-{uuid4().hex}@example.test",
        mot_de_passe_hash="not-used",
        role=role,
        actif=True,
    )
    db.add(user)
    db.flush()
    return user


def utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


if __name__ == "__main__":
    raise SystemExit(main())
