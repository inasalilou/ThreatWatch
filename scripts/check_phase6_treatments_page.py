"""
Verification locale de la page /treatments.

Controle la consultation des traitements analyste sans modifier les donnees.
Les donnees positives sont creees dans une transaction annulee a la fin.
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
from app.db.database import get_db, get_safe_database_url, test_database_connection  # noqa: E402
from app.main import app  # noqa: E402
from app.models.alert import Alert  # noqa: E402
from app.models.alert_treatment import AlertTreatment, AlertTreatmentActionType  # noqa: E402
from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType  # noqa: E402
from app.models.asset_vulnerability_correlation import (  # noqa: E402
    AssetVulnerabilityCorrelation,
    CorrelationPersistenceStatus,
)
from app.models.user import RoleUtilisateur, Utilisateur  # noqa: E402
from app.models.vulnerability import EnrichmentStatus, Vulnerability  # noqa: E402
from app.services.alert_service import create_alert_from_correlation  # noqa: E402
from app.services.analyst_treatment_service import (  # noqa: E402
    add_alert_comment,
    resolve_alert_treatment,
    start_alert_treatment,
)
from app.services.treatment_query_service import get_treatment_stats, list_treatments  # noqa: E402


def main() -> int:
    print(
        "Verification phase 6 traitements page avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        with SessionLocalForScript() as db:
            admin = create_test_user(db, RoleUtilisateur.ADMIN)
            analyst = create_test_user(db, RoleUtilisateur.ANALYSTE)
            alert = create_alert_with_history(db, analyst)

            if not check_service_filters_and_pagination(db, alert, analyst):
                return 1
            if not check_routes(db, admin, analyst, alert):
                return 1

            db.rollback()

        print("PHASE 6 TREATMENTS PAGE CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR SQLAlchemy: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def SessionLocalForScript():
    from app.db.database import SessionLocal

    return SessionLocal()


def check_service_filters_and_pagination(
    db: Session,
    alert: Alert,
    analyst: Utilisateur,
) -> bool:
    search_result = list_treatments(db, search="TEST-TREATMENTS-PAGE")
    analyst_result = list_treatments(db, analyst_id=analyst.id)
    action_result = list_treatments(db, action_type=AlertTreatmentActionType.COMMENTED.value)
    status_result = list_treatments(db, new_status=alert.status.value)
    role_result = list_treatments(db, role=analyst.role.value)
    empty_result = list_treatments(db, search="NO-TREATMENT-SHOULD-MATCH-THIS")
    page_result = list_treatments(db, per_page=1)
    stats = get_treatment_stats(db)

    if (
        search_result.total < 1
        or analyst_result.total < 1
        or action_result.total < 1
        or status_result.total < 1
        or role_result.total < 1
        or empty_result.total != 0
        or page_result.per_page != 1
        or page_result.total_pages < 1
        or stats.total_actions < 3
        or stats.started_actions < 1
        or stats.commented_actions < 1
        or stats.resolved_actions < 1
        or count_duplicate_treatments(db) != 0
    ):
        print("Service traitements filtres/pagination: FAILED")
        return False

    print("Service traitements filtres/pagination: OK")
    return True


def check_routes(
    db: Session,
    admin: Utilisateur,
    analyst: Utilisateur,
    alert: Alert,
) -> bool:
    client = TestClient(app, follow_redirects=False)
    response = client.get("/treatments")
    if response.status_code != 303 or "/login" not in response.headers.get("location", ""):
        print("Route /treatments hors session: FAILED")
        return False

    if not route_with_user_returns_200(db, admin, alert):
        print("Route /treatments ADMIN: FAILED")
        return False
    if not route_with_user_returns_200(db, analyst, alert):
        print("Route /treatments ANALYSTE: FAILED")
        return False

    before_counts = count_objects(db)
    install_overrides(db, analyst)
    try:
        client = TestClient(app, follow_redirects=False)
        response = client.get("/treatments?q=TEST-TREATMENTS-PAGE")
        after_counts = count_objects(db)
        body = response.text
        if response.status_code != 200:
            print("Route /treatments contenu: FAILED (HTTP)")
            return False
        if "TEST-TREATMENTS-PAGE" not in body or f"/alerts/{alert.id}" not in body:
            print("Route /treatments contenu: FAILED")
            return False
        if before_counts != after_counts:
            print("Route /treatments lecture seule: FAILED")
            return False
    finally:
        app.dependency_overrides.clear()

    print("Route /treatments hors session: OK")
    print("Route /treatments ADMIN: OK")
    print("Route /treatments ANALYSTE: OK")
    print("Route /treatments contenu et lien alerte: OK")
    print("Route /treatments lecture seule: OK")
    return True


def route_with_user_returns_200(db: Session, user: Utilisateur, alert: Alert) -> bool:
    install_overrides(db, user)
    try:
        client = TestClient(app, follow_redirects=False)
        response = client.get("/treatments")
        filtered = client.get(
            "/treatments",
            params={
                "analyst_id": user.id,
                "action_type": AlertTreatmentActionType.STARTED.value,
                "new_status": "IN_PROGRESS",
                "role": user.role.value,
                "q": "TEST-TREATMENTS-PAGE",
            },
        )
        return response.status_code == 200 and filtered.status_code == 200
    finally:
        app.dependency_overrides.clear()


def install_overrides(db: Session, user: Utilisateur) -> None:
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[require_authenticated_user] = lambda: user


def create_alert_with_history(db: Session, analyst: Utilisateur) -> Alert:
    alert = create_test_alert(db)
    start_alert_treatment(db, alert.id, analyst)
    add_alert_comment(
        db,
        alert.id,
        analyst,
        "TEST-TREATMENTS-PAGE Observation de controle pour la vue traitements.",
    )
    resolve_alert_treatment(db, alert.id, analyst)
    db.refresh(alert)
    return alert


def create_test_alert(db: Session) -> Alert:
    token = uuid4().hex[:8].upper()
    asset = Asset(
        name=f"TEST-TREATMENTS-PAGE-ASSET-{token}",
        asset_type=AssetType.APPLICATION,
        vendor="TreatmentPageVendor",
        product="TreatmentPageProduct",
        product_version="1.0.0",
        criticality=AssetCriticality.HIGH,
        environment=AssetEnvironment.PRODUCTION,
        is_active=True,
    )
    vulnerability = Vulnerability(
        cve_id=f"CVE-2095-{token[:4]}",
        description="Vulnerabilite de test pour page traitements.",
        cvss_score=Decimal("7.5"),
        cvss_severity="HIGH",
        enrichment_status=EnrichmentStatus.SUCCESS,
    )
    db.add_all([asset, vulnerability])
    db.flush()

    correlation = AssetVulnerabilityCorrelation(
        asset_id=asset.id,
        vulnerability_id=vulnerability.id,
        status=CorrelationPersistenceStatus.MATCH,
        reason="Correlation MATCH de test pour page traitements.",
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


def create_test_user(db: Session, role: RoleUtilisateur) -> Utilisateur:
    token = uuid4().hex
    user = Utilisateur(
        nom=f"TEST TREATMENTS {role.value} {token[:6]}",
        email=f"test-treatments-{role.value.lower()}-{token}@example.test",
        mot_de_passe_hash="not-used",
        role=role,
        actif=True,
    )
    db.add(user)
    db.flush()
    return user


def count_objects(db: Session) -> tuple[int, int]:
    alert_count = db.scalar(select(func.count(Alert.id))) or 0
    treatment_count = db.scalar(select(func.count(AlertTreatment.id))) or 0
    return alert_count, treatment_count


def count_duplicate_treatments(db: Session) -> int:
    grouped = (
        select(AlertTreatment.id)
        .group_by(AlertTreatment.id)
        .having(func.count(AlertTreatment.id) > 1)
        .subquery()
    )
    return db.scalar(select(func.count()).select_from(grouped)) or 0


def utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


if __name__ == "__main__":
    raise SystemExit(main())
