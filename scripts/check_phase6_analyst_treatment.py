"""
Verification locale de la phase 6.1.

Controle l'historique de traitement analyste des alertes SOC. Les donnees de
test sont creees dans une transaction puis annulees par rollback final.
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

from app.db.database import (  # noqa: E402
    SessionLocal,
    create_database_tables,
    engine,
    get_safe_database_url,
    test_database_connection,
)
from app.models.alert import Alert, AlertStatus  # noqa: E402
from app.models.alert_treatment import (  # noqa: E402
    AlertTreatment,
    AlertTreatmentActionType,
)
from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType  # noqa: E402
from app.models.asset_vulnerability_correlation import (  # noqa: E402
    AssetVulnerabilityCorrelation,
    CorrelationPersistenceStatus,
)
from app.models.user import RoleUtilisateur, Utilisateur  # noqa: E402
from app.models.vulnerability import EnrichmentStatus, Vulnerability  # noqa: E402
from app.services.alert_service import create_alert_from_correlation  # noqa: E402
from app.services.analyst_treatment_service import (  # noqa: E402
    AlertTreatmentError,
    add_alert_comment,
    close_alert_treatment,
    get_alert_treatment_history,
    resolve_alert_treatment,
    start_alert_treatment,
)


EXPECTED_COLUMNS = {
    "id",
    "alert_id",
    "analyst_id",
    "action_type",
    "comment",
    "previous_status",
    "new_status",
    "created_at",
}


def main() -> int:
    print(
        "Verification phase 6.1 traitements analyste avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        create_database_tables()
        if not check_table_structure():
            return 1

        with SessionLocal() as db:
            admin = create_test_user(db, RoleUtilisateur.ADMIN)
            analyst = create_test_user(db, RoleUtilisateur.ANALYSTE)
            checks = [
                check_start_transition(db, analyst),
                check_comment(db, analyst),
                check_resolve_transition(db, analyst),
                check_close_transition(db, analyst),
                check_forbidden_transition(db, analyst),
                check_history_is_preserved(db, analyst),
                check_permissions(db, admin, analyst),
                check_rollback_on_error(db),
            ]
            if not all(checks):
                return 1
            db.rollback()

        print("PHASE 6.1 ANALYST TREATMENT CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR SQLAlchemy: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def check_table_structure() -> bool:
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    if "alert_treatments" not in tables:
        print("AlertTreatment table: MANQUANTE")
        return False

    columns = {column["name"] for column in inspector.get_columns("alert_treatments")}
    missing = EXPECTED_COLUMNS - columns
    if missing:
        print("AlertTreatment table: colonnes manquantes " + ", ".join(sorted(missing)))
        return False

    print("AlertTreatment table: OK")
    return True


def check_start_transition(db, analyst: Utilisateur) -> bool:
    alert = create_test_alert(db, "START")
    started = start_alert_treatment(db, alert.id, analyst)
    treatment = latest_treatment(db, alert.id)

    if (
        started.status != AlertStatus.IN_PROGRESS
        or treatment is None
        or treatment.action_type != AlertTreatmentActionType.STARTED
        or treatment.previous_status != AlertStatus.NEW
        or treatment.new_status != AlertStatus.IN_PROGRESS
        or treatment.analyst_id != analyst.id
    ):
        print("Test 1 NEW -> IN_PROGRESS: FAILED")
        return False

    print("Test 1 NEW -> IN_PROGRESS: OK")
    return True


def check_comment(db, analyst: Utilisateur) -> bool:
    alert = create_test_alert(db, "COMMENT")
    treatment = add_alert_comment(
        db,
        alert.id,
        analyst,
        "Verification en cours sur l'actif concerne.",
    )
    db.refresh(alert)

    if (
        alert.status != AlertStatus.NEW
        or treatment is None
        or treatment.action_type != AlertTreatmentActionType.COMMENTED
        or treatment.previous_status != AlertStatus.NEW
        or treatment.new_status != AlertStatus.NEW
        or not treatment.comment
    ):
        print("Test 2 commentaire: FAILED")
        return False

    print("Test 2 commentaire sans changement de statut: OK")
    return True


def check_resolve_transition(db, analyst: Utilisateur) -> bool:
    alert = create_test_alert(db, "RESOLVE")
    start_alert_treatment(db, alert.id, analyst)
    resolved = resolve_alert_treatment(db, alert.id, analyst)
    treatment = latest_treatment(db, alert.id)

    if (
        resolved.status != AlertStatus.RESOLVED
        or treatment is None
        or treatment.action_type != AlertTreatmentActionType.RESOLVED
        or treatment.previous_status != AlertStatus.IN_PROGRESS
        or treatment.new_status != AlertStatus.RESOLVED
    ):
        print("Test 3 IN_PROGRESS -> RESOLVED: FAILED")
        return False

    print("Test 3 IN_PROGRESS -> RESOLVED: OK")
    return True


def check_close_transition(db, analyst: Utilisateur) -> bool:
    alert = create_test_alert(db, "CLOSE")
    start_alert_treatment(db, alert.id, analyst)
    resolve_alert_treatment(db, alert.id, analyst)
    closed = close_alert_treatment(db, alert.id, analyst)
    treatment = latest_treatment(db, alert.id)

    if (
        closed.status != AlertStatus.CLOSED
        or closed.is_active is not False
        or treatment is None
        or treatment.action_type != AlertTreatmentActionType.CLOSED
        or treatment.previous_status != AlertStatus.RESOLVED
        or treatment.new_status != AlertStatus.CLOSED
    ):
        print("Test 4 RESOLVED -> CLOSED: FAILED")
        return False

    print("Test 4 RESOLVED -> CLOSED avec is_active=False: OK")
    return True


def check_forbidden_transition(db, analyst: Utilisateur) -> bool:
    alert = create_test_alert(db, "FORBIDDEN")
    try:
        close_alert_treatment(db, alert.id, analyst)
    except AlertTreatmentError:
        db.refresh(alert)
        if alert.status == AlertStatus.NEW and count_treatments(db, alert.id) == 0:
            print("Test 5 transition interdite: OK")
            return True
        print("Test 5 transition interdite: FAILED")
        return False

    print("Test 5 transition interdite: FAILED")
    return False


def check_history_is_preserved(db, analyst: Utilisateur) -> bool:
    alert = create_test_alert(db, "HISTORY")
    start_alert_treatment(db, alert.id, analyst)
    add_alert_comment(db, alert.id, analyst, "Observation conservee.")
    resolve_alert_treatment(db, alert.id, analyst)
    close_alert_treatment(db, alert.id, analyst)

    history = get_alert_treatment_history(db, alert.id)
    actions = [item.action_type for item in history]
    if (
        len(history) != 4
        or AlertTreatmentActionType.STARTED not in actions
        or AlertTreatmentActionType.COMMENTED not in actions
        or AlertTreatmentActionType.RESOLVED not in actions
        or AlertTreatmentActionType.CLOSED not in actions
    ):
        print("Test 6 historique conserve: FAILED")
        return False

    print("Test 6 historique conserve: OK")
    return True


def check_permissions(
    db,
    admin: Utilisateur,
    analyst: Utilisateur,
) -> bool:
    admin_alert = create_test_alert(db, "PERM-ADMIN")
    analyst_alert = create_test_alert(db, "PERM-ANALYST")
    inactive_user = create_test_user(db, RoleUtilisateur.ANALYSTE, active=False)

    start_alert_treatment(db, admin_alert.id, admin)
    start_alert_treatment(db, analyst_alert.id, analyst)

    try:
        add_alert_comment(db, analyst_alert.id, inactive_user, "Ne doit pas passer.")
    except AlertTreatmentError:
        print("Test 7 permissions ADMIN / ANALYSTE: OK")
        return True

    print("Test 7 permissions ADMIN / ANALYSTE: FAILED")
    return False


def check_rollback_on_error(db) -> bool:
    alert = create_test_alert(db, "ROLLBACK")
    fake_user = Utilisateur(
        id=f"missing-{uuid4()}",
        nom="Fake Analyst",
        email=f"fake-{uuid4().hex}@example.test",
        mot_de_passe_hash="not-used",
        role=RoleUtilisateur.ANALYSTE,
        actif=True,
    )

    nested = db.begin_nested()
    try:
        start_alert_treatment(db, alert.id, fake_user)
    except SQLAlchemyError:
        nested.rollback()
        db.refresh(alert)
        if alert.status != AlertStatus.NEW or count_treatments(db, alert.id) != 0:
            print("Test 8 rollback sur erreur: FAILED")
            return False
        print("Test 8 rollback sur erreur: OK")
        return True
    else:
        nested.rollback()
        print("Test 8 rollback sur erreur: FAILED")
        return False


def create_test_alert(db, suffix: str) -> Alert:
    token = uuid4().hex[:8].upper()
    asset = Asset(
        name=f"TEST-TREATMENT-{suffix}-{token}",
        asset_type=AssetType.APPLICATION,
        vendor="TreatmentVendor",
        product="TreatmentProduct",
        product_version="1.0.0",
        criticality=AssetCriticality.HIGH,
        environment=AssetEnvironment.PRODUCTION,
        is_active=True,
    )
    vulnerability = Vulnerability(
        cve_id=f"CVE-2096-{token[:4]}",
        description="Vulnerabilite de test pour traitement analyste.",
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
        reason="Correlation MATCH de test pour traitement analyste.",
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


def create_test_user(
    db,
    role: RoleUtilisateur,
    active: bool = True,
) -> Utilisateur:
    token = uuid4().hex
    user = Utilisateur(
        nom=f"TEST {role.value} {token[:6]}",
        email=f"test-{role.value.lower()}-{token}@example.test",
        mot_de_passe_hash="not-used",
        role=role,
        actif=active,
    )
    db.add(user)
    db.flush()
    return user


def latest_treatment(db, alert_id: str) -> AlertTreatment | None:
    return db.execute(
        select(AlertTreatment)
        .where(AlertTreatment.alert_id == alert_id)
        .order_by(AlertTreatment.created_at.desc(), AlertTreatment.id.desc())
        .limit(1)
    ).scalar_one_or_none()


def count_treatments(db, alert_id: str) -> int:
    return (
        db.scalar(
            select(func.count(AlertTreatment.id)).where(AlertTreatment.alert_id == alert_id)
        )
        or 0
    )


def utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


if __name__ == "__main__":
    raise SystemExit(main())
