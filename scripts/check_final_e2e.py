"""
Verification E2E finale de ThreatWatch.

Scenario controle avec rollback :
Asset -> Vulnerability -> MATCH -> Correlation -> Alert -> Priority ->
Notification IN_APP -> EMAIL sans reseau -> Treatment -> CLOSED.
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

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.core.config import settings  # noqa: E402
from app.db.database import SessionLocal, engine, get_safe_database_url, test_database_connection  # noqa: E402
from app.models.alert import Alert, AlertPriority, AlertStatus  # noqa: E402
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
)
from app.models.user import RoleUtilisateur, Utilisateur  # noqa: E402
from app.models.vulnerability import EnrichmentStatus, Vulnerability  # noqa: E402
from app.models.vulnerability_affected_product import VulnerabilityAffectedProduct  # noqa: E402
from app.services.analyst_treatment_service import (  # noqa: E402
    add_alert_comment,
    close_alert_treatment,
    resolve_alert_treatment,
    start_alert_treatment,
)
from app.services.correlation_persistence_service import (  # noqa: E402
    evaluate_and_persist_asset_vulnerability,
)
from app.services.correlation_service import CorrelationStatus  # noqa: E402


COUNTED_TABLES = {
    "assets": Asset,
    "vulnerabilities": Vulnerability,
    "correlations": AssetVulnerabilityCorrelation,
    "alerts": Alert,
    "notifications": Notification,
    "treatments": AlertTreatment,
    "users": Utilisateur,
}


def main() -> int:
    print(f"Verification E2E finale avec DATABASE_URL={get_safe_database_url()}")
    original_smtp_enabled = settings.SMTP_ENABLED

    try:
        test_database_connection()
        initial_counts = count_objects()
        settings.SMTP_ENABLED = False

        connection = engine.connect()
        transaction = connection.begin()
        db = Session(bind=connection, join_transaction_mode="create_savepoint")
        try:
            checks = [check_complete_soc_chain(db)]
            db.close()
            transaction.rollback()
        finally:
            connection.close()
            settings.SMTP_ENABLED = original_smtp_enabled

        if count_objects() != initial_counts:
            print("Rollback final E2E: FAILED")
            return 1
        if not all(checks):
            return 1

        print("Rollback final E2E: OK")
        print("THREATWATCH FINAL E2E: OK")
        return 0
    except SQLAlchemyError as exc:
        settings.SMTP_ENABLED = original_smtp_enabled
        print(f"ERREUR SQLAlchemy: {exc}")
        return 1
    except RuntimeError as exc:
        settings.SMTP_ENABLED = original_smtp_enabled
        print(f"ERREUR: {exc}")
        return 1


def check_complete_soc_chain(db: Session) -> bool:
    analyst = create_test_user(db)
    asset, vulnerability = create_asset_vulnerability_pair(db)
    result = evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    correlation = find_correlation(db, asset.id, vulnerability.id)
    alert = find_alert(db, correlation.id if correlation else "")

    if (
        result.status != CorrelationStatus.MATCH
        or correlation is None
        or correlation.status != CorrelationPersistenceStatus.MATCH
        or alert is None
        or alert.priority_level not in {AlertPriority.HIGH, AlertPriority.CRITICAL}
    ):
        print("Chaine Asset -> Correlation -> Alert -> Priority: FAILED")
        return False

    in_app = find_notification(db, alert.id, NotificationChannel.IN_APP)
    email = find_notification(db, alert.id, NotificationChannel.EMAIL)
    if (
        in_app is None
        or in_app.status != NotificationStatus.SENT
        or email is None
        or email.status != NotificationStatus.PENDING
    ):
        print("Notifications IN_APP + EMAIL sans reseau: FAILED")
        return False

    start_alert_treatment(db, alert.id, analyst, "Prise en charge E2E.")
    add_alert_comment(db, alert.id, analyst, "Analyse controlee E2E.")
    resolve_alert_treatment(db, alert.id, analyst, "Correction verifiee E2E.")
    close_alert_treatment(db, alert.id, analyst, "Cloture finale E2E.")
    db.refresh(alert)

    actions = list_treatment_actions(db, alert.id)
    expected_actions = [
        AlertTreatmentActionType.STARTED,
        AlertTreatmentActionType.COMMENTED,
        AlertTreatmentActionType.RESOLVED,
        AlertTreatmentActionType.CLOSED,
    ]
    if (
        alert.status != AlertStatus.CLOSED
        or alert.is_active is not False
        or actions != expected_actions
    ):
        print("Traitement analyste jusqu'a CLOSED: FAILED")
        return False

    print("Chaine Asset -> Correlation -> Alert -> Priority: OK")
    print("Notifications IN_APP + EMAIL sans reseau: OK")
    print("Traitement analyste jusqu'a CLOSED: OK")
    return True


def create_asset_vulnerability_pair(db: Session) -> tuple[Asset, Vulnerability]:
    token = uuid4().hex[:8].upper()
    asset = Asset(
        name=f"TEST-FINAL-E2E-ASSET-{token}",
        asset_type=AssetType.APPLICATION,
        vendor="FinalVendor",
        product="FinalProduct",
        product_version="1.5.0",
        criticality=AssetCriticality.CRITICAL,
        environment=AssetEnvironment.PRODUCTION,
        cpe="cpe:2.3:a:finalvendor:finalproduct:1.5.0:*:*:*:*:*:*:*",
        is_active=True,
    )
    vulnerability = Vulnerability(
        cve_id=f"CVE-2099-{1000 + (uuid4().int % 8999)}",
        description="Vulnerabilite temporaire pour validation E2E finale.",
        cvss_score=Decimal("9.8"),
        cvss_severity="CRITICAL",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_version="3.1",
        enrichment_status=EnrichmentStatus.SUCCESS,
        enrichment_source="TEST",
        last_enrichment_at=utcnow_naive(),
    )
    affected_product = VulnerabilityAffectedProduct(
        cpe="cpe:2.3:a:finalvendor:finalproduct:*:*:*:*:*:*:*:*",
        cpe_part="a",
        vendor="FinalVendor",
        product="FinalProduct",
        version="*",
        version_start_including="1.0.0",
        version_start_excluding="",
        version_end_including="",
        version_end_excluding="2.0.0",
        vulnerable=True,
    )
    vulnerability.affected_products.append(affected_product)
    db.add_all([asset, vulnerability])
    db.flush()
    return asset, vulnerability


def create_test_user(db: Session) -> Utilisateur:
    token = uuid4().hex
    user = Utilisateur(
        nom=f"TEST FINAL ANALYSTE {token[:6]}",
        email=f"test-final-analyste-{token}@example.test",
        mot_de_passe_hash="not-used",
        role=RoleUtilisateur.ANALYSTE,
        actif=True,
    )
    db.add(user)
    db.flush()
    return user


def find_correlation(
    db: Session,
    asset_id: str,
    vulnerability_id: str,
) -> AssetVulnerabilityCorrelation | None:
    return db.execute(
        select(AssetVulnerabilityCorrelation).where(
            AssetVulnerabilityCorrelation.asset_id == asset_id,
            AssetVulnerabilityCorrelation.vulnerability_id == vulnerability_id,
        )
    ).scalar_one_or_none()


def find_alert(db: Session, correlation_id: str) -> Alert | None:
    return db.execute(
        select(Alert).where(Alert.correlation_id == correlation_id)
    ).scalar_one_or_none()


def find_notification(
    db: Session,
    alert_id: str,
    channel: NotificationChannel,
) -> Notification | None:
    return db.execute(
        select(Notification).where(
            Notification.alert_id == alert_id,
            Notification.channel == channel,
        )
    ).scalar_one_or_none()


def list_treatment_actions(
    db: Session,
    alert_id: str,
) -> list[AlertTreatmentActionType]:
    return list(
        db.execute(
            select(AlertTreatment.action_type)
            .where(AlertTreatment.alert_id == alert_id)
            .order_by(AlertTreatment.created_at.asc(), AlertTreatment.id.asc())
        ).scalars()
    )


def count_objects() -> dict[str, int]:
    with SessionLocal() as db:
        return {
            name: db.scalar(select(func.count(model.id))) or 0
            for name, model in COUNTED_TABLES.items()
        }


def utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


if __name__ == "__main__":
    raise SystemExit(main())
