"""
Verification locale de la phase 5.2.

Le script controle le calcul de priorite SOC des alertes. Les colonnes ajoutees
a la table alerts sont migrees de facon additive si elles manquent; les donnees
de test sont annulees par rollback final.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

from sqlalchemy import inspect, text
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
from app.models.alert import AlertPriority, AlertSeverity  # noqa: E402
from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType  # noqa: E402
from app.models.asset_vulnerability_correlation import (  # noqa: E402
    AssetVulnerabilityCorrelation,
    CorrelationPersistenceStatus,
)
from app.models.vulnerability import EnrichmentStatus, Vulnerability  # noqa: E402
from app.services.alert_priority_service import calculate_alert_priority  # noqa: E402
from app.services.alert_service import create_alert_from_correlation  # noqa: E402


EXPECTED_PRIORITY_COLUMNS = {
    "priority_score",
    "priority_level",
    "priority_reason",
}


def main() -> int:
    print(
        "Verification phase 5.2 priorite SOC avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        create_database_tables()
        ensure_alert_priority_columns()
        if not check_priority_columns():
            return 1

        with SessionLocal() as db:
            try:
                checks = [
                    check_case_critical_priority(db),
                    check_case_high_priority(db),
                    check_case_low_priority(db),
                    check_case_missing_cvss(db),
                    check_recalculation(db),
                ]
                if not all(checks):
                    return 1
            finally:
                db.rollback()

        print("PHASE 5.2 PRIORITY CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR SQLAlchemy: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def ensure_alert_priority_columns() -> None:
    inspector = inspect(engine)
    if "alerts" not in set(inspector.get_table_names()):
        return

    columns = {column["name"] for column in inspector.get_columns("alerts")}
    missing = EXPECTED_PRIORITY_COLUMNS - columns
    if not missing:
        return

    dialect = engine.dialect.name
    with engine.begin() as connection:
        if dialect == "postgresql":
            connection.execute(
                text(
                    """
                    DO $$
                    BEGIN
                        CREATE TYPE alert_priority AS ENUM (
                            'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
                        );
                    EXCEPTION
                        WHEN duplicate_object THEN NULL;
                    END $$;
                    """
                )
            )
            if "priority_score" in missing:
                connection.execute(
                    text(
                        "ALTER TABLE alerts "
                        "ADD COLUMN IF NOT EXISTS priority_score "
                        "NUMERIC(5, 2) NOT NULL DEFAULT 0.00"
                    )
                )
            if "priority_level" in missing:
                connection.execute(
                    text(
                        "ALTER TABLE alerts "
                        "ADD COLUMN IF NOT EXISTS priority_level "
                        "alert_priority NOT NULL DEFAULT 'LOW'"
                    )
                )
            if "priority_reason" in missing:
                connection.execute(
                    text(
                        "ALTER TABLE alerts "
                        "ADD COLUMN IF NOT EXISTS priority_reason TEXT"
                    )
                )
        elif dialect == "sqlite":
            if "priority_score" in missing:
                connection.execute(
                    text(
                        "ALTER TABLE alerts "
                        "ADD COLUMN priority_score NUMERIC(5, 2) "
                        "NOT NULL DEFAULT 0.00"
                    )
                )
            if "priority_level" in missing:
                connection.execute(
                    text(
                        "ALTER TABLE alerts "
                        "ADD COLUMN priority_level VARCHAR(20) "
                        "NOT NULL DEFAULT 'LOW'"
                    )
                )
            if "priority_reason" in missing:
                connection.execute(
                    text("ALTER TABLE alerts ADD COLUMN priority_reason TEXT")
                )
        else:
            raise RuntimeError(
                f"Dialecte non supporte pour la migration additive: {dialect}"
            )

    print(
        "Alert priority columns added: "
        + ", ".join(sorted(missing))
    )


def check_priority_columns() -> bool:
    inspector = inspect(engine)
    columns = {column["name"] for column in inspector.get_columns("alerts")}
    missing = EXPECTED_PRIORITY_COLUMNS - columns
    if missing:
        print(
            "Alert priority columns: MANQUANTES "
            + ", ".join(sorted(missing))
        )
        return False

    print("Alert priority columns: OK")
    return True


def check_case_critical_priority(db) -> bool:
    alert = create_priority_test_alert(
        db=db,
        suffix="CRITICAL",
        cvss_score=Decimal("9.8"),
        cvss_severity="CRITICAL",
        criticality=AssetCriticality.CRITICAL,
        environment=AssetEnvironment.PRODUCTION,
    )
    if (
        alert.priority_level != AlertPriority.CRITICAL
        or alert.priority_score != Decimal("99.00")
        or alert.severity != AlertSeverity.CRITICAL
    ):
        print("Cas 1 priorite CRITICAL: FAILED")
        return False

    print("Cas 1 priorite CRITICAL: OK")
    return True


def check_case_high_priority(db) -> bool:
    alert = create_priority_test_alert(
        db=db,
        suffix="HIGH",
        cvss_score=Decimal("7.5"),
        cvss_severity="HIGH",
        criticality=AssetCriticality.HIGH,
        environment=AssetEnvironment.PRODUCTION,
    )
    if alert.priority_level != AlertPriority.HIGH or alert.priority_score != Decimal("77.50"):
        print("Cas 2 priorite HIGH: FAILED")
        return False

    print("Cas 2 priorite HIGH: OK")
    return True


def check_case_low_priority(db) -> bool:
    alert = create_priority_test_alert(
        db=db,
        suffix="LOW",
        cvss_score=Decimal("4.1"),
        cvss_severity="MEDIUM",
        criticality=AssetCriticality.LOW,
        environment=AssetEnvironment.TEST,
    )
    if alert.priority_level != AlertPriority.LOW or alert.priority_score != Decimal("32.50"):
        print("Cas 3 priorite LOW: FAILED")
        return False

    print("Cas 3 priorite LOW: OK")
    return True


def check_case_missing_cvss(db) -> bool:
    alert = create_priority_test_alert(
        db=db,
        suffix="CVSS-NULL",
        cvss_score=None,
        cvss_severity=None,
        criticality=AssetCriticality.CRITICAL,
        environment=AssetEnvironment.PRODUCTION,
    )
    if (
        alert.priority_level != AlertPriority.HIGH
        or alert.priority_score != Decimal("65.00")
        or alert.severity != AlertSeverity.MEDIUM
        or "CVSS absent" not in (alert.priority_reason or "")
    ):
        print("Cas 4 CVSS absent: FAILED")
        return False

    print("Cas 4 CVSS absent: OK")
    return True


def check_recalculation(db) -> bool:
    asset, vulnerability, correlation = create_priority_test_context(
        db=db,
        suffix="RECALC",
        cvss_score=Decimal("4.1"),
        cvss_severity="MEDIUM",
        criticality=AssetCriticality.LOW,
        environment=AssetEnvironment.TEST,
    )
    alert = create_alert_from_correlation(db, correlation.id)
    initial_score = alert.priority_score
    initial_level = alert.priority_level

    asset.criticality = AssetCriticality.CRITICAL
    asset.environment = AssetEnvironment.PRODUCTION
    recalculated_alert = create_alert_from_correlation(db, correlation.id)

    if recalculated_alert.id != alert.id:
        print("Cas 5 recalcul: FAILED (doublon)")
        return False
    if recalculated_alert.priority_score == initial_score:
        print("Cas 5 recalcul: FAILED (score inchange)")
        return False
    if (
        initial_level != AlertPriority.LOW
        or recalculated_alert.priority_level != AlertPriority.HIGH
    ):
        print("Cas 5 recalcul: FAILED (niveau inattendu)")
        return False

    direct_result = calculate_alert_priority(asset, vulnerability, correlation)
    if recalculated_alert.priority_score != direct_result.score:
        print("Cas 5 recalcul: FAILED (service incoherent)")
        return False

    print("Cas 5 recalcul criticite/environnement: OK")
    return True


def create_priority_test_alert(
    *,
    db,
    suffix: str,
    cvss_score: Decimal | None,
    cvss_severity: str | None,
    criticality: AssetCriticality,
    environment: AssetEnvironment,
):
    _asset, _vulnerability, correlation = create_priority_test_context(
        db=db,
        suffix=suffix,
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        criticality=criticality,
        environment=environment,
    )
    alert = create_alert_from_correlation(db, correlation.id)
    if alert is None:
        raise RuntimeError("Alerte non creee depuis une correlation MATCH")
    return alert


def create_priority_test_context(
    *,
    db,
    suffix: str,
    cvss_score: Decimal | None,
    cvss_severity: str | None,
    criticality: AssetCriticality,
    environment: AssetEnvironment,
) -> tuple[Asset, Vulnerability, AssetVulnerabilityCorrelation]:
    token = uuid4().hex[:8].upper()
    asset = Asset(
        name=f"TEST-PRIORITY-{suffix}-{token}",
        asset_type=AssetType.APPLICATION,
        vendor="PriorityVendor",
        product="PriorityProduct",
        product_version="1.0.0",
        criticality=criticality,
        environment=environment,
        is_active=True,
    )
    vulnerability = Vulnerability(
        cve_id=f"CVE-2099-{token[:4]}",
        description="Vulnerabilite de test pour la priorisation SOC.",
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        enrichment_status=EnrichmentStatus.SUCCESS,
    )
    db.add_all([asset, vulnerability])
    db.flush()

    correlation = AssetVulnerabilityCorrelation(
        asset_id=asset.id,
        vulnerability_id=vulnerability.id,
        status=CorrelationPersistenceStatus.MATCH,
        reason="Correlation MATCH de test pour priorite SOC.",
        first_detected_at=utcnow_naive(),
        last_evaluated_at=utcnow_naive(),
        is_active=True,
    )
    db.add(correlation)
    db.flush()
    return asset, vulnerability, correlation


def utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


if __name__ == "__main__":
    raise SystemExit(main())
