"""
Supprime uniquement la chaine de demonstration DEMO-NETTY-01.

Ne supprime jamais CVE-2025-58057, la Vulnerability ni ses affected products.
"""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import delete, select

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, get_safe_database_url, test_database_connection  # noqa: E402
from app.models.alert import Alert  # noqa: E402
from app.models.alert_treatment import AlertTreatment  # noqa: E402
from app.models.asset import Asset  # noqa: E402
from app.models.asset_vulnerability_correlation import AssetVulnerabilityCorrelation  # noqa: E402
from app.models.notification import Notification  # noqa: E402
from app.models.vulnerability import Vulnerability  # noqa: E402


DEMO_ASSET_NAME = "DEMO-NETTY-01"
DEMO_CVE_ID = "CVE-2025-58057"


def main() -> int:
    print("Nettoyage controle de la chaine demo ThreatWatch")
    print(f"DATABASE_URL={get_safe_database_url()}")
    print(f"Cible asset: {DEMO_ASSET_NAME}")
    print(f"CVE conservee: {DEMO_CVE_ID}")

    try:
        test_database_connection()
        with SessionLocal() as db:
            try:
                assets = (
                    db.execute(select(Asset).where(Asset.name == DEMO_ASSET_NAME))
                    .scalars()
                    .all()
                )
                if not assets:
                    print("\nAucune donnee demo a supprimer.")
                    return 0

                vulnerability = db.execute(
                    select(Vulnerability).where(Vulnerability.cve_id == DEMO_CVE_ID)
                ).scalar_one_or_none()

                deletion_plan = build_deletion_plan(db, assets, vulnerability)
                print_plan(deletion_plan)

                delete_plan(db, deletion_plan)
                db.commit()
                print("\nCLEANUP DEMO COMMIT OK")
                print("Vulnerability et affected products NVD conserves.")
                return 0
            except Exception as exc:
                db.rollback()
                print("\nERREUR: nettoyage annule, rollback effectue.")
                print(str(exc))
                return 1
    except Exception as exc:
        print(f"ERREUR: {exc}")
        return 1


def build_deletion_plan(db, assets: list[Asset], vulnerability: Vulnerability | None):
    asset_ids = [asset.id for asset in assets]
    if vulnerability is None:
        correlations = []
    else:
        correlations = (
            db.execute(
                select(AssetVulnerabilityCorrelation).where(
                    AssetVulnerabilityCorrelation.asset_id.in_(asset_ids),
                    AssetVulnerabilityCorrelation.vulnerability_id == vulnerability.id,
                )
            )
            .scalars()
            .all()
        )

    correlation_ids = [correlation.id for correlation in correlations]
    alerts = []
    if correlation_ids:
        alerts = (
            db.execute(select(Alert).where(Alert.correlation_id.in_(correlation_ids)))
            .scalars()
            .all()
        )

    alert_ids = [alert.id for alert in alerts]
    notifications = []
    treatments = []
    if alert_ids:
        notifications = (
            db.execute(select(Notification).where(Notification.alert_id.in_(alert_ids)))
            .scalars()
            .all()
        )
        treatments = (
            db.execute(select(AlertTreatment).where(AlertTreatment.alert_id.in_(alert_ids)))
            .scalars()
            .all()
        )

    remaining_correlations = (
        db.execute(
            select(AssetVulnerabilityCorrelation).where(
                AssetVulnerabilityCorrelation.asset_id.in_(asset_ids),
                ~AssetVulnerabilityCorrelation.id.in_(correlation_ids or [""]),
            )
        )
        .scalars()
        .all()
    )
    if remaining_correlations:
        raise RuntimeError(
            "L'actif demo porte d'autres correlations que la chaine CVE-2025-58057. "
            "Nettoyage automatique refuse pour eviter une suppression hors perimetre."
        )

    return {
        "assets": assets,
        "vulnerability": vulnerability,
        "correlations": correlations,
        "alerts": alerts,
        "notifications": notifications,
        "treatments": treatments,
    }


def print_plan(plan: dict) -> None:
    print("\nElements qui seront supprimes")
    print_ids("Notifications", plan["notifications"])
    print_ids("Traitements alerte demo", plan["treatments"])
    print_ids("Alertes", plan["alerts"])
    print_ids("Correlations", plan["correlations"])
    print_ids("Assets", plan["assets"])
    print("\nElements conserves")
    if plan["vulnerability"] is not None:
        print(f"Vulnerability: {plan['vulnerability'].cve_id} ({plan['vulnerability'].id})")
    else:
        print(f"Vulnerability: {DEMO_CVE_ID} introuvable, rien a supprimer cote CVE")
    print("Affected products NVD: conserves")


def print_ids(label: str, rows: list) -> None:
    if not rows:
        print(f"- {label}: 0")
        return
    print(f"- {label}: {len(rows)}")
    for row in rows:
        print(f"  {row.id}")


def delete_plan(db, plan: dict) -> None:
    bulk_delete(db, Notification, plan["notifications"])
    bulk_delete(db, AlertTreatment, plan["treatments"])
    bulk_delete(db, Alert, plan["alerts"])
    bulk_delete(db, AssetVulnerabilityCorrelation, plan["correlations"])
    bulk_delete(db, Asset, plan["assets"])


def bulk_delete(db, model, rows: list) -> None:
    ids = [row.id for row in rows]
    if ids:
        db.execute(delete(model).where(model.id.in_(ids)))


if __name__ == "__main__":
    raise SystemExit(main())
