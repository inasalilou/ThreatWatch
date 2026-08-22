"""
Cree une seule chaine de demonstration ThreatWatch persistante.

Flux controle:
DEMO-NETTY-01 -> CVE-2025-58057 -> correlation MATCH -> alerte ->
priorite SOC -> notifications IN_APP/EMAIL.

Ce script commit uniquement apres validation complete. Il ne lance aucun batch
global et ne modifie aucune donnee hors de l'actif de demonstration.
"""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import selectinload

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.core.config import settings  # noqa: E402
from app.db.database import SessionLocal, get_safe_database_url, test_database_connection  # noqa: E402
from app.models.alert import Alert, AlertPriority, AlertStatus  # noqa: E402
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
from app.models.vulnerability import Vulnerability  # noqa: E402
from app.services.correlation_persistence_service import (  # noqa: E402
    evaluate_and_persist_asset_vulnerability,
)
from app.services.correlation_service import CorrelationStatus  # noqa: E402


DEMO_ASSET_NAME = "DEMO-NETTY-01"
DEMO_CVE_ID = "CVE-2025-58057"


def main() -> int:
    print("Creation controlee d'une chaine demo ThreatWatch")
    print(f"DATABASE_URL={get_safe_database_url()}")
    print(f"SMTP_ENABLED={settings.SMTP_ENABLED}")
    print(f"SOC_NOTIFICATION_EMAIL={'configure' if settings.SOC_NOTIFICATION_EMAIL else 'non configure'}")

    try:
        test_database_connection()
        with SessionLocal() as db:
            try:
                asset, asset_created = get_or_create_demo_asset(db)
                vulnerability = load_demo_vulnerability(db)

                print("\nEvaluation correlation")
                result = evaluate_and_persist_asset_vulnerability(
                    db,
                    asset,
                    vulnerability,
                )
                print(f"Resultat correlation: {result.status.value}")
                print(f"Raison: {result.reason}")
                if result.status != CorrelationStatus.MATCH:
                    raise RuntimeError(
                        "La chaine demo n'a pas produit MATCH. "
                        "Aucun commit effectue."
                    )

                correlation = get_demo_correlation(db, asset.id, vulnerability.id)
                alert = get_demo_alert(db, correlation.id if correlation else "")
                in_app = get_demo_notification(alert, NotificationChannel.IN_APP)
                email = get_demo_notification(alert, NotificationChannel.EMAIL)

                validate_chain(asset, vulnerability, correlation, alert, in_app, email)
                restore_demo_unread_state(in_app)

                db.commit()
                print_report(
                    asset=asset,
                    asset_created=asset_created,
                    vulnerability=vulnerability,
                    correlation=correlation,
                    alert=alert,
                    in_app=in_app,
                    email=email,
                )
                return 0
            except Exception as exc:
                db.rollback()
                print("\nERREUR: creation demo annulee, rollback effectue.")
                print(str(exc))
                return 1
    except Exception as exc:
        print(f"ERREUR: {exc}")
        return 1


def get_or_create_demo_asset(db) -> tuple[Asset, bool]:
    assets = (
        db.execute(select(Asset).where(Asset.name == DEMO_ASSET_NAME))
        .scalars()
        .all()
    )
    if len(assets) > 1:
        raise RuntimeError(
            f"Plusieurs actifs {DEMO_ASSET_NAME} existent. "
            "Nettoyez manuellement cette ambiguite avant de lancer la demo."
        )
    if assets:
        asset = assets[0]
        validate_existing_demo_asset(asset)
        print(f"Actif demo reutilise: {asset.name} ({asset.id})")
        return asset, False

    asset = Asset(
        name=DEMO_ASSET_NAME,
        asset_type=AssetType.APPLICATION,
        vendor="Netty",
        product="Netty",
        product_version="4.1.124",
        criticality=AssetCriticality.CRITICAL,
        environment=AssetEnvironment.PRODUCTION,
        is_active=True,
        description=(
            "Actif de demonstration ThreatWatch pour la chaine "
            "CVE-2025-58057 -> alerte -> notifications."
        ),
    )
    db.add(asset)
    db.flush()
    print(f"Actif demo cree: {asset.name} ({asset.id})")
    return asset, True


def validate_existing_demo_asset(asset: Asset) -> None:
    expected = {
        "asset_type": AssetType.APPLICATION,
        "vendor": "Netty",
        "product": "Netty",
        "product_version": "4.1.124",
        "criticality": AssetCriticality.CRITICAL,
        "environment": AssetEnvironment.PRODUCTION,
    }
    mismatches = [
        f"{field}={getattr(asset, field)!r}"
        for field, value in expected.items()
        if getattr(asset, field) != value
    ]
    if asset.is_active is not True:
        mismatches.append("is_active=False")
    if mismatches:
        raise RuntimeError(
            f"L'actif {DEMO_ASSET_NAME} existe mais ne correspond pas a la demo: "
            + ", ".join(mismatches)
            + ". Utilisez cleanup_demo_alert.py si c'est bien un ancien seed demo."
        )


def load_demo_vulnerability(db) -> Vulnerability:
    vulnerability = db.execute(
        select(Vulnerability)
        .options(selectinload(Vulnerability.affected_products))
        .where(Vulnerability.cve_id == DEMO_CVE_ID)
    ).scalar_one_or_none()
    if vulnerability is None:
        raise RuntimeError(
            f"{DEMO_CVE_ID} est absente de la base. Lancez d'abord l'enrichissement NVD."
        )
    vulnerable_products = [
        item for item in vulnerability.affected_products if item.vulnerable is True
    ]
    if not vulnerable_products:
        raise RuntimeError(
            f"{DEMO_CVE_ID} existe mais aucun affected product vulnerable n'est stocke."
        )
    print(
        f"Vulnerability reutilisee: {vulnerability.cve_id} "
        f"({len(vulnerable_products)} affected product(s) vulnerable(s))"
    )
    return vulnerability


def get_demo_correlation(
    db,
    asset_id: str,
    vulnerability_id: str,
) -> AssetVulnerabilityCorrelation | None:
    return db.execute(
        select(AssetVulnerabilityCorrelation).where(
            AssetVulnerabilityCorrelation.asset_id == asset_id,
            AssetVulnerabilityCorrelation.vulnerability_id == vulnerability_id,
        )
    ).scalar_one_or_none()


def get_demo_alert(db, correlation_id: str) -> Alert | None:
    return db.execute(
        select(Alert).where(Alert.correlation_id == correlation_id)
    ).scalar_one_or_none()


def get_demo_notification(
    alert: Alert | None,
    channel: NotificationChannel,
) -> Notification | None:
    if alert is None:
        return None
    for notification in alert.notifications:
        if notification.channel == channel:
            return notification
    return None


def validate_chain(
    asset: Asset,
    vulnerability: Vulnerability,
    correlation: AssetVulnerabilityCorrelation | None,
    alert: Alert | None,
    in_app: Notification | None,
    email: Notification | None,
) -> None:
    if correlation is None or correlation.status != CorrelationPersistenceStatus.MATCH:
        raise RuntimeError("Correlation MATCH non persistee.")
    if alert is None:
        raise RuntimeError("Alerte non creee depuis la correlation MATCH.")
    if alert.status != AlertStatus.NEW or alert.is_active is not True:
        raise RuntimeError(
            f"Alerte demo inattendue: status={alert.status.value}, active={alert.is_active}."
        )
    if alert.priority_level not in {AlertPriority.HIGH, AlertPriority.CRITICAL}:
        raise RuntimeError(
            f"Priorite SOC insuffisante pour demo: {alert.priority_level.value}."
        )
    if in_app is None:
        raise RuntimeError("Notification IN_APP non creee.")
    if in_app.status != NotificationStatus.SENT:
        raise RuntimeError("Notification IN_APP non disponible en statut SENT.")
    if email is None:
        raise RuntimeError("Notification EMAIL non creee.")
    if email.status not in {
        NotificationStatus.PENDING,
        NotificationStatus.SENT,
        NotificationStatus.FAILED,
    }:
        raise RuntimeError(f"Statut EMAIL inattendu: {email.status.value}.")
    if asset.name != DEMO_ASSET_NAME or vulnerability.cve_id != DEMO_CVE_ID:
        raise RuntimeError("La chaine validee ne correspond pas a la demo attendue.")


def restore_demo_unread_state(notification: Notification | None) -> None:
    if notification is None:
        return
    notification.is_read = False
    notification.read_at = None


def print_report(
    *,
    asset: Asset,
    asset_created: bool,
    vulnerability: Vulnerability,
    correlation: AssetVulnerabilityCorrelation,
    alert: Alert,
    in_app: Notification,
    email: Notification | None,
) -> None:
    print("\nDEMO COMMIT OK")
    print(f"Asset: {'cree' if asset_created else 'reutilise'}")
    print(f"Asset ID: {asset.id}")
    print(f"Vulnerability: {vulnerability.cve_id} (reutilisee)")
    print(f"Correlation ID: {correlation.id}")
    print(f"Correlation status: {correlation.status.value}")
    print(f"Alert ID: {alert.id}")
    print(f"Alert status: {alert.status.value}, active={alert.is_active}")
    print(f"Priority score: {alert.priority_score}")
    print(f"Priority level: {alert.priority_level.value}")
    print(f"Notification IN_APP ID: {in_app.id}")
    print(
        "Notification IN_APP: "
        f"status={in_app.status.value}, is_read={in_app.is_read}"
    )
    if email is not None:
        print(f"Notification EMAIL ID: {email.id}")
        print(f"Notification EMAIL: status={email.status.value}")
        if settings.SMTP_ENABLED and email.status != NotificationStatus.SENT:
            print(
                "SMTP est active mais l'email n'est pas SENT. "
                "Verifiez la configuration SMTP sans afficher le mot de passe."
            )

    print("\nPages a ouvrir")
    print(f"/assets/{asset.id}")
    print(f"/vulnerabilities/{vulnerability.cve_id}")
    print("/correlations")
    print("/alerts")
    print(f"/alerts/{alert.id}")
    print("/notifications")


if __name__ == "__main__":
    raise SystemExit(main())
