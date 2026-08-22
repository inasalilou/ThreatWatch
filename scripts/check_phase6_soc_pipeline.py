"""
Verification locale de la phase 6.6.1 Pipeline SOC.

Le test utilise un client NVD mocke et une transaction globale annulee a la fin.
Il ne lance aucun appel reseau et ne persiste aucune donnee de test.
"""
from __future__ import annotations

import sys
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

from sqlalchemy import func, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.core.config import settings  # noqa: E402
from app.db.database import SessionLocal, engine, get_safe_database_url, test_database_connection  # noqa: E402
from app.models.alert import Alert, AlertPriority  # noqa: E402
from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType  # noqa: E402
from app.models.asset_vulnerability_correlation import (  # noqa: E402
    AssetVulnerabilityCorrelation,
    CorrelationPersistenceStatus,
)
from app.models.notification import Notification, NotificationChannel  # noqa: E402
from app.models.vulnerability import EnrichmentStatus, Vulnerability  # noqa: E402
from app.services.nvd_client import NVDClientError  # noqa: E402
from app.services.soc_orchestration_service import process_pending_security_pipeline  # noqa: E402


def main() -> int:
    print(
        "Verification phase 6.6.1 pipeline SOC avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        initial_counts = count_persistent_objects()
        connection = engine.connect()
        transaction = connection.begin()
        db = Session(bind=connection, join_transaction_mode="create_savepoint")
        original_smtp_enabled = settings.SMTP_ENABLED
        try:
            settings.SMTP_ENABLED = False
            silence_existing_pending(db)
            checks = [
                check_zero_pending(db),
                check_match_alert_notification_and_idempotence(db),
                check_no_match_no_alert(db),
                check_possible_match_no_alert(db),
                check_nvd_error_continues(db),
            ]
            db.close()
            transaction.rollback()
        finally:
            settings.SMTP_ENABLED = original_smtp_enabled
            connection.close()

        if count_persistent_objects() != initial_counts:
            print("Rollback final pipeline SOC: FAILED")
            return 1
        if not all(checks):
            return 1

        print("Rollback final pipeline SOC: OK")
        print("PHASE 6.6.1 SOC PIPELINE CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR SQLAlchemy: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def check_zero_pending(db: Session) -> bool:
    client = MockNVDClient({})
    result = process_pending_security_pipeline(
        db,
        limit=5,
        request_delay_seconds=0,
        client=client,
        sleep_func=lambda seconds: None,
        force_enabled=True,
    )
    if result.selected_vulnerabilities != 0 or client.calls:
        print("0 PENDING -> sortie propre: FAILED")
        return False
    print("0 PENDING -> sortie propre: OK")
    return True


def check_match_alert_notification_and_idempotence(db: Session) -> bool:
    cve_id = unique_cve_id()
    cpe = "cpe:2.3:a:pipelinevendor:pipelineproduct:1.0:*:*:*:*:*:*:*"
    asset = create_asset(
        db,
        name="TEST-PIPELINE-MATCH-ASSET",
        vendor="pipelinevendor",
        product="pipelineproduct",
        version="1.0",
        cpe=cpe,
        criticality=AssetCriticality.CRITICAL,
    )
    vulnerability = create_pending_vulnerability(db, cve_id)
    client = MockNVDClient({cve_id: build_nvd_response(cve_id, cpe, cvss_score="9.8")})

    result = process_pending_security_pipeline(
        db,
        limit=1,
        request_delay_seconds=0,
        client=client,
        sleep_func=lambda seconds: None,
        force_enabled=True,
    )
    db.refresh(vulnerability)

    correlation = get_correlation(db, asset.id, vulnerability.id)
    alert = get_alert_for_correlation(db, correlation.id if correlation else "")
    in_app = get_notification(db, alert.id if alert else "", NotificationChannel.IN_APP)
    email = get_notification(db, alert.id if alert else "", NotificationChannel.EMAIL)

    second = process_pending_security_pipeline(
        db,
        limit=1,
        request_delay_seconds=0,
        client=client,
        sleep_func=lambda seconds: None,
        force_enabled=True,
    )

    if (
        result.selected_vulnerabilities != 1
        or client.calls.count(cve_id) != 1
        or vulnerability.enrichment_status != EnrichmentStatus.SUCCESS
        or correlation is None
        or correlation.status != CorrelationPersistenceStatus.MATCH
        or alert is None
        or alert.priority_level not in {AlertPriority.HIGH, AlertPriority.CRITICAL}
        or in_app is None
        or email is None
        or second.selected_vulnerabilities != 0
        or count_alerts_for_vulnerability(db, vulnerability.id) != 1
        or count_notifications_for_alert(db, alert.id) != 2
    ):
        print("MATCH -> correlation/alerte/notifications/idempotence: FAILED")
        return False

    print("Mock NVD SUCCESS -> enrichissement appele: OK")
    print("SUCCESS + actif correspondant -> MATCH: OK")
    print("MATCH -> correlation persistee: OK")
    print("MATCH -> alerte et priorite SOC: OK")
    print("Notifications IN_APP/EMAIL preparees: OK")
    print("Idempotence sans doublons: OK")
    return True


def check_no_match_no_alert(db: Session) -> bool:
    cve_id = unique_cve_id()
    cpe = "cpe:2.3:a:nomatchvendor:nomatchproduct:2.0:*:*:*:*:*:*:*"
    vulnerability = create_pending_vulnerability(db, cve_id)
    client = MockNVDClient({cve_id: build_nvd_response(cve_id, cpe, cvss_score="7.5")})

    result = process_pending_security_pipeline(
        db,
        limit=1,
        request_delay_seconds=0,
        client=client,
        sleep_func=lambda seconds: None,
        force_enabled=True,
    )

    if result.selected_vulnerabilities != 1 or count_alerts_for_vulnerability(db, vulnerability.id) != 0:
        print("NO_MATCH -> aucune alerte: FAILED")
        return False

    print("NO_MATCH -> aucune alerte: OK")
    return True


def check_possible_match_no_alert(db: Session) -> bool:
    cve_id = unique_cve_id()
    cpe = "cpe:2.3:a:possiblevendor:possibleproduct:2.0:*:*:*:*:*:*:*"
    asset = create_asset(
        db,
        name="TEST-PIPELINE-POSSIBLE-ASSET",
        vendor="possiblevendor",
        product="possibleproduct",
        version=None,
        cpe=None,
        criticality=AssetCriticality.HIGH,
    )
    vulnerability = create_pending_vulnerability(db, cve_id)
    client = MockNVDClient({cve_id: build_nvd_response(cve_id, cpe, cvss_score="8.0")})

    result = process_pending_security_pipeline(
        db,
        limit=1,
        request_delay_seconds=0,
        client=client,
        sleep_func=lambda seconds: None,
        force_enabled=True,
    )
    correlation = get_correlation(db, asset.id, vulnerability.id)

    if (
        result.selected_vulnerabilities != 1
        or correlation is None
        or correlation.status != CorrelationPersistenceStatus.POSSIBLE_MATCH
        or count_alerts_for_vulnerability(db, vulnerability.id) != 0
    ):
        print("POSSIBLE_MATCH -> aucune alerte: FAILED")
        return False

    print("POSSIBLE_MATCH -> correlation sans alerte: OK")
    return True


def check_nvd_error_continues(db: Session) -> bool:
    failing_cve = unique_cve_id()
    success_cve = unique_cve_id()
    success_cpe = "cpe:2.3:a:errorcontinuevendor:errorcontinueproduct:1.0:*:*:*:*:*:*:*"
    create_pending_vulnerability(db, failing_cve)
    success_vulnerability = create_pending_vulnerability(db, success_cve)
    client = MockNVDClient(
        {success_cve: build_nvd_response(success_cve, success_cpe, cvss_score="5.0")},
        failures={failing_cve},
    )

    result = process_pending_security_pipeline(
        db,
        limit=2,
        request_delay_seconds=0,
        client=client,
        sleep_func=lambda seconds: None,
        force_enabled=True,
    )
    db.refresh(success_vulnerability)

    if (
        result.selected_vulnerabilities != 2
        or result.enriched_failed != 1
        or result.enriched_success != 1
        or success_vulnerability.enrichment_status != EnrichmentStatus.SUCCESS
    ):
        print("Erreur NVD -> suivante continue: FAILED")
        return False

    print("Erreur NVD -> suivante continue: OK")
    return True


class MockNVDClient:
    def __init__(self, responses: dict[str, dict], failures: set[str] | None = None):
        self.responses = responses
        self.failures = failures or set()
        self.calls: list[str] = []

    def fetch_cve(self, cve_id: str) -> dict:
        normalized = cve_id.strip().upper()
        self.calls.append(normalized)
        if normalized in self.failures:
            raise NVDClientError("Erreur NVD controlee")
        return self.responses.get(normalized, {"vulnerabilities": []})


def build_nvd_response(cve_id: str, cpe: str, *, cvss_score: str) -> dict:
    severity = "CRITICAL" if Decimal(cvss_score) >= Decimal("9.0") else "HIGH"
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": f"Pipeline SOC test vulnerability {cve_id}.",
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": float(cvss_score),
                                    "baseSeverity": severity,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                },
                            }
                        ]
                    },
                    "weaknesses": [
                        {"description": [{"lang": "en", "value": "CWE-79"}]}
                    ],
                    "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-01-02T00:00:00.000",
                    "references": [{"url": "https://example.test/pipeline"}],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": cpe,
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }


def silence_existing_pending(db: Session) -> None:
    db.execute(update(Vulnerability).values(enrichment_status=EnrichmentStatus.SUCCESS))
    db.flush()


def create_pending_vulnerability(db: Session, cve_id: str) -> Vulnerability:
    vulnerability = Vulnerability(
        cve_id=cve_id,
        enrichment_status=EnrichmentStatus.PENDING,
    )
    db.add(vulnerability)
    db.flush()
    return vulnerability


def create_asset(
    db: Session,
    *,
    name: str,
    vendor: str,
    product: str,
    version: str | None,
    cpe: str | None,
    criticality: AssetCriticality,
) -> Asset:
    asset = Asset(
        name=f"{name}-{uuid4().hex[:6]}",
        asset_type=AssetType.APPLICATION,
        vendor=vendor,
        product=product,
        product_version=version,
        cpe=cpe,
        criticality=criticality,
        environment=AssetEnvironment.PRODUCTION,
        is_active=True,
    )
    db.add(asset)
    db.flush()
    return asset


def get_correlation(
    db: Session,
    asset_id: str,
    vulnerability_id: str,
) -> AssetVulnerabilityCorrelation | None:
    return db.scalar(
        select(AssetVulnerabilityCorrelation).where(
            AssetVulnerabilityCorrelation.asset_id == asset_id,
            AssetVulnerabilityCorrelation.vulnerability_id == vulnerability_id,
        )
    )


def get_alert_for_correlation(db: Session, correlation_id: str) -> Alert | None:
    return db.scalar(select(Alert).where(Alert.correlation_id == correlation_id))


def get_notification(
    db: Session,
    alert_id: str,
    channel: NotificationChannel,
) -> Notification | None:
    return db.scalar(
        select(Notification).where(
            Notification.alert_id == alert_id,
            Notification.channel == channel,
        )
    )


def count_alerts_for_vulnerability(db: Session, vulnerability_id: str) -> int:
    return (
        db.scalar(select(func.count(Alert.id)).where(Alert.vulnerability_id == vulnerability_id))
        or 0
    )


def count_notifications_for_alert(db: Session, alert_id: str) -> int:
    return db.scalar(select(func.count(Notification.id)).where(Notification.alert_id == alert_id)) or 0


def count_persistent_objects() -> tuple[int, int, int, int, int]:
    with SessionLocal() as db:
        return (
            db.scalar(select(func.count(Vulnerability.id))) or 0,
            db.scalar(select(func.count(Asset.id))) or 0,
            db.scalar(select(func.count(AssetVulnerabilityCorrelation.id))) or 0,
            db.scalar(select(func.count(Alert.id))) or 0,
            db.scalar(select(func.count(Notification.id))) or 0,
        )


def unique_cve_id() -> str:
    return f"CVE-2096-{10000 + (uuid4().int % 89999)}"


if __name__ == "__main__":
    raise SystemExit(main())
