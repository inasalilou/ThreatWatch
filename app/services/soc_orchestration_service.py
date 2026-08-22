"""
Orchestration automatique SOC de bout en bout.

Ce service coordonne les briques existantes : enrichissement NVD, correlation,
persistance, alertes et notifications indirectes. Il ne recree pas la logique
metier deja portee par ces services.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models.alert import Alert
from app.models.asset import Asset
from app.models.asset_vulnerability_correlation import AssetVulnerabilityCorrelation
from app.models.notification import Notification
from app.models.vulnerability import EnrichmentStatus, Vulnerability
from app.services.correlation_persistence_service import (
    find_existing_correlation,
    persist_correlation_result,
)
from app.services.correlation_service import CorrelationStatus, evaluate_asset_vulnerability
from app.services.cve_enrichment_service import CveEnrichmentResult, enrich_single_cve
from app.services.nvd_client import NVDClient
from app.services.settings_service import get_effective_settings, initialize_default_settings

logger = logging.getLogger(__name__)


@dataclass
class SocPipelineResult:
    selected_vulnerabilities: int = 0
    enriched_success: int = 0
    enriched_not_found: int = 0
    enriched_failed: int = 0
    assets_checked: int = 0
    matches: int = 0
    possible_matches: int = 0
    no_matches: int = 0
    unknown: int = 0
    correlations_created: int = 0
    correlations_updated: int = 0
    alerts_created_or_updated: int = 0
    notifications_created_or_updated: int = 0
    errors: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None
    duration_seconds: float = 0.0
    disabled: bool = False


class SOCOrchestrationService:
    def __init__(
        self,
        db: Session,
        *,
        client: NVDClient | None = None,
        sleep_func: Callable[[float], None] = time.sleep,
    ):
        self.db = db
        self.client = client
        self.sleep_func = sleep_func

    def run_soc_pipeline(
        self,
        *,
        limit: int | None = None,
        request_delay_seconds: float | None = None,
        include_failed_retry: bool = False,
        force_enabled: bool = False,
    ) -> SocPipelineResult:
        result = SocPipelineResult()
        started_monotonic = time.monotonic()
        logger.info("[SOC Pipeline] Start")

        try:
            initialize_default_settings(self.db)
            self.db.commit()
            effective_settings = get_effective_settings(self.db)

            if not force_enabled and not effective_settings.get("SOC_PIPELINE_ENABLED", True):
                result.disabled = True
                logger.info("[SOC Pipeline] Disabled by settings")
                return finish_result(result, started_monotonic)

            batch_limit = safe_positive_int(
                limit if limit is not None else effective_settings.get("NVD_BATCH_SIZE"),
                default=5,
                maximum=100,
            )
            delay = safe_non_negative_float(
                request_delay_seconds
                if request_delay_seconds is not None
                else effective_settings.get("NVD_REQUEST_DELAY_SECONDS"),
                default=0.0,
            )

            vulnerabilities = select_vulnerabilities_to_process(
                self.db,
                limit=batch_limit,
                include_failed_retry=include_failed_retry,
            )
            result.selected_vulnerabilities = len(vulnerabilities)
            logger.info("[SOC Pipeline] %s CVE selected", len(vulnerabilities))

            for index, vulnerability in enumerate(vulnerabilities):
                self.process_single_vulnerability(vulnerability.cve_id, result)
                if delay > 0 and index < len(vulnerabilities) - 1:
                    logger.info("[SOC Pipeline] Waiting %.2f second(s) before next NVD call", delay)
                    self.sleep_func(delay)

            logger.info("[SOC Pipeline] Completed")
            return finish_result(result, started_monotonic)
        except Exception as exc:
            self.db.rollback()
            message = f"{exc.__class__.__name__}: {exc}"
            result.errors.append(message[:500])
            logger.exception("[SOC Pipeline] ERROR: %s", exc)
            return finish_result(result, started_monotonic)

    def process_single_vulnerability(
        self,
        cve_id: str,
        result: SocPipelineResult,
    ) -> None:
        try:
            enrichment = enrich_single_cve(self.db, cve_id, client=self.client)
            self.count_enrichment(enrichment, result)
            logger.info(
                "[SOC Pipeline] %s enrichment %s",
                enrichment.cve_id,
                enrichment.new_status.value,
            )

            if enrichment.new_status != EnrichmentStatus.SUCCESS:
                return

            self.correlate_successful_vulnerability(enrichment.cve_id, result)
        except Exception as exc:
            self.db.rollback()
            message = f"{cve_id}: {exc.__class__.__name__}: {exc}"
            result.errors.append(message[:500])
            result.enriched_failed += 1
            logger.exception("[SOC Pipeline] ERROR on %s: %s", cve_id, exc)

    def count_enrichment(
        self,
        enrichment: CveEnrichmentResult,
        result: SocPipelineResult,
    ) -> None:
        if enrichment.new_status == EnrichmentStatus.SUCCESS:
            result.enriched_success += 1
        elif enrichment.new_status == EnrichmentStatus.NOT_FOUND:
            result.enriched_not_found += 1
        elif enrichment.new_status == EnrichmentStatus.FAILED:
            result.enriched_failed += 1

    def correlate_successful_vulnerability(
        self,
        cve_id: str,
        result: SocPipelineResult,
    ) -> None:
        vulnerability = load_vulnerability_with_products(self.db, cve_id)
        if vulnerability is None:
            result.errors.append(f"{cve_id}: vulnerability missing after enrichment")
            return

        assets = select_active_assets(self.db)
        if not assets:
            logger.info("[SOC Pipeline] %s checked against 0 assets", cve_id)
            return

        alerts_before = count_rows(self.db, Alert)
        notifications_before = count_rows(self.db, Notification)

        for asset in assets:
            evaluation = evaluate_asset_vulnerability(asset, vulnerability)
            result.assets_checked += 1
            increment_correlation_status(result, evaluation.status)
            logger.info(
                "[SOC Pipeline] %s on %s -> %s",
                cve_id,
                asset.name,
                evaluation.status.value,
            )

            existing = None
            if evaluation.asset_id and evaluation.vulnerability_id:
                existing = find_existing_correlation(
                    self.db,
                    asset_id=evaluation.asset_id,
                    vulnerability_id=evaluation.vulnerability_id,
                )

            persisted = persist_correlation_result(self.db, evaluation)
            if persisted is None:
                continue
            if existing is None:
                result.correlations_created += 1
            else:
                result.correlations_updated += 1

        self.db.commit()

        alerts_after = count_rows(self.db, Alert)
        notifications_after = count_rows(self.db, Notification)
        result.alerts_created_or_updated += max(alerts_after - alerts_before, 0)
        result.notifications_created_or_updated += max(
            notifications_after - notifications_before,
            0,
        )
        logger.info(
            "[SOC Pipeline] %s checked against %s asset(s)",
            cve_id,
            len(assets),
        )


def process_pending_security_pipeline(
    db: Session,
    *,
    limit: int | None = None,
    request_delay_seconds: float | None = None,
    client: NVDClient | None = None,
    sleep_func: Callable[[float], None] = time.sleep,
    include_failed_retry: bool = False,
    force_enabled: bool = False,
) -> SocPipelineResult:
    service = SOCOrchestrationService(db, client=client, sleep_func=sleep_func)
    return service.run_soc_pipeline(
        limit=limit,
        request_delay_seconds=request_delay_seconds,
        include_failed_retry=include_failed_retry,
        force_enabled=force_enabled,
    )


def run_soc_pipeline(
    db: Session,
    **kwargs,
) -> SocPipelineResult:
    return process_pending_security_pipeline(db, **kwargs)


def select_vulnerabilities_to_process(
    db: Session,
    *,
    limit: int,
    include_failed_retry: bool = False,
) -> list[Vulnerability]:
    statuses = [EnrichmentStatus.PENDING]
    if include_failed_retry:
        statuses.append(EnrichmentStatus.FAILED)

    return list(
        db.scalars(
            select(Vulnerability)
            .where(Vulnerability.enrichment_status.in_(statuses))
            .order_by(Vulnerability.created_at.asc(), Vulnerability.cve_id.asc())
            .limit(limit)
        )
    )


def load_vulnerability_with_products(db: Session, cve_id: str) -> Vulnerability | None:
    return db.scalar(
        select(Vulnerability)
        .options(selectinload(Vulnerability.affected_products))
        .where(Vulnerability.cve_id == cve_id.strip().upper())
    )


def select_active_assets(db: Session) -> list[Asset]:
    return list(
        db.scalars(
            select(Asset).where(Asset.is_active.is_(True)).order_by(Asset.name.asc())
        )
    )


def increment_correlation_status(
    result: SocPipelineResult,
    status: CorrelationStatus,
) -> None:
    if status == CorrelationStatus.MATCH:
        result.matches += 1
    elif status == CorrelationStatus.POSSIBLE_MATCH:
        result.possible_matches += 1
    elif status == CorrelationStatus.NO_MATCH:
        result.no_matches += 1
    elif status == CorrelationStatus.UNKNOWN:
        result.unknown += 1


def count_rows(db: Session, model) -> int:
    return db.scalar(select(func.count(model.id))) or 0


def safe_positive_int(value, *, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(parsed, maximum))


def safe_non_negative_float(value, *, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return max(parsed, 0.0)


def finish_result(result: SocPipelineResult, started_monotonic: float) -> SocPipelineResult:
    result.finished_at = datetime.utcnow()
    result.duration_seconds = round(time.monotonic() - started_monotonic, 3)
    return result
