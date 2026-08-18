"""
Service d'enrichissement technique d'une CVE.

La phase 3.2.3 enrichit une seule Vulnerability locale a la fois. Les appels
externes restent separes du rendu web et de la synchronisation DGSSI.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.vulnerability import EnrichmentStatus, Vulnerability
from app.services.nvd_client import NVDClient, NVDClientError

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,10}$", re.IGNORECASE)
CWE_PATTERN = re.compile(r"^CWE-\d+$", re.IGNORECASE)


class CveEnrichmentError(RuntimeError):
    """Erreur fonctionnelle controlee du service d'enrichissement."""


@dataclass(frozen=True)
class CvssSelection:
    score: Decimal | None = None
    severity: str | None = None
    vector: str | None = None
    version: str | None = None


@dataclass(frozen=True)
class NormalizedNvdCve:
    cve_id: str
    description: str | None
    cvss: CvssSelection
    cwes: list[str]
    published_at: datetime | None
    modified_at: datetime | None
    external_references: list[dict[str, str]]


@dataclass(frozen=True)
class CveEnrichmentResult:
    cve_id: str
    old_status: EnrichmentStatus
    new_status: EnrichmentStatus
    source: str = "NVD"
    description: str | None = None
    cvss_score: Decimal | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cwes: list[str] = field(default_factory=list)
    published_at: datetime | None = None
    modified_at: datetime | None = None
    reference_count: int = 0
    error_message: str | None = None


def normalize_cve_id(cve_id: str | None) -> str:
    if not cve_id:
        return ""
    return cve_id.strip().upper()


def is_valid_cve_id(cve_id: str | None) -> bool:
    return bool(CVE_PATTERN.match(normalize_cve_id(cve_id)))


def enrich_single_cve(
    db: Session,
    cve_id: str,
    client: NVDClient | None = None,
) -> CveEnrichmentResult:
    normalized_cve_id = normalize_cve_id(cve_id)
    if not is_valid_cve_id(normalized_cve_id):
        raise CveEnrichmentError("Identifiant CVE invalide")

    vulnerability = db.execute(
        select(Vulnerability).where(Vulnerability.cve_id == normalized_cve_id)
    ).scalar_one_or_none()
    if vulnerability is None:
        raise CveEnrichmentError("CVE absente de ThreatWatch")

    old_status = vulnerability.enrichment_status
    client = client or NVDClient()

    try:
        data = client.fetch_cve(normalized_cve_id)
        nvd_record = extract_matching_nvd_record(data, normalized_cve_id)
        if nvd_record is None:
            update_not_found(vulnerability)
            db.commit()
            return CveEnrichmentResult(
                cve_id=normalized_cve_id,
                old_status=old_status,
                new_status=EnrichmentStatus.NOT_FOUND,
                error_message="CVE introuvable dans NVD",
            )

        normalized = normalize_nvd_cve(nvd_record, normalized_cve_id)
        apply_successful_enrichment(vulnerability, normalized)
        db.commit()

        return CveEnrichmentResult(
            cve_id=normalized_cve_id,
            old_status=old_status,
            new_status=EnrichmentStatus.SUCCESS,
            description=normalized.description,
            cvss_score=normalized.cvss.score,
            cvss_severity=normalized.cvss.severity,
            cvss_vector=normalized.cvss.vector,
            cvss_version=normalized.cvss.version,
            cwes=normalized.cwes,
            published_at=normalized.published_at,
            modified_at=normalized.modified_at,
            reference_count=len(normalized.external_references),
        )
    except NVDClientError as exc:
        db.rollback()
        mark_failed(db, vulnerability, old_status, str(exc))
        return CveEnrichmentResult(
            cve_id=normalized_cve_id,
            old_status=old_status,
            new_status=EnrichmentStatus.FAILED,
            error_message=str(exc),
        )
    except (SQLAlchemyError, Exception) as exc:
        db.rollback()
        message = f"{exc.__class__.__name__}: {exc}"
        mark_failed(db, vulnerability, old_status, message)
        return CveEnrichmentResult(
            cve_id=normalized_cve_id,
            old_status=old_status,
            new_status=EnrichmentStatus.FAILED,
            error_message=message[:500],
        )


def extract_matching_nvd_record(data: dict[str, Any], cve_id: str) -> dict[str, Any] | None:
    for item in data.get("vulnerabilities") or []:
        cve = item.get("cve") if isinstance(item, dict) else None
        if isinstance(cve, dict) and normalize_cve_id(cve.get("id")) == cve_id:
            return cve
    return None


def normalize_nvd_cve(record: dict[str, Any], cve_id: str) -> NormalizedNvdCve:
    return NormalizedNvdCve(
        cve_id=cve_id,
        description=select_description(record.get("descriptions") or []),
        cvss=select_cvss(record.get("metrics") or {}),
        cwes=extract_cwes(record.get("weaknesses") or []),
        published_at=parse_nvd_datetime(record.get("published")),
        modified_at=parse_nvd_datetime(record.get("lastModified")),
        external_references=extract_references(record.get("references") or []),
    )


def select_description(descriptions: list[dict[str, Any]]) -> str | None:
    fallback = None
    for description in descriptions:
        value = description.get("value")
        if not value:
            continue
        if fallback is None:
            fallback = value
        if str(description.get("lang", "")).lower() == "en":
            return value
    return fallback


def select_cvss(metrics: dict[str, Any]) -> CvssSelection:
    # Priorite explicite : CVSS v4.0, puis 3.1, 3.0, puis v2.
    for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_items = metrics.get(metric_key) or []
        if not metric_items:
            continue
        metric = choose_cvss_metric(metric_items)
        cvss_data = metric.get("cvssData") or {}
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity")
        vector = cvss_data.get("vectorString")
        version = cvss_data.get("version") or cvss_version_from_key(metric_key)

        return CvssSelection(
            score=Decimal(str(score)) if score is not None else None,
            severity=str(severity).upper() if severity else None,
            vector=str(vector) if vector else None,
            version=str(version) if version else None,
        )
    return CvssSelection()


def choose_cvss_metric(metric_items: list[dict[str, Any]]) -> dict[str, Any]:
    for metric in metric_items:
        if str(metric.get("type", "")).upper() == "PRIMARY":
            return metric
    return metric_items[0]


def cvss_version_from_key(metric_key: str) -> str:
    return {
        "cvssMetricV40": "4.0",
        "cvssMetricV31": "3.1",
        "cvssMetricV30": "3.0",
        "cvssMetricV2": "2.0",
    }.get(metric_key, "")


def extract_cwes(weaknesses: list[dict[str, Any]]) -> list[str]:
    cwes: list[str] = []
    seen: set[str] = set()
    for weakness in weaknesses:
        for description in weakness.get("description") or []:
            value = normalize_cve_id(description.get("value"))
            if not CWE_PATTERN.match(value):
                continue
            if value not in seen:
                cwes.append(value)
                seen.add(value)
    return cwes


def extract_references(references: list[dict[str, Any]]) -> list[dict[str, str]]:
    extracted: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    for reference in references:
        url = reference.get("url")
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        item = {"url": str(url)}
        source = reference.get("source")
        if source:
            item["source"] = str(source)
        extracted.append(item)
    return extracted


def parse_nvd_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    cleaned = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed
    return parsed.astimezone(UTC).replace(tzinfo=None)


def apply_successful_enrichment(
    vulnerability: Vulnerability,
    normalized: NormalizedNvdCve,
) -> None:
    vulnerability.description = normalized.description
    vulnerability.cvss_score = normalized.cvss.score
    vulnerability.cvss_severity = normalized.cvss.severity
    vulnerability.cvss_vector = normalized.cvss.vector
    vulnerability.cvss_version = normalized.cvss.version
    vulnerability.cwes = normalized.cwes or None
    vulnerability.external_references = normalized.external_references or None
    vulnerability.published_at = normalized.published_at
    vulnerability.modified_at = normalized.modified_at
    vulnerability.enrichment_source = "NVD"
    vulnerability.enrichment_status = EnrichmentStatus.SUCCESS
    vulnerability.enrichment_error = None
    vulnerability.last_enrichment_at = datetime.utcnow()


def update_not_found(vulnerability: Vulnerability) -> None:
    vulnerability.enrichment_source = "NVD"
    vulnerability.enrichment_status = EnrichmentStatus.NOT_FOUND
    vulnerability.enrichment_error = "CVE introuvable dans NVD"
    vulnerability.last_enrichment_at = datetime.utcnow()


def mark_failed(
    db: Session,
    vulnerability: Vulnerability,
    old_status: EnrichmentStatus,
    message: str,
) -> None:
    vulnerability.enrichment_source = "NVD"
    vulnerability.enrichment_status = EnrichmentStatus.FAILED
    vulnerability.enrichment_error = message[:500]
    vulnerability.last_enrichment_at = datetime.utcnow()
    try:
        db.add(vulnerability)
        db.commit()
    except Exception:
        db.rollback()
        vulnerability.enrichment_status = old_status
        raise
