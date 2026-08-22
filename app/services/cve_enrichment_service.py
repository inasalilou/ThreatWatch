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

from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.vulnerability import EnrichmentStatus, Vulnerability
from app.models.vulnerability_affected_product import VulnerabilityAffectedProduct
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
    affected_products: list["NormalizedAffectedProduct"]


@dataclass(frozen=True)
class NormalizedAffectedProduct:
    cpe: str
    cpe_part: str | None = None
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    version_start_including: str = ""
    version_start_excluding: str = ""
    version_end_including: str = ""
    version_end_excluding: str = ""
    vulnerable: bool = True


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
    affected_product_count: int = 0
    affected_product_samples: list[str] = field(default_factory=list)
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
        replace_affected_products(db, vulnerability, normalized.affected_products)
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
            affected_product_count=len(normalized.affected_products),
            affected_product_samples=[
                product.cpe for product in normalized.affected_products[:5]
            ],
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
        affected_products=extract_affected_products(record.get("configurations") or []),
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


def extract_affected_products(
    configurations: list[dict[str, Any]] | dict[str, Any],
) -> list[NormalizedAffectedProduct]:
    products: list[NormalizedAffectedProduct] = []
    seen: set[tuple[str, str, str, str, str]] = set()

    for cpe_match in iter_cpe_matches(configurations):
        if cpe_match.get("vulnerable") is not True:
            continue

        cpe = normalize_optional_string(
            cpe_match.get("criteria")
            or cpe_match.get("cpe23Uri")
            or cpe_match.get("cpe22Uri")
        )
        if not cpe:
            continue

        version_start_including = normalize_version_bound(
            cpe_match.get("versionStartIncluding")
        )
        version_start_excluding = normalize_version_bound(
            cpe_match.get("versionStartExcluding")
        )
        version_end_including = normalize_version_bound(
            cpe_match.get("versionEndIncluding")
        )
        version_end_excluding = normalize_version_bound(
            cpe_match.get("versionEndExcluding")
        )

        key = (
            cpe,
            version_start_including,
            version_start_excluding,
            version_end_including,
            version_end_excluding,
        )
        if key in seen:
            continue
        seen.add(key)

        cpe_components = parse_cpe_23(cpe)
        products.append(
            NormalizedAffectedProduct(
                cpe=cpe,
                cpe_part=cpe_components.get("part"),
                vendor=cpe_components.get("vendor"),
                product=cpe_components.get("product"),
                version=cpe_components.get("version"),
                version_start_including=version_start_including,
                version_start_excluding=version_start_excluding,
                version_end_including=version_end_including,
                version_end_excluding=version_end_excluding,
                vulnerable=True,
            )
        )

    return products


def iter_cpe_matches(
    configurations: list[dict[str, Any]] | dict[str, Any],
):
    if isinstance(configurations, dict):
        configuration_items = [configurations]
    elif isinstance(configurations, list):
        configuration_items = configurations
    else:
        return

    for configuration in configuration_items:
        if not isinstance(configuration, dict):
            continue
        for node in configuration.get("nodes") or []:
            yield from iter_cpe_matches_from_node(node)


def iter_cpe_matches_from_node(node: dict[str, Any]):
    if not isinstance(node, dict):
        return

    for cpe_match in node.get("cpeMatch") or []:
        if isinstance(cpe_match, dict):
            yield cpe_match

    for child_node in node.get("nodes") or []:
        yield from iter_cpe_matches_from_node(child_node)


def parse_cpe_23(cpe: str) -> dict[str, str]:
    parts = split_cpe_23(cpe)
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return {}

    return {
        "part": unescape_cpe_component(parts[2]),
        "vendor": unescape_cpe_component(parts[3]),
        "product": unescape_cpe_component(parts[4]),
        "version": unescape_cpe_component(parts[5]),
    }


def split_cpe_23(cpe: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False

    for character in cpe:
        if escaped:
            current.append("\\" + character)
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == ":":
            parts.append("".join(current))
            current = []
            continue
        current.append(character)

    if escaped:
        current.append("\\")
    parts.append("".join(current))
    return parts


def unescape_cpe_component(value: str) -> str:
    return value.replace("\\", "")


def normalize_optional_string(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def normalize_version_bound(value: Any) -> str:
    normalized = normalize_optional_string(value)
    return normalized or ""


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


def replace_affected_products(
    db: Session,
    vulnerability: Vulnerability,
    affected_products: list[NormalizedAffectedProduct],
) -> None:
    db.execute(
        delete(VulnerabilityAffectedProduct).where(
            VulnerabilityAffectedProduct.vulnerability_id == vulnerability.id
        )
    )
    db.add_all(
        [
            VulnerabilityAffectedProduct(
                vulnerability_id=vulnerability.id,
                cpe=affected_product.cpe,
                cpe_part=affected_product.cpe_part,
                vendor=affected_product.vendor,
                product=affected_product.product,
                version=affected_product.version,
                version_start_including=affected_product.version_start_including,
                version_start_excluding=affected_product.version_start_excluding,
                version_end_including=affected_product.version_end_including,
                version_end_excluding=affected_product.version_end_excluding,
                vulnerable=affected_product.vulnerable,
            )
            for affected_product in affected_products
        ]
    )


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
