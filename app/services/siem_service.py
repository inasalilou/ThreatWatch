"""
Service metier pour l'ingestion des alertes SIEM Wazuh.

Le service ne depend pas de FastAPI: il recoit des champs normalises, tente la
correlation avec l'inventaire, persiste l'evenement et renforce la priorite SOC
des alertes actives de l'actif lorsqu'un signal d'attaque est observe.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import math
from typing import Any

from sqlalchemy import distinct, func, or_, select
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertPriority, AlertSeverity, AlertStatus
from app.models.asset import Asset
from app.models.asset_vulnerability_correlation import (
    AssetVulnerabilityCorrelation,
    CorrelationPersistenceStatus,
)
from app.models.siem_alert import SiemAlert
from app.models.vulnerability import Vulnerability
from app.services.alert_priority_service import priority_level_from_score


ACTIVE_ATTACK_BONUS = Decimal("20.00")
MAX_PRIORITY_SCORE = Decimal("100.00")
SCORE_QUANTUM = Decimal("0.01")
PER_PAGE = 20


@dataclass(frozen=True)
class NormalizedWazuhAlert:
    agent_id: str | None
    agent_name: str | None
    agent_ip: str | None
    rule_id: str | None
    rule_level: int | None
    description: str | None
    mitre_technique_id: str | None
    mitre_tactic: str | None
    raw_payload: dict[str, Any]


@dataclass(frozen=True)
class SiemIngestionResult:
    alert: SiemAlert
    asset: Asset | None
    boosted_alerts: int


@dataclass(frozen=True)
class SiemAlertListItem:
    alert: SiemAlert
    asset: Asset | None


@dataclass(frozen=True)
class SiemAlertSearchResult:
    items: list[SiemAlertListItem]
    total: int
    page: int
    per_page: int
    total_pages: int
    search: str
    severity: str
    technique: str

    @property
    def has_previous(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages


@dataclass(frozen=True)
class SiemStats:
    total_recent_24h: int
    high_or_critical_alerts: int
    affected_assets: int
    unique_mitre_techniques: int


def ingest_wazuh_alert(
    db: Session,
    wazuh_alert: NormalizedWazuhAlert,
) -> SiemIngestionResult:
    asset = find_matching_asset(
        db,
        agent_name=wazuh_alert.agent_name,
        agent_ip=wazuh_alert.agent_ip,
    )

    siem_alert = SiemAlert(
        agent_id=wazuh_alert.agent_id,
        agent_name=wazuh_alert.agent_name,
        agent_ip=wazuh_alert.agent_ip,
        rule_id=wazuh_alert.rule_id,
        rule_level=wazuh_alert.rule_level,
        description=wazuh_alert.description,
        mitre_technique_id=wazuh_alert.mitre_technique_id,
        mitre_tactic=wazuh_alert.mitre_tactic,
        raw_payload=wazuh_alert.raw_payload,
        date_detection=datetime.utcnow(),
        asset_id=asset.id if asset else None,
    )
    db.add(siem_alert)
    db.flush()

    boosted_alerts = 0
    if asset is not None and should_boost_asset_priority(db, asset.id):
        boosted_alerts = boost_active_asset_alerts(
            db,
            asset_id=asset.id,
            siem_alert=siem_alert,
        )

    db.commit()
    db.refresh(siem_alert)
    return SiemIngestionResult(
        alert=siem_alert,
        asset=asset,
        boosted_alerts=boosted_alerts,
    )


def list_siem_alerts(
    db: Session,
    search: str = "",
    severity: str = "",
    technique: str = "",
    page: int = 1,
    per_page: int = PER_PAGE,
) -> SiemAlertSearchResult:
    page = max(page, 1)
    per_page = max(per_page, 1)
    cleaned_search = search.strip()
    cleaned_severity = severity.strip().upper()
    cleaned_technique = technique.strip()
    filters = build_siem_filters(
        search=cleaned_search,
        severity=cleaned_severity,
        technique=cleaned_technique,
    )

    base_statement = (
        select(SiemAlert.id)
        .outerjoin(Asset, SiemAlert.asset_id == Asset.id)
        .where(*filters)
    )
    total = db.scalar(select(func.count()).select_from(base_statement.subquery())) or 0
    total_pages = max(math.ceil(total / per_page), 1)
    if page > total_pages:
        page = total_pages

    statement = (
        select(SiemAlert, Asset)
        .outerjoin(Asset, SiemAlert.asset_id == Asset.id)
        .where(*filters)
        .order_by(SiemAlert.date_detection.desc(), SiemAlert.id.desc())
        .limit(per_page)
        .offset((page - 1) * per_page)
    )
    return SiemAlertSearchResult(
        items=[
            SiemAlertListItem(alert=siem_alert, asset=asset)
            for siem_alert, asset in db.execute(statement).all()
        ],
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        search=cleaned_search,
        severity=cleaned_severity,
        technique=cleaned_technique,
    )


def get_siem_stats(db: Session) -> SiemStats:
    since = datetime.utcnow() - timedelta(hours=24)
    return SiemStats(
        total_recent_24h=db.scalar(
            select(func.count(SiemAlert.id)).where(SiemAlert.date_detection >= since)
        )
        or 0,
        high_or_critical_alerts=db.scalar(
            select(func.count(SiemAlert.id)).where(SiemAlert.rule_level >= 7)
        )
        or 0,
        affected_assets=db.scalar(
            select(func.count(distinct(SiemAlert.asset_id))).where(
                SiemAlert.asset_id.is_not(None)
            )
        )
        or 0,
        unique_mitre_techniques=db.scalar(
            select(func.count(distinct(SiemAlert.mitre_technique_id))).where(
                SiemAlert.mitre_technique_id.is_not(None)
            )
        )
        or 0,
    )


def build_siem_filters(search: str = "", severity: str = "", technique: str = ""):
    filters = []
    if search:
        pattern = f"%{search}%"
        filters.append(
            or_(
                SiemAlert.agent_name.ilike(pattern),
                SiemAlert.agent_ip.ilike(pattern),
                SiemAlert.description.ilike(pattern),
                Asset.name.ilike(pattern),
                Asset.hostname.ilike(pattern),
                Asset.ip_address.ilike(pattern),
            )
        )

    severity_filter = siem_severity_filter(severity)
    if severity_filter is not None:
        filters.append(severity_filter)

    if technique:
        filters.append(SiemAlert.mitre_technique_id.ilike(f"%{technique}%"))

    return filters


def siem_severity_filter(severity: str):
    normalized = severity.strip().upper()
    if normalized == "CRITICAL":
        return SiemAlert.rule_level >= 12
    if normalized == "HIGH":
        return SiemAlert.rule_level.between(7, 11)
    if normalized == "MEDIUM":
        return SiemAlert.rule_level.between(3, 6)
    if normalized == "LOW":
        return SiemAlert.rule_level <= 2
    return None


def get_siem_severity_options() -> list[tuple[str, str]]:
    return [
        ("CRITICAL", "Critique"),
        ("HIGH", "Haute"),
        ("MEDIUM", "Moyenne"),
        ("LOW", "Basse"),
    ]


def get_available_mitre_techniques(db: Session) -> list[str]:
    rows = db.execute(
        select(SiemAlert.mitre_technique_id)
        .where(SiemAlert.mitre_technique_id.is_not(None))
        .group_by(SiemAlert.mitre_technique_id)
        .order_by(SiemAlert.mitre_technique_id.asc())
    ).scalars()
    return [technique for technique in rows if technique]


def siem_level_label(level: int | None) -> str:
    if level is None:
        return "N/A"
    if level >= 12:
        return f"Critique {level}"
    if level >= 7:
        return f"Haute {level}"
    if level >= 3:
        return f"Moyenne {level}"
    return f"Basse {level}"


def siem_level_tone(level: int | None) -> str:
    if level is None:
        return "tone-neutral"
    if level >= 12:
        return "tone-critical"
    if level >= 7:
        return "tone-warning"
    if level >= 3:
        return "tone-info"
    return "tone-success"


def asset_correlation_label(asset: Asset | None) -> str:
    return "MATCH" if asset is not None else "NON MATCH"


def asset_correlation_tone(asset: Asset | None) -> str:
    return "tone-success" if asset is not None else "tone-neutral"


def format_datetime(value: datetime | None) -> str:
    if value is None:
        return "-"
    return value.strftime("%d/%m/%Y %H:%M")


def find_matching_asset(
    db: Session,
    *,
    agent_name: str | None,
    agent_ip: str | None,
) -> Asset | None:
    filters = []
    if agent_name:
        filters.append(
            or_(
                Asset.name.ilike(agent_name),
                Asset.hostname.ilike(agent_name),
            )
        )
    if agent_ip:
        filters.append(Asset.ip_address == agent_ip)

    if not filters:
        return None

    return db.execute(
        select(Asset)
        .where(Asset.is_active.is_(True), or_(*filters))
        .order_by(Asset.name.asc())
        .limit(1)
    ).scalar_one_or_none()


def should_boost_asset_priority(db: Session, asset_id: str) -> bool:
    critical_unresolved_alert = db.scalar(
        select(Alert.id)
        .join(Vulnerability, Alert.vulnerability_id == Vulnerability.id)
        .where(
            Alert.asset_id == asset_id,
            Alert.is_active.is_(True),
            Alert.status.in_([AlertStatus.NEW, AlertStatus.IN_PROGRESS]),
            or_(
                Alert.priority_level == AlertPriority.CRITICAL,
                Alert.severity == AlertSeverity.CRITICAL,
                Vulnerability.cvss_severity == "CRITICAL",
            ),
        )
        .limit(1)
    )
    if critical_unresolved_alert is not None:
        return True

    match_correlation = db.scalar(
        select(AssetVulnerabilityCorrelation.id)
        .where(
            AssetVulnerabilityCorrelation.asset_id == asset_id,
            AssetVulnerabilityCorrelation.is_active.is_(True),
            AssetVulnerabilityCorrelation.status == CorrelationPersistenceStatus.MATCH,
        )
        .limit(1)
    )
    return match_correlation is not None


def boost_active_asset_alerts(
    db: Session,
    *,
    asset_id: str,
    siem_alert: SiemAlert,
) -> int:
    alerts = db.execute(
        select(Alert).where(
            Alert.asset_id == asset_id,
            Alert.is_active.is_(True),
            Alert.status.in_([AlertStatus.NEW, AlertStatus.IN_PROGRESS]),
        )
    ).scalars()

    updated_count = 0
    for alert in alerts:
        previous_score = decimal_score(alert.priority_score)
        boosted_score = min(previous_score + ACTIVE_ATTACK_BONUS, MAX_PRIORITY_SCORE)
        boosted_score = boosted_score.quantize(SCORE_QUANTUM, rounding=ROUND_HALF_UP)

        if boosted_score != previous_score:
            updated_count += 1

        alert.priority_score = boosted_score
        alert.priority_level = priority_level_from_score(boosted_score)
        alert.priority_reason = append_active_attack_reason(
            alert.priority_reason,
            siem_alert=siem_alert,
        )
        alert.last_seen_at = siem_alert.date_detection
        alert.updated_at = datetime.utcnow()

    db.flush()
    return updated_count


def append_active_attack_reason(
    current_reason: str | None,
    *,
    siem_alert: SiemAlert,
) -> str:
    technique = siem_alert.mitre_technique_id or "MITRE N/A"
    tactic = siem_alert.mitre_tactic or "tactique N/A"
    rule = siem_alert.rule_id or "regle N/A"
    addition = (
        f"Signal SIEM Wazuh actif: {technique} ({tactic}), "
        f"regle {rule}, niveau {siem_alert.rule_level or 'N/A'}; "
        f"bonus attaque active +{format_decimal(ACTIVE_ATTACK_BONUS)}."
    )

    if not current_reason:
        return addition
    if "Signal SIEM Wazuh actif:" in current_reason:
        return current_reason
    return f"{current_reason} {addition}"


def decimal_score(value) -> Decimal:
    try:
        return Decimal(str(value or "0")).quantize(SCORE_QUANTUM)
    except (InvalidOperation, ValueError):
        return Decimal("0.00")


def format_decimal(value: Decimal) -> str:
    normalized = value.quantize(SCORE_QUANTUM, rounding=ROUND_HALF_UP)
    if normalized == normalized.to_integral():
        return str(int(normalized))
    return str(normalized)
