"""
Service metier des alertes SOC.

La phase 5.1 limite la creation automatique aux correlations MATCH actives.
Le caller garde la responsabilite du commit/rollback.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertPriority, AlertSeverity, AlertStatus
from app.models.asset import Asset
from app.models.asset_vulnerability_correlation import (
    AssetVulnerabilityCorrelation,
    CorrelationPersistenceStatus,
)
from app.models.vulnerability import Vulnerability
from app.services.alert_priority_service import calculate_alert_priority
from app.services.notification_service import create_notifications_from_alert


PER_PAGE = 20


class AlertCreationSkipped(RuntimeError):
    """Signale qu'aucune alerte ne doit etre creee pour cette correlation."""


class AlertTransitionError(ValueError):
    """Erreur controlee lorsqu'une transition de workflow est invalide."""


@dataclass(frozen=True)
class AlertListItem:
    alert: Alert
    asset: Asset
    vulnerability: Vulnerability


@dataclass(frozen=True)
class AlertDetail:
    alert: Alert
    asset: Asset
    vulnerability: Vulnerability
    correlation: AssetVulnerabilityCorrelation


@dataclass(frozen=True)
class AlertSearchResult:
    items: list[AlertListItem]
    total: int
    page: int
    per_page: int
    total_pages: int
    search: str
    status: str
    priority: str
    severity: str
    asset: str
    cve: str
    is_active: str

    @property
    def has_previous(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages


@dataclass(frozen=True)
class AlertStats:
    active_alerts: int
    new_alerts: int
    in_progress_alerts: int
    critical_alerts: int


def create_alert_from_correlation(
    db: Session,
    correlation_id: str,
) -> Alert | None:
    correlation = db.get(AssetVulnerabilityCorrelation, correlation_id)
    if correlation is None:
        raise AlertCreationSkipped("Correlation introuvable")

    if correlation.status != CorrelationPersistenceStatus.MATCH:
        return None
    if not correlation.is_active:
        return None

    asset = db.get(Asset, correlation.asset_id)
    vulnerability = db.get(Vulnerability, correlation.vulnerability_id)
    if asset is None or vulnerability is None:
        raise AlertCreationSkipped("Correlation incoherente: asset ou CVE introuvable")
    if not asset.is_active:
        return None

    existing = get_alert_by_correlation_id(db, correlation.id)
    if existing is not None:
        if existing.status == AlertStatus.CLOSED:
            return existing
        update_existing_alert(
            alert=existing,
            asset=asset,
            vulnerability=vulnerability,
            correlation=correlation,
        )
        db.flush()
        create_notifications_from_alert(db, existing)
        return existing

    alert = Alert(
        correlation_id=correlation.id,
        asset_id=asset.id,
        vulnerability_id=vulnerability.id,
        title=build_alert_title(asset, vulnerability),
        description=build_alert_description(asset, vulnerability),
        severity=derive_alert_severity(vulnerability),
        **build_alert_priority_fields(asset, vulnerability, correlation),
        status=AlertStatus.NEW,
        source="CORRELATION",
        reason=correlation.reason,
        first_detected_at=correlation.first_detected_at,
        last_seen_at=correlation.last_evaluated_at,
        is_active=True,
    )
    db.add(alert)
    db.flush()
    create_notifications_from_alert(db, alert)
    return alert


def update_existing_alert(
    alert: Alert,
    asset: Asset,
    vulnerability: Vulnerability,
    correlation: AssetVulnerabilityCorrelation,
) -> None:
    alert.asset_id = asset.id
    alert.vulnerability_id = vulnerability.id
    alert.title = build_alert_title(asset, vulnerability)
    alert.description = build_alert_description(asset, vulnerability)
    alert.severity = derive_alert_severity(vulnerability)
    apply_alert_priority(alert, asset, vulnerability, correlation)
    alert.source = "CORRELATION"
    alert.reason = correlation.reason
    alert.last_seen_at = correlation.last_evaluated_at
    alert.is_active = True


def get_alert_by_id(db: Session, alert_id: str) -> Alert | None:
    return db.get(Alert, alert_id)


def get_alert_detail(db: Session, alert_id: str) -> AlertDetail | None:
    row = db.execute(
        select(Alert, Asset, Vulnerability, AssetVulnerabilityCorrelation)
        .join(Asset, Alert.asset_id == Asset.id)
        .join(Vulnerability, Alert.vulnerability_id == Vulnerability.id)
        .join(
            AssetVulnerabilityCorrelation,
            Alert.correlation_id == AssetVulnerabilityCorrelation.id,
        )
        .where(Alert.id == alert_id)
    ).one_or_none()
    if row is None:
        return None

    alert, asset, vulnerability, correlation = row
    return AlertDetail(
        alert=alert,
        asset=asset,
        vulnerability=vulnerability,
        correlation=correlation,
    )


def get_alert_by_correlation_id(db: Session, correlation_id: str) -> Alert | None:
    return db.execute(
        select(Alert).where(Alert.correlation_id == correlation_id)
    ).scalar_one_or_none()


def list_alerts(
    db: Session,
    search: str = "",
    status: str = "",
    priority: str = "",
    severity: str = "",
    asset: str = "",
    cve: str = "",
    is_active: str = "",
    page: int = 1,
    per_page: int = PER_PAGE,
) -> AlertSearchResult:
    page = max(page, 1)
    per_page = max(per_page, 1)
    cleaned_search = search.strip()
    cleaned_status = status.strip().upper()
    cleaned_priority = priority.strip().upper()
    cleaned_severity = severity.strip().upper()
    cleaned_asset = asset.strip()
    cleaned_cve = cve.strip().upper()
    cleaned_is_active = is_active.strip().lower()
    filters = build_alert_filters(
        search=cleaned_search,
        status=cleaned_status,
        priority=cleaned_priority,
        severity=cleaned_severity,
        asset=cleaned_asset,
        cve=cleaned_cve,
        is_active=cleaned_is_active,
    )

    base_statement = (
        select(Alert.id)
        .join(Asset, Alert.asset_id == Asset.id)
        .join(Vulnerability, Alert.vulnerability_id == Vulnerability.id)
        .where(*filters)
    )
    total = db.scalar(select(func.count()).select_from(base_statement.subquery())) or 0
    total_pages = max(math.ceil(total / per_page), 1)
    if page > total_pages:
        page = total_pages

    statement = (
        select(Alert, Asset, Vulnerability)
        .join(Asset, Alert.asset_id == Asset.id)
        .join(Vulnerability, Alert.vulnerability_id == Vulnerability.id)
        .where(*filters)
        .order_by(
            Alert.is_active.desc(),
            Alert.priority_score.desc(),
            alert_status_rank_expression(),
            Alert.last_seen_at.desc(),
            Alert.created_at.desc(),
        )
        .limit(per_page)
        .offset((page - 1) * per_page)
    )

    return AlertSearchResult(
        items=[
            AlertListItem(alert=alert, asset=asset_row, vulnerability=vulnerability)
            for alert, asset_row, vulnerability in db.execute(statement).all()
        ],
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        search=cleaned_search,
        status=cleaned_status,
        priority=cleaned_priority,
        severity=cleaned_severity,
        asset=cleaned_asset,
        cve=cleaned_cve,
        is_active=cleaned_is_active,
    )


def build_alert_filters(
    search: str = "",
    status: str = "",
    priority: str = "",
    severity: str = "",
    asset: str = "",
    cve: str = "",
    is_active: str = "",
):
    filters = []

    if search:
        pattern = f"%{search}%"
        filters.append(
            or_(
                Alert.title.ilike(pattern),
                Alert.description.ilike(pattern),
                Alert.reason.ilike(pattern),
                Asset.name.ilike(pattern),
                Asset.hostname.ilike(pattern),
                Vulnerability.cve_id.ilike(pattern),
            )
        )

    if status in {item.value for item in AlertStatus}:
        filters.append(Alert.status == status)

    if priority in {item.value for item in AlertPriority}:
        filters.append(Alert.priority_level == priority)

    if severity in {item.value for item in AlertSeverity}:
        filters.append(Alert.severity == severity)

    if asset:
        pattern = f"%{asset}%"
        filters.append(or_(Asset.name.ilike(pattern), Asset.hostname.ilike(pattern)))

    if cve:
        filters.append(Vulnerability.cve_id.ilike(f"%{cve}%"))

    if is_active == "active":
        filters.append(Alert.is_active.is_(True))
    elif is_active == "inactive":
        filters.append(Alert.is_active.is_(False))

    return filters


def get_alert_stats(db: Session) -> AlertStats:
    active_alerts = (
        db.scalar(select(func.count(Alert.id)).where(Alert.is_active.is_(True))) or 0
    )
    new_alerts = (
        db.scalar(
            select(func.count(Alert.id)).where(
                Alert.is_active.is_(True),
                Alert.status == AlertStatus.NEW,
            )
        )
        or 0
    )
    in_progress_alerts = (
        db.scalar(
            select(func.count(Alert.id)).where(
                Alert.is_active.is_(True),
                Alert.status == AlertStatus.IN_PROGRESS,
            )
        )
        or 0
    )
    critical_alerts = (
        db.scalar(
            select(func.count(Alert.id)).where(
                Alert.is_active.is_(True),
                Alert.priority_level == AlertPriority.CRITICAL,
            )
        )
        or 0
    )
    return AlertStats(
        active_alerts=active_alerts,
        new_alerts=new_alerts,
        in_progress_alerts=in_progress_alerts,
        critical_alerts=critical_alerts,
    )


def start_alert(db: Session, alert_id: str) -> Alert | None:
    alert = get_alert_by_id(db, alert_id)
    if alert is None:
        return None
    require_alert_status(alert, AlertStatus.NEW, "demarrer")
    alert.status = AlertStatus.IN_PROGRESS
    alert.updated_at = datetime.utcnow()
    db.flush()
    return alert


def resolve_alert(db: Session, alert_id: str) -> Alert | None:
    alert = get_alert_by_id(db, alert_id)
    if alert is None:
        return None
    require_alert_status(alert, AlertStatus.IN_PROGRESS, "resoudre")
    alert.status = AlertStatus.RESOLVED
    alert.updated_at = datetime.utcnow()
    db.flush()
    return alert


def close_alert(db: Session, alert_id: str) -> Alert | None:
    alert = get_alert_by_id(db, alert_id)
    if alert is None:
        return None
    require_alert_status(alert, AlertStatus.RESOLVED, "cloturer")
    alert.status = AlertStatus.CLOSED
    alert.is_active = False
    alert.updated_at = datetime.utcnow()
    db.flush()
    return alert


def require_alert_status(alert: Alert, expected: AlertStatus, action: str) -> None:
    if alert.status != expected:
        raise AlertTransitionError(
            f"Impossible de {action} cette alerte depuis le statut {alert.status.value}."
        )


def alert_status_rank_expression():
    return case(
        (Alert.status == AlertStatus.NEW, 0),
        (Alert.status == AlertStatus.IN_PROGRESS, 1),
        (Alert.status == AlertStatus.RESOLVED, 2),
        (Alert.status == AlertStatus.CLOSED, 3),
        else_=4,
    )


def get_alert_status_options() -> list[tuple[str, str]]:
    return [(status.value, alert_status_label(status)) for status in AlertStatus]


def get_alert_priority_options() -> list[tuple[str, str]]:
    return [(priority.value, priority.value) for priority in AlertPriority]


def get_alert_severity_options() -> list[tuple[str, str]]:
    return [(severity.value, severity.value) for severity in AlertSeverity]


def get_alert_activity_options() -> list[tuple[str, str]]:
    return [
        ("active", "Actives"),
        ("inactive", "Inactives"),
        ("all", "Toutes"),
    ]


def alert_status_label(value: AlertStatus | str | None) -> str:
    normalized = enum_value(value)
    return {
        AlertStatus.NEW.value: "Nouvelle",
        AlertStatus.IN_PROGRESS.value: "En cours",
        AlertStatus.RESOLVED.value: "Resolue",
        AlertStatus.CLOSED.value: "Cloturee",
    }.get(normalized, "Inconnu")


def alert_status_tone(value: AlertStatus | str | None) -> str:
    normalized = enum_value(value)
    return {
        AlertStatus.NEW.value: "tone-critical",
        AlertStatus.IN_PROGRESS.value: "tone-warning",
        AlertStatus.RESOLVED.value: "tone-success",
        AlertStatus.CLOSED.value: "tone-neutral",
    }.get(normalized, "tone-neutral")


def alert_priority_tone(value: AlertPriority | str | None) -> str:
    normalized = enum_value(value)
    return {
        AlertPriority.CRITICAL.value: "tone-critical",
        AlertPriority.HIGH.value: "tone-warning",
        AlertPriority.MEDIUM.value: "tone-info",
        AlertPriority.LOW.value: "tone-success",
    }.get(normalized, "tone-neutral")


def alert_activity_label(is_active: bool | None) -> str:
    if is_active is True:
        return "Active"
    if is_active is False:
        return "Inactive"
    return "Toutes"


def alert_activity_tone(is_active: bool | None) -> str:
    return "tone-success" if is_active is True else "tone-neutral"


def build_alert_title(asset: Asset, vulnerability: Vulnerability) -> str:
    return f"Vulnerabilite {vulnerability.cve_id} detectee sur {asset.name}"


def build_alert_description(asset: Asset, vulnerability: Vulnerability) -> str:
    return (
        f"La vulnerabilite {vulnerability.cve_id} correspond a l'actif "
        f"{asset.name} selon les donnees NVD et la correlation ThreatWatch."
    )


def derive_alert_severity(vulnerability: Vulnerability) -> AlertSeverity:
    # Regle provisoire Phase 5.1 : reprendre la severite CVSS NVD si disponible.
    value = (vulnerability.cvss_severity or "").strip().upper()
    if value in {item.value for item in AlertSeverity}:
        return AlertSeverity(value)
    return AlertSeverity.MEDIUM


def build_alert_priority_fields(
    asset: Asset,
    vulnerability: Vulnerability,
    correlation: AssetVulnerabilityCorrelation,
) -> dict:
    priority = calculate_alert_priority(asset, vulnerability, correlation)
    return {
        "priority_score": priority.score,
        "priority_level": priority.level,
        "priority_reason": priority.reason,
    }


def apply_alert_priority(
    alert: Alert,
    asset: Asset,
    vulnerability: Vulnerability,
    correlation: AssetVulnerabilityCorrelation,
) -> None:
    priority = calculate_alert_priority(asset, vulnerability, correlation)
    alert.priority_score = priority.score
    alert.priority_level = priority.level
    alert.priority_reason = priority.reason


def enum_value(value) -> str:
    return getattr(value, "value", str(value or "")).strip().upper()
