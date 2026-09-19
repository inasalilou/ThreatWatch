"""
Service de synthese pour le dashboard SOC.

Toutes les valeurs exposees par /dashboard viennent de PostgreSQL. Le service
regroupe uniquement des lectures agregees et des listes limitees.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertPriority, AlertStatus
from app.models.alert_treatment import AlertTreatment, AlertTreatmentActionType
from app.models.asset import Asset, AssetCriticality
from app.models.asset_vulnerability_correlation import (
    AssetVulnerabilityCorrelation,
    CorrelationPersistenceStatus,
)
from app.models.notification import Notification
from app.models.siem_alert import SiemAlert
from app.models.sync_history import SyncHistory
from app.models.user import Utilisateur
from app.models.vulnerability import EnrichmentStatus, Vulnerability
from app.services.alert_service import (
    alert_priority_tone,
    alert_status_label,
    alert_status_tone,
)
from app.services.analyst_treatment_service import action_type_label
from app.services.notification_service import notification_severity_tone


@dataclass(frozen=True)
class DashboardCounters:
    active_alerts: int
    critical_alerts: int
    vulnerabilities_detected: int
    active_assets: int
    new_alerts: int
    in_progress_alerts: int
    resolved_alerts: int
    active_match_correlations: int
    unread_notifications: int
    nvd_success_vulnerabilities: int


@dataclass(frozen=True)
class RecentAlertItem:
    alert_id: str
    cve_id: str
    asset_id: str
    asset_name: str
    priority_level: AlertPriority
    priority_score: Decimal
    status: AlertStatus
    last_seen_at: datetime


@dataclass(frozen=True)
class SeverityStat:
    severity: str
    count: int


@dataclass(frozen=True)
class ExposedAssetItem:
    asset_id: str
    asset_name: str
    criticality: AssetCriticality
    match_count: int
    possible_match_count: int
    total_count: int


@dataclass(frozen=True)
class RecentTreatmentItem:
    treatment_id: str
    alert_id: str
    analyst_name: str
    action_type: AlertTreatmentActionType
    cve_id: str
    created_at: datetime


@dataclass(frozen=True)
class RecentNotificationItem:
    notification_id: str
    alert_id: str
    title: str
    severity: str
    is_read: bool
    created_at: datetime


@dataclass(frozen=True)
class SyncSummary:
    sync_id: str | None
    source: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    items_found: int
    items_created: int
    items_updated: int
    error_message: str | None


@dataclass(frozen=True)
class PipelineStatus:
    pending: int
    success: int
    failed: int
    not_found: int


@dataclass(frozen=True)
class SiemTechniqueStat:
    technique_id: str
    count: int


@dataclass(frozen=True)
class RecentSiemDetectionItem:
    alert_id: str
    asset_id: str | None
    asset_name: str | None
    agent_name: str | None
    mitre_technique_id: str | None
    mitre_tactic: str | None
    description: str | None
    rule_level: int | None
    date_detection: datetime


@dataclass(frozen=True)
class SiemDashboardStats:
    recent_count: int
    top_mitre_techniques: list[SiemTechniqueStat]
    recent_detections: list[RecentSiemDetectionItem]


@dataclass(frozen=True)
class DashboardData:
    counters: DashboardCounters
    recent_alerts: list[RecentAlertItem]
    vulnerability_severity_stats: list[SeverityStat]
    top_exposed_assets: list[ExposedAssetItem]
    recent_treatments: list[RecentTreatmentItem]
    recent_notifications: list[RecentNotificationItem]
    sync_summary: SyncSummary
    pipeline_status: PipelineStatus
    siem: SiemDashboardStats


def get_dashboard_data(db: Session, current_user: Utilisateur) -> DashboardData:
    return DashboardData(
        counters=get_dashboard_counters(db, current_user),
        recent_alerts=get_recent_alerts(db),
        vulnerability_severity_stats=get_vulnerability_severity_stats(db),
        top_exposed_assets=get_top_exposed_assets(db),
        recent_treatments=get_recent_treatments(db),
        recent_notifications=get_recent_notifications(db, current_user),
        sync_summary=get_sync_summary(db),
        pipeline_status=get_pipeline_status(db),
        siem=get_siem_dashboard_stats(db),
    )


def get_dashboard_counters(db: Session, current_user: Utilisateur) -> DashboardCounters:
    return DashboardCounters(
        active_alerts=count_where(db, Alert, Alert.is_active.is_(True)),
        critical_alerts=count_where(
            db,
            Alert,
            Alert.is_active.is_(True),
            Alert.priority_level == AlertPriority.CRITICAL,
        ),
        vulnerabilities_detected=count_all(db, Vulnerability),
        active_assets=count_where(db, Asset, Asset.is_active.is_(True)),
        new_alerts=count_where(
            db,
            Alert,
            Alert.is_active.is_(True),
            Alert.status == AlertStatus.NEW,
        ),
        in_progress_alerts=count_where(
            db,
            Alert,
            Alert.is_active.is_(True),
            Alert.status == AlertStatus.IN_PROGRESS,
        ),
        resolved_alerts=count_where(
            db,
            Alert,
            Alert.is_active.is_(True),
            Alert.status == AlertStatus.RESOLVED,
        ),
        active_match_correlations=count_where(
            db,
            AssetVulnerabilityCorrelation,
            AssetVulnerabilityCorrelation.is_active.is_(True),
            AssetVulnerabilityCorrelation.status == CorrelationPersistenceStatus.MATCH,
        ),
        unread_notifications=count_unread_visible_notifications(db, current_user),
        nvd_success_vulnerabilities=count_where(
            db,
            Vulnerability,
            Vulnerability.enrichment_status == EnrichmentStatus.SUCCESS,
        ),
    )


def get_recent_alerts(db: Session, limit: int = 5) -> list[RecentAlertItem]:
    rows = db.execute(
        select(Alert, Asset, Vulnerability)
        .join(Asset, Alert.asset_id == Asset.id)
        .join(Vulnerability, Alert.vulnerability_id == Vulnerability.id)
        .where(Alert.is_active.is_(True))
        .order_by(Alert.last_seen_at.desc(), Alert.created_at.desc())
        .limit(limit)
    ).all()
    return [
        RecentAlertItem(
            alert_id=alert.id,
            cve_id=vulnerability.cve_id,
            asset_id=asset.id,
            asset_name=asset.name,
            priority_level=alert.priority_level,
            priority_score=alert.priority_score,
            status=alert.status,
            last_seen_at=alert.last_seen_at,
        )
        for alert, asset, vulnerability in rows
    ]


def get_vulnerability_severity_stats(db: Session) -> list[SeverityStat]:
    rows = db.execute(
        select(Vulnerability.cvss_severity, func.count(Vulnerability.id))
        .where(
            Vulnerability.enrichment_status == EnrichmentStatus.SUCCESS,
            Vulnerability.cvss_severity.is_not(None),
        )
        .group_by(Vulnerability.cvss_severity)
    ).all()
    counts = {str(severity).upper(): count for severity, count in rows if severity}
    return [
        SeverityStat(severity=severity, count=counts.get(severity, 0))
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    ]


def get_top_exposed_assets(db: Session, limit: int = 5) -> list[ExposedAssetItem]:
    match_case = case(
        (AssetVulnerabilityCorrelation.status == CorrelationPersistenceStatus.MATCH, 1),
        else_=0,
    )
    possible_case = case(
        (
            AssetVulnerabilityCorrelation.status
            == CorrelationPersistenceStatus.POSSIBLE_MATCH,
            1,
        ),
        else_=0,
    )
    rows = db.execute(
        select(
            Asset,
            func.sum(match_case).label("match_count"),
            func.sum(possible_case).label("possible_match_count"),
            func.count(AssetVulnerabilityCorrelation.id).label("total_count"),
        )
        .join(
            AssetVulnerabilityCorrelation,
            AssetVulnerabilityCorrelation.asset_id == Asset.id,
        )
        .where(
            Asset.is_active.is_(True),
            AssetVulnerabilityCorrelation.is_active.is_(True),
            AssetVulnerabilityCorrelation.status.in_(
                [
                    CorrelationPersistenceStatus.MATCH,
                    CorrelationPersistenceStatus.POSSIBLE_MATCH,
                ]
            ),
        )
        .group_by(Asset.id)
        .order_by(func.count(AssetVulnerabilityCorrelation.id).desc(), Asset.name.asc())
        .limit(limit)
    ).all()
    return [
        ExposedAssetItem(
            asset_id=asset.id,
            asset_name=asset.name,
            criticality=asset.criticality,
            match_count=int(match_count or 0),
            possible_match_count=int(possible_match_count or 0),
            total_count=int(total_count or 0),
        )
        for asset, match_count, possible_match_count, total_count in rows
    ]


def get_recent_treatments(db: Session, limit: int = 5) -> list[RecentTreatmentItem]:
    rows = db.execute(
        select(AlertTreatment, Alert, Vulnerability, Utilisateur)
        .join(Alert, AlertTreatment.alert_id == Alert.id)
        .join(Vulnerability, Alert.vulnerability_id == Vulnerability.id)
        .join(Utilisateur, AlertTreatment.analyst_id == Utilisateur.id)
        .order_by(AlertTreatment.created_at.desc())
        .limit(limit)
    ).all()
    return [
        RecentTreatmentItem(
            treatment_id=treatment.id,
            alert_id=alert.id,
            analyst_name=analyst.nom,
            action_type=treatment.action_type,
            cve_id=vulnerability.cve_id,
            created_at=treatment.created_at,
        )
        for treatment, alert, vulnerability, analyst in rows
    ]


def get_recent_notifications(
    db: Session,
    current_user: Utilisateur,
    limit: int = 5,
) -> list[RecentNotificationItem]:
    rows = db.execute(
        select(Notification)
        .where(*notification_visibility_filters(current_user))
        .order_by(Notification.is_read.asc(), Notification.created_at.desc())
        .limit(limit)
    ).scalars()
    return [
        RecentNotificationItem(
            notification_id=notification.id,
            alert_id=notification.alert_id,
            title=notification.title,
            severity=notification.severity,
            is_read=notification.is_read,
            created_at=notification.created_at,
        )
        for notification in rows
    ]


def get_sync_summary(db: Session) -> SyncSummary:
    sync = db.scalar(
        select(SyncHistory)
        .where(SyncHistory.source == "DGSSI")
        .order_by(SyncHistory.started_at.desc())
        .limit(1)
    )
    if sync is None:
        return SyncSummary(
            sync_id=None,
            source="DGSSI",
            status="Aucune",
            started_at=None,
            finished_at=None,
            items_found=0,
            items_created=0,
            items_updated=0,
            error_message=None,
        )
    return SyncSummary(
        sync_id=sync.id,
        source=sync.source,
        status=sync.status.value,
        started_at=sync.started_at,
        finished_at=sync.finished_at,
        items_found=sync.items_found,
        items_created=sync.items_created,
        items_updated=sync.items_updated,
        error_message=short_error(sync.error_message),
    )


def get_pipeline_status(db: Session) -> PipelineStatus:
    rows = db.execute(
        select(Vulnerability.enrichment_status, func.count(Vulnerability.id)).group_by(
            Vulnerability.enrichment_status
        )
    ).all()
    counts = {status: count for status, count in rows}
    return PipelineStatus(
        pending=counts.get(EnrichmentStatus.PENDING, 0),
        success=counts.get(EnrichmentStatus.SUCCESS, 0),
        failed=counts.get(EnrichmentStatus.FAILED, 0),
        not_found=counts.get(EnrichmentStatus.NOT_FOUND, 0),
    )


def get_siem_dashboard_stats(db: Session) -> SiemDashboardStats:
    return SiemDashboardStats(
        recent_count=get_recent_siem_count(db),
        top_mitre_techniques=get_top_mitre_techniques(db),
        recent_detections=get_recent_siem_detections(db),
    )


def get_recent_siem_count(db: Session, hours: int = 24) -> int:
    since = datetime.utcnow() - timedelta(hours=hours)
    return (
        db.scalar(
            select(func.count(SiemAlert.id)).where(SiemAlert.date_detection >= since)
        )
        or 0
    )


def get_top_mitre_techniques(
    db: Session,
    limit: int = 5,
) -> list[SiemTechniqueStat]:
    rows = db.execute(
        select(SiemAlert.mitre_technique_id, func.count(SiemAlert.id))
        .where(SiemAlert.mitre_technique_id.is_not(None))
        .group_by(SiemAlert.mitre_technique_id)
        .order_by(func.count(SiemAlert.id).desc(), SiemAlert.mitre_technique_id.asc())
        .limit(limit)
    ).all()
    return [
        SiemTechniqueStat(technique_id=technique_id, count=count)
        for technique_id, count in rows
        if technique_id
    ]


def get_recent_siem_detections(
    db: Session,
    limit: int = 8,
) -> list[RecentSiemDetectionItem]:
    rows = db.execute(
        select(SiemAlert, Asset)
        .outerjoin(Asset, SiemAlert.asset_id == Asset.id)
        .order_by(SiemAlert.date_detection.desc())
        .limit(limit)
    ).all()
    return [
        RecentSiemDetectionItem(
            alert_id=siem_alert.id,
            asset_id=asset.id if asset else None,
            asset_name=asset.name if asset else None,
            agent_name=siem_alert.agent_name,
            mitre_technique_id=siem_alert.mitre_technique_id,
            mitre_tactic=siem_alert.mitre_tactic,
            description=short_text(siem_alert.description, max_length=120),
            rule_level=siem_alert.rule_level,
            date_detection=siem_alert.date_detection,
        )
        for siem_alert, asset in rows
    ]


def count_all(db: Session, model) -> int:
    return db.scalar(select(func.count(model.id))) or 0


def count_where(db: Session, model, *filters) -> int:
    return db.scalar(select(func.count(model.id)).where(*filters)) or 0


def count_unread_visible_notifications(db: Session, current_user: Utilisateur) -> int:
    return (
        db.scalar(
            select(func.count(Notification.id)).where(
                *notification_visibility_filters(current_user),
                Notification.is_read.is_(False),
            )
        )
        or 0
    )


def notification_visibility_filters(current_user: Utilisateur):
    return [
        or_(
            Notification.recipient_user_id.is_(None),
            Notification.recipient_user_id == current_user.id,
        )
    ]


def short_error(value: str | None, max_length: int = 180) -> str | None:
    if not value:
        return None
    cleaned = " ".join(value.split())
    if len(cleaned) <= max_length:
        return cleaned
    return cleaned[: max_length - 3].rstrip() + "..."


def short_text(value: str | None, max_length: int = 120) -> str | None:
    if not value:
        return None
    cleaned = " ".join(value.split())
    if len(cleaned) <= max_length:
        return cleaned
    return cleaned[: max_length - 3].rstrip() + "..."


def criticality_tone(value: AssetCriticality | str | None) -> str:
    normalized = enum_value(value)
    return {
        AssetCriticality.CRITICAL.value: "tone-critical",
        AssetCriticality.HIGH.value: "tone-warning",
        AssetCriticality.MEDIUM.value: "tone-info",
        AssetCriticality.LOW.value: "tone-success",
    }.get(normalized, "tone-neutral")


def sync_status_tone(status: str | None) -> str:
    return {
        "SUCCESS": "tone-success",
        "PARTIAL": "tone-warning",
        "FAILED": "tone-critical",
    }.get(str(status or "").upper(), "tone-neutral")


def severity_tone(value: str | None) -> str:
    return {
        "CRITICAL": "tone-critical",
        "HIGH": "tone-warning",
        "MEDIUM": "tone-info",
        "LOW": "tone-success",
    }.get(str(value or "").upper(), "tone-neutral")


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


def format_datetime(value: datetime | None) -> str:
    if value is None:
        return "-"
    return value.strftime("%d/%m/%Y %H:%M")


def enum_value(value) -> str:
    return getattr(value, "value", str(value or "")).strip().upper()


__all__ = [
    "DashboardData",
    "get_dashboard_data",
    "get_dashboard_counters",
    "get_recent_alerts",
    "get_vulnerability_severity_stats",
    "get_top_exposed_assets",
    "get_recent_treatments",
    "get_recent_notifications",
    "get_sync_summary",
    "get_siem_dashboard_stats",
    "alert_priority_tone",
    "alert_status_label",
    "alert_status_tone",
    "action_type_label",
    "notification_severity_tone",
    "criticality_tone",
    "sync_status_tone",
    "severity_tone",
    "siem_level_tone",
    "format_datetime",
]
