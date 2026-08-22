"""
Service metier des notifications SOC.

Phase 6.2.1: persistance de notifications IN_APP uniquement. Le caller garde
la responsabilite du commit/rollback de la session SQLAlchemy.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertPriority, AlertStatus
from app.models.asset import Asset
from app.models.notification import (
    Notification,
    NotificationChannel,
    NotificationStatus,
    NotificationType,
)
from app.models.user import Utilisateur
from app.models.vulnerability import Vulnerability
from app.services.email_service import EmailDeliveryError, EmailService


PER_PAGE = 20
NOTIFIABLE_PRIORITIES = {AlertPriority.HIGH, AlertPriority.CRITICAL}


@dataclass(frozen=True)
class NotificationListItem:
    notification: Notification
    alert: Alert
    asset: Asset
    vulnerability: Vulnerability
    recipient_user: Utilisateur | None


@dataclass(frozen=True)
class NotificationSearchResult:
    items: list[NotificationListItem]
    total: int
    page: int
    per_page: int
    total_pages: int
    search: str = ""
    read_filter: str = "all"
    severity: str = ""
    notification_type: str = ""

    @property
    def has_previous(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages


@dataclass(frozen=True)
class NotificationStats:
    total: int
    unread: int
    critical: int
    sent: int


def create_notification_from_alert(
    db: Session,
    alert_or_id: Alert | str,
    *,
    recipient_user_id: str | None = None,
    notification_type: NotificationType = NotificationType.ALERT_CREATED,
    channel: NotificationChannel = NotificationChannel.IN_APP,
) -> Notification | None:
    alert = resolve_alert(db, alert_or_id)
    if alert is None or not should_create_notification(alert):
        return None

    existing = find_existing_notification(
        db=db,
        alert_id=alert.id,
        notification_type=notification_type,
        channel=channel,
    )
    if existing is not None:
        return existing

    asset = db.get(Asset, alert.asset_id)
    vulnerability = db.get(Vulnerability, alert.vulnerability_id)
    if asset is None or vulnerability is None:
        return None

    now = datetime.utcnow()
    status = notification_status_for_channel(channel)
    notification = Notification(
        alert_id=alert.id,
        recipient_user_id=recipient_user_id,
        notification_type=notification_type,
        channel=channel,
        title=build_notification_title(alert, asset, vulnerability),
        message=build_notification_message(alert, asset, vulnerability),
        severity=enum_value(alert.priority_level),
        status=status,
        sent_at=now if status == NotificationStatus.SENT else None,
        is_read=False,
    )
    db.add(notification)
    db.flush()
    return notification


def create_notifications_from_alert(
    db: Session,
    alert_or_id: Alert | str,
    *,
    email_service: EmailService | None = None,
) -> tuple[Notification | None, Notification | None]:
    in_app_notification = create_notification_from_alert(
        db,
        alert_or_id,
        channel=NotificationChannel.IN_APP,
    )
    email_notification = create_email_notification_from_alert(
        db,
        alert_or_id,
        email_service=email_service,
    )
    return in_app_notification, email_notification


def create_email_notification_from_alert(
    db: Session,
    alert_or_id: Alert | str,
    *,
    email_service: EmailService | None = None,
) -> Notification | None:
    alert = resolve_alert(db, alert_or_id)
    if alert is None or not should_create_notification(alert):
        return None

    existing = find_existing_notification(
        db=db,
        alert_id=alert.id,
        notification_type=NotificationType.ALERT_CREATED,
        channel=NotificationChannel.EMAIL,
    )
    if existing is not None:
        return existing

    asset = db.get(Asset, alert.asset_id)
    vulnerability = db.get(Vulnerability, alert.vulnerability_id)
    if asset is None or vulnerability is None:
        return None

    notification = Notification(
        alert_id=alert.id,
        recipient_user_id=None,
        notification_type=NotificationType.ALERT_CREATED,
        channel=NotificationChannel.EMAIL,
        title=build_email_subject(alert, vulnerability),
        message=build_email_body(alert, asset, vulnerability),
        severity=enum_value(alert.priority_level),
        status=NotificationStatus.PENDING,
        is_read=True,
        read_at=datetime.utcnow(),
    )
    db.add(notification)
    db.flush()

    delivery_service = email_service or EmailService()
    try:
        result = delivery_service.send_email(
            to_email=delivery_service.settings.SOC_NOTIFICATION_EMAIL,
            subject=notification.title,
            body=notification.message,
        )
        if result.sent:
            notification.status = NotificationStatus.SENT
            notification.sent_at = datetime.utcnow()
        else:
            notification.status = NotificationStatus.PENDING
    except EmailDeliveryError:
        notification.status = NotificationStatus.FAILED
    except Exception:
        notification.status = NotificationStatus.FAILED

    db.flush()
    return notification


def get_notification_by_id(db: Session, notification_id: str) -> Notification | None:
    return db.get(Notification, notification_id)


def list_notifications(
    db: Session,
    *,
    visible_to_user_id: str | None = None,
    recipient_user_id: str | None = None,
    unread_only: bool = False,
    read_filter: str = "all",
    severity: str = "",
    notification_type: str = "",
    status: str = "",
    channel: str = "",
    search: str = "",
    page: int = 1,
    per_page: int = PER_PAGE,
) -> NotificationSearchResult:
    page = max(page, 1)
    per_page = max(per_page, 1)
    cleaned_search = search.strip()
    cleaned_read_filter = read_filter.strip().lower()
    cleaned_severity = severity.strip().upper()
    cleaned_notification_type = notification_type.strip().upper()
    filters = build_notification_filters(
        visible_to_user_id=visible_to_user_id,
        recipient_user_id=recipient_user_id,
        unread_only=unread_only or cleaned_read_filter == "unread",
        read_filter=cleaned_read_filter,
        severity=cleaned_severity,
        notification_type=cleaned_notification_type,
        status=status,
        channel=channel,
        search=cleaned_search,
    )

    base_statement = (
        select(Notification.id)
        .join(Alert, Notification.alert_id == Alert.id)
        .join(Asset, Alert.asset_id == Asset.id)
        .join(Vulnerability, Alert.vulnerability_id == Vulnerability.id)
        .outerjoin(Utilisateur, Notification.recipient_user_id == Utilisateur.id)
        .where(*filters)
    )
    total = db.scalar(select(func.count()).select_from(base_statement.subquery())) or 0
    total_pages = max(math.ceil(total / per_page), 1)
    if page > total_pages:
        page = total_pages

    statement = (
        select(Notification, Alert, Asset, Vulnerability, Utilisateur)
        .join(Alert, Notification.alert_id == Alert.id)
        .join(Asset, Alert.asset_id == Asset.id)
        .join(Vulnerability, Alert.vulnerability_id == Vulnerability.id)
        .outerjoin(Utilisateur, Notification.recipient_user_id == Utilisateur.id)
        .where(*filters)
        .order_by(
            Notification.is_read.asc(),
            Notification.created_at.desc(),
            Notification.id.desc(),
        )
        .limit(per_page)
        .offset((page - 1) * per_page)
    )

    return NotificationSearchResult(
        items=[
            NotificationListItem(
                notification=notification,
                alert=alert,
                asset=asset,
                vulnerability=vulnerability,
                recipient_user=recipient_user,
            )
            for notification, alert, asset, vulnerability, recipient_user in db.execute(
                statement
            ).all()
        ],
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        search=cleaned_search,
        read_filter=cleaned_read_filter if cleaned_read_filter in {"all", "read", "unread"} else "all",
        severity=cleaned_severity,
        notification_type=cleaned_notification_type,
    )


def mark_notification_as_read(
    db: Session,
    notification_id: str,
    current_user: Utilisateur,
) -> Notification | None:
    notification = get_notification_by_id(db, notification_id)
    if notification is None or not is_notification_visible_to_user(
        notification,
        current_user,
    ):
        return None

    if not notification.is_read:
        notification.is_read = True
        notification.read_at = datetime.utcnow()
        db.flush()
    return notification


def mark_all_notifications_as_read(
    db: Session,
    current_user: Utilisateur,
) -> int:
    notifications = db.execute(
        select(Notification).where(
            *visibility_filters(current_user.id),
            Notification.is_read.is_(False),
        )
    ).scalars().all()

    now = datetime.utcnow()
    for notification in notifications:
        notification.is_read = True
        notification.read_at = now

    if notifications:
        db.flush()
    return len(notifications)


def count_unread_notifications(db: Session, current_user: Utilisateur) -> int:
    return (
        db.scalar(
            select(func.count(Notification.id)).where(
                *visibility_filters(current_user.id),
                Notification.is_read.is_(False),
            )
        )
        or 0
    )


def get_notification_stats(
    db: Session,
    current_user: Utilisateur,
) -> NotificationStats:
    visible = visibility_filters(current_user.id)
    total = db.scalar(select(func.count(Notification.id)).where(*visible)) or 0
    unread = (
        db.scalar(
            select(func.count(Notification.id)).where(
                *visible,
                Notification.is_read.is_(False),
            )
        )
        or 0
    )
    critical = (
        db.scalar(
            select(func.count(Notification.id)).where(
                *visible,
                Notification.severity == AlertPriority.CRITICAL.value,
            )
        )
        or 0
    )
    sent = (
        db.scalar(
            select(func.count(Notification.id)).where(
                *visible,
                Notification.status == NotificationStatus.SENT,
            )
        )
        or 0
    )
    return NotificationStats(total=total, unread=unread, critical=critical, sent=sent)


def should_create_notification(alert: Alert) -> bool:
    if not alert.is_active:
        return False
    if alert.status == AlertStatus.CLOSED:
        return False
    return normalize_priority(alert.priority_level) in NOTIFIABLE_PRIORITIES


def find_existing_notification(
    db: Session,
    *,
    alert_id: str,
    notification_type: NotificationType,
    channel: NotificationChannel,
) -> Notification | None:
    return db.execute(
        select(Notification).where(
            Notification.alert_id == alert_id,
            Notification.notification_type == notification_type,
            Notification.channel == channel,
        )
    ).scalar_one_or_none()


def build_notification_filters(
    *,
    visible_to_user_id: str | None,
    recipient_user_id: str | None,
    unread_only: bool,
    read_filter: str,
    severity: str,
    notification_type: str,
    status: str,
    channel: str,
    search: str,
):
    filters = []
    if visible_to_user_id:
        filters.extend(visibility_filters(visible_to_user_id))
    if recipient_user_id:
        filters.append(Notification.recipient_user_id == recipient_user_id)
    if unread_only:
        filters.append(Notification.is_read.is_(False))
    elif read_filter == "read":
        filters.append(Notification.is_read.is_(True))

    if severity in {item.value for item in AlertPriority}:
        filters.append(Notification.severity == severity)

    if notification_type in {item.value for item in NotificationType}:
        filters.append(Notification.notification_type == notification_type)

    cleaned_status = status.strip().upper()
    if cleaned_status in {item.value for item in NotificationStatus}:
        filters.append(Notification.status == cleaned_status)

    cleaned_channel = channel.strip().upper()
    if cleaned_channel in {item.value for item in NotificationChannel}:
        filters.append(Notification.channel == cleaned_channel)

    cleaned_search = search.strip()
    if cleaned_search:
        pattern = f"%{cleaned_search}%"
        filters.append(
            or_(
                Notification.title.ilike(pattern),
                Notification.message.ilike(pattern),
                Alert.title.ilike(pattern),
                Asset.name.ilike(pattern),
                Asset.hostname.ilike(pattern),
                Vulnerability.cve_id.ilike(pattern),
            )
        )
    return filters


def is_notification_visible_to_user(
    notification: Notification,
    current_user: Utilisateur,
) -> bool:
    return (
        notification.recipient_user_id is None
        or notification.recipient_user_id == current_user.id
    )


def visibility_filters(user_id: str):
    return [
        or_(
            Notification.recipient_user_id.is_(None),
            Notification.recipient_user_id == user_id,
        )
    ]


def notification_status_for_channel(
    channel: NotificationChannel,
) -> NotificationStatus:
    if channel == NotificationChannel.IN_APP:
        return NotificationStatus.SENT
    return NotificationStatus.PENDING


def get_notification_read_options() -> list[tuple[str, str]]:
    return [
        ("all", "Toutes"),
        ("unread", "Non lues"),
        ("read", "Lues"),
    ]


def get_notification_severity_options() -> list[tuple[str, str]]:
    return [
        (AlertPriority.HIGH.value, AlertPriority.HIGH.value),
        (AlertPriority.CRITICAL.value, AlertPriority.CRITICAL.value),
    ]


def get_notification_type_options() -> list[tuple[str, str]]:
    return [
        (item.value, notification_type_label(item))
        for item in NotificationType
    ]


def notification_type_label(value: NotificationType | str | None) -> str:
    normalized = enum_value(value)
    return {
        NotificationType.ALERT_CREATED.value: "Nouvelle alerte",
        NotificationType.ALERT_CRITICAL.value: "Alerte critique",
        NotificationType.ALERT_UPDATED.value: "Mise a jour",
        NotificationType.ALERT_RESOLVED.value: "Resolution",
    }.get(normalized, "Notification")


def notification_status_label(value: NotificationStatus | str | None) -> str:
    normalized = enum_value(value)
    return {
        NotificationStatus.PENDING.value: "En attente",
        NotificationStatus.SENT.value: "Envoyee",
        NotificationStatus.FAILED.value: "Echec",
    }.get(normalized, "Inconnu")


def notification_read_label(is_read: bool | None) -> str:
    return "Lu" if is_read else "Non lu"


def notification_read_tone(is_read: bool | None) -> str:
    return "tone-neutral" if is_read else "tone-info"


def notification_severity_tone(value: AlertPriority | str | None) -> str:
    normalized = enum_value(value)
    return {
        AlertPriority.CRITICAL.value: "tone-critical",
        AlertPriority.HIGH.value: "tone-warning",
        AlertPriority.MEDIUM.value: "tone-info",
        AlertPriority.LOW.value: "tone-success",
    }.get(normalized, "tone-neutral")


def build_notification_title(
    alert: Alert,
    asset: Asset,
    vulnerability: Vulnerability,
) -> str:
    return (
        f"Alerte SOC {enum_value(alert.priority_level)} - "
        f"{vulnerability.cve_id} sur {asset.name}"
    )


def build_notification_message(
    alert: Alert,
    asset: Asset,
    vulnerability: Vulnerability,
) -> str:
    reason = alert.priority_reason or alert.reason or "Priorite SOC calculee."
    return (
        f"Une alerte SOC de priorite {enum_value(alert.priority_level)} a ete "
        f"generee pour {vulnerability.cve_id} sur l'actif {asset.name}. "
        f"Raison principale: {shorten(reason)}"
    )


def build_email_subject(alert: Alert, vulnerability: Vulnerability) -> str:
    return (
        f"[ThreatWatch] Alerte SOC {enum_value(alert.priority_level)} - "
        f"{vulnerability.cve_id}"
    )


def build_email_body(
    alert: Alert,
    asset: Asset,
    vulnerability: Vulnerability,
) -> str:
    cvss_score = vulnerability.cvss_score if vulnerability.cvss_score is not None else "N/A"
    cvss_severity = vulnerability.cvss_severity or "N/A"
    priority_reason = alert.priority_reason or "Priorite SOC calculee."
    correlation_reason = alert.reason or "Correlation MATCH ThreatWatch."
    return "\n".join(
        [
            "ThreatWatch - Notification SOC",
            "",
            f"Alerte: {alert.title}",
            f"CVE: {vulnerability.cve_id}",
            f"Actif: {asset.name}",
            f"Priorite SOC: {enum_value(alert.priority_level)}",
            f"Score SOC: {alert.priority_score}",
            f"CVSS: {cvss_score} ({cvss_severity})",
            f"Criticite actif: {enum_value(asset.criticality)}",
            f"Environnement: {enum_value(asset.environment)}",
            f"Raison de correlation: {correlation_reason}",
            f"Raison priorite: {priority_reason}",
            "",
            f"Lien alerte local: /alerts/{alert.id}",
        ]
    )


def resolve_alert(db: Session, alert_or_id: Alert | str) -> Alert | None:
    if isinstance(alert_or_id, Alert):
        return alert_or_id
    return db.get(Alert, alert_or_id)


def normalize_priority(value) -> AlertPriority | None:
    normalized = enum_value(value)
    if normalized in {item.value for item in AlertPriority}:
        return AlertPriority(normalized)
    return None


def enum_value(value) -> str:
    return getattr(value, "value", str(value or "")).strip().upper()


def shorten(value: str, max_length: int = 240) -> str:
    cleaned = " ".join(value.split())
    if len(cleaned) <= max_length:
        return cleaned
    return cleaned[: max_length - 3].rstrip() + "..."
