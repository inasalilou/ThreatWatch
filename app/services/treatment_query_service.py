"""
Lecture des traitements analyste pour l'interface /treatments.

Ce service est strictement consultatif: il ne modifie ni les alertes ni
l'historique des traitements.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import date, datetime, time

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertStatus
from app.models.alert_treatment import AlertTreatment, AlertTreatmentActionType
from app.models.asset import Asset
from app.models.user import RoleUtilisateur, Utilisateur
from app.models.vulnerability import Vulnerability


PER_PAGE = 20


@dataclass(frozen=True)
class TreatmentListItem:
    treatment: AlertTreatment
    alert: Alert
    asset: Asset
    vulnerability: Vulnerability
    analyst: Utilisateur


@dataclass(frozen=True)
class TreatmentSearchResult:
    items: list[TreatmentListItem]
    total: int
    page: int
    per_page: int
    total_pages: int
    analyst_id: str
    role: str
    action_type: str
    new_status: str
    date_from: date | None
    date_to: date | None
    search: str

    @property
    def has_previous(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages


@dataclass(frozen=True)
class TreatmentStats:
    total_actions: int
    started_actions: int
    commented_actions: int
    resolved_actions: int
    closed_actions: int


def list_treatments(
    db: Session,
    analyst_id: str = "",
    role: str = "",
    action_type: str = "",
    new_status: str = "",
    date_from: date | None = None,
    date_to: date | None = None,
    search: str = "",
    page: int = 1,
    per_page: int = PER_PAGE,
) -> TreatmentSearchResult:
    page = max(page, 1)
    per_page = max(per_page, 1)
    cleaned_analyst_id = analyst_id.strip()
    cleaned_role = role.strip().upper()
    cleaned_action_type = action_type.strip().upper()
    cleaned_new_status = new_status.strip().upper()
    cleaned_search = search.strip()

    filters = build_treatment_filters(
        analyst_id=cleaned_analyst_id,
        role=cleaned_role,
        action_type=cleaned_action_type,
        new_status=cleaned_new_status,
        date_from=date_from,
        date_to=date_to,
        search=cleaned_search,
    )

    base_statement = (
        select(AlertTreatment.id)
        .join(Alert, AlertTreatment.alert_id == Alert.id)
        .join(Asset, Alert.asset_id == Asset.id)
        .join(Vulnerability, Alert.vulnerability_id == Vulnerability.id)
        .join(Utilisateur, AlertTreatment.analyst_id == Utilisateur.id)
        .where(*filters)
    )
    total = db.scalar(select(func.count()).select_from(base_statement.subquery())) or 0
    total_pages = max(math.ceil(total / per_page), 1)
    if page > total_pages:
        page = total_pages

    statement = (
        select(AlertTreatment, Alert, Asset, Vulnerability, Utilisateur)
        .join(Alert, AlertTreatment.alert_id == Alert.id)
        .join(Asset, Alert.asset_id == Asset.id)
        .join(Vulnerability, Alert.vulnerability_id == Vulnerability.id)
        .join(Utilisateur, AlertTreatment.analyst_id == Utilisateur.id)
        .where(*filters)
        .order_by(AlertTreatment.created_at.desc(), AlertTreatment.id.desc())
        .limit(per_page)
        .offset((page - 1) * per_page)
    )

    return TreatmentSearchResult(
        items=[
            TreatmentListItem(
                treatment=treatment,
                alert=alert,
                asset=asset,
                vulnerability=vulnerability,
                analyst=analyst,
            )
            for treatment, alert, asset, vulnerability, analyst in db.execute(
                statement
            ).all()
        ],
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        analyst_id=cleaned_analyst_id,
        role=cleaned_role,
        action_type=cleaned_action_type,
        new_status=cleaned_new_status,
        date_from=date_from,
        date_to=date_to,
        search=cleaned_search,
    )


def get_treatment_stats(db: Session) -> TreatmentStats:
    total_actions = db.scalar(select(func.count(AlertTreatment.id))) or 0
    return TreatmentStats(
        total_actions=total_actions,
        started_actions=count_actions_by_type(db, AlertTreatmentActionType.STARTED),
        commented_actions=count_actions_by_type(db, AlertTreatmentActionType.COMMENTED),
        resolved_actions=count_actions_by_type(db, AlertTreatmentActionType.RESOLVED),
        closed_actions=count_actions_by_type(db, AlertTreatmentActionType.CLOSED),
    )


def get_treatment_analyst_options(db: Session) -> list[tuple[str, str]]:
    rows = db.execute(
        select(Utilisateur.id, Utilisateur.nom)
        .join(AlertTreatment, AlertTreatment.analyst_id == Utilisateur.id)
        .group_by(Utilisateur.id, Utilisateur.nom)
        .order_by(Utilisateur.nom.asc())
    ).all()
    return [(user_id, name) for user_id, name in rows]


def get_treatment_action_options() -> list[tuple[str, str]]:
    return [(action.value, action.value) for action in AlertTreatmentActionType]


def get_treatment_alert_status_options() -> list[tuple[str, str]]:
    return [(status.value, status.value) for status in AlertStatus]


def get_treatment_role_options() -> list[tuple[str, str]]:
    return [(role.value, role.value) for role in RoleUtilisateur]


def build_treatment_filters(
    *,
    analyst_id: str,
    role: str,
    action_type: str,
    new_status: str,
    date_from: date | None,
    date_to: date | None,
    search: str,
):
    filters = []

    if analyst_id:
        filters.append(AlertTreatment.analyst_id == analyst_id)

    if role in {item.value for item in RoleUtilisateur}:
        filters.append(Utilisateur.role == role)

    if action_type in {item.value for item in AlertTreatmentActionType}:
        filters.append(AlertTreatment.action_type == action_type)

    if new_status in {item.value for item in AlertStatus}:
        filters.append(AlertTreatment.new_status == new_status)

    if date_from is not None:
        filters.append(AlertTreatment.created_at >= datetime.combine(date_from, time.min))

    if date_to is not None:
        filters.append(AlertTreatment.created_at <= datetime.combine(date_to, time.max))

    if search:
        pattern = f"%{search}%"
        filters.append(
            or_(
                Vulnerability.cve_id.ilike(pattern),
                Asset.name.ilike(pattern),
                Asset.hostname.ilike(pattern),
                Alert.title.ilike(pattern),
                Utilisateur.nom.ilike(pattern),
                Utilisateur.email.ilike(pattern),
                AlertTreatment.comment.ilike(pattern),
            )
        )

    return filters


def count_alerts_by_status(db: Session, status: AlertStatus) -> int:
    return db.scalar(select(func.count(Alert.id)).where(Alert.status == status)) or 0


def count_actions_by_type(db: Session, action_type: AlertTreatmentActionType) -> int:
    return (
        db.scalar(
            select(func.count(AlertTreatment.id)).where(
                AlertTreatment.action_type == action_type
            )
        )
        or 0
    )
