"""
Service metier des traitements analyste sur les alertes SOC.

Le statut de l'alerte reste la source de verite. Ce service ajoute une trace
historique pour chaque action analyste dans la meme transaction SQLAlchemy.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.models.alert import Alert, AlertStatus
from app.models.alert_treatment import AlertTreatment, AlertTreatmentActionType
from app.models.user import RoleUtilisateur, Utilisateur


MAX_COMMENT_LENGTH = 2000
ALLOWED_ROLES = {RoleUtilisateur.ADMIN, RoleUtilisateur.ANALYSTE}


class AlertTreatmentError(ValueError):
    """Erreur controlee pour les actions analyste sur une alerte."""


def start_alert_treatment(
    db: Session,
    alert_id: str,
    analyst: Utilisateur,
    comment: str | None = None,
) -> Alert | None:
    return apply_status_transition(
        db=db,
        alert_id=alert_id,
        analyst=analyst,
        expected_status=AlertStatus.NEW,
        new_status=AlertStatus.IN_PROGRESS,
        action_type=AlertTreatmentActionType.STARTED,
        comment=comment,
        action_label="prendre en charge",
    )


def resolve_alert_treatment(
    db: Session,
    alert_id: str,
    analyst: Utilisateur,
    comment: str | None = None,
) -> Alert | None:
    return apply_status_transition(
        db=db,
        alert_id=alert_id,
        analyst=analyst,
        expected_status=AlertStatus.IN_PROGRESS,
        new_status=AlertStatus.RESOLVED,
        action_type=AlertTreatmentActionType.RESOLVED,
        comment=comment,
        action_label="resoudre",
    )


def close_alert_treatment(
    db: Session,
    alert_id: str,
    analyst: Utilisateur,
    comment: str | None = None,
) -> Alert | None:
    alert = apply_status_transition(
        db=db,
        alert_id=alert_id,
        analyst=analyst,
        expected_status=AlertStatus.RESOLVED,
        new_status=AlertStatus.CLOSED,
        action_type=AlertTreatmentActionType.CLOSED,
        comment=comment,
        action_label="cloturer",
    )
    if alert is not None:
        alert.is_active = False
        alert.updated_at = datetime.utcnow()
        db.flush()
    return alert


def add_alert_comment(
    db: Session,
    alert_id: str,
    analyst: Utilisateur,
    comment: str,
) -> AlertTreatment | None:
    ensure_user_can_treat_alert(analyst)
    cleaned_comment = normalize_comment(comment, required=True)
    alert = db.get(Alert, alert_id)
    if alert is None:
        return None

    treatment = create_treatment_event(
        db=db,
        alert=alert,
        analyst=analyst,
        action_type=AlertTreatmentActionType.COMMENTED,
        previous_status=alert.status,
        new_status=alert.status,
        comment=cleaned_comment,
    )
    db.flush()
    return treatment


def get_alert_treatment_history(
    db: Session,
    alert_id: str,
) -> list[AlertTreatment]:
    return list(
        db.execute(
            select(AlertTreatment)
            .options(joinedload(AlertTreatment.analyst))
            .where(AlertTreatment.alert_id == alert_id)
            .order_by(AlertTreatment.created_at.desc(), AlertTreatment.id.desc())
        ).scalars()
    )


def apply_status_transition(
    *,
    db: Session,
    alert_id: str,
    analyst: Utilisateur,
    expected_status: AlertStatus,
    new_status: AlertStatus,
    action_type: AlertTreatmentActionType,
    comment: str | None,
    action_label: str,
) -> Alert | None:
    ensure_user_can_treat_alert(analyst)
    cleaned_comment = normalize_comment(comment, required=False)
    alert = db.get(Alert, alert_id)
    if alert is None:
        return None

    previous_status = alert.status
    if previous_status != expected_status:
        raise AlertTreatmentError(
            f"Impossible de {action_label} cette alerte depuis le statut "
            f"{previous_status.value}."
        )

    alert.status = new_status
    alert.updated_at = datetime.utcnow()
    create_treatment_event(
        db=db,
        alert=alert,
        analyst=analyst,
        action_type=action_type,
        previous_status=previous_status,
        new_status=new_status,
        comment=cleaned_comment,
    )
    db.flush()
    return alert


def create_treatment_event(
    *,
    db: Session,
    alert: Alert,
    analyst: Utilisateur,
    action_type: AlertTreatmentActionType,
    previous_status: AlertStatus,
    new_status: AlertStatus,
    comment: str | None,
) -> AlertTreatment:
    treatment = AlertTreatment(
        alert_id=alert.id,
        analyst_id=analyst.id,
        action_type=action_type,
        comment=comment,
        previous_status=previous_status,
        new_status=new_status,
    )
    db.add(treatment)
    return treatment


def ensure_user_can_treat_alert(user: Utilisateur) -> None:
    if user is None or not user.actif or user.role not in ALLOWED_ROLES:
        raise AlertTreatmentError("Utilisateur non autorise a traiter cette alerte.")


def normalize_comment(value: str | None, *, required: bool) -> str | None:
    cleaned = (value or "").strip()
    if required and not cleaned:
        raise AlertTreatmentError("Le commentaire est obligatoire.")
    if len(cleaned) > MAX_COMMENT_LENGTH:
        raise AlertTreatmentError(
            f"Le commentaire ne doit pas depasser {MAX_COMMENT_LENGTH} caracteres."
        )
    return cleaned or None


def action_type_label(value: AlertTreatmentActionType | str | None) -> str:
    normalized = getattr(value, "value", str(value or "")).strip().upper()
    return {
        AlertTreatmentActionType.CREATED.value: "Creation",
        AlertTreatmentActionType.STARTED.value: "Prise en charge",
        AlertTreatmentActionType.COMMENTED.value: "Observation",
        AlertTreatmentActionType.RESOLVED.value: "Resolution",
        AlertTreatmentActionType.CLOSED.value: "Cloture",
        AlertTreatmentActionType.UPDATED.value: "Mise a jour",
    }.get(normalized, "Action")
