"""
Historique des traitements analyste realises sur les alertes SOC.

Chaque entree conserve qui a effectue l'action, le statut avant/apres et le
commentaire eventuel. Les lignes sont conservees meme si l'alerte est cloturee.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base
from app.models.alert import AlertStatus
from app.models.user import Utilisateur  # noqa: F401


class AlertTreatmentActionType(str, enum.Enum):
    CREATED = "CREATED"
    STARTED = "STARTED"
    COMMENTED = "COMMENTED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    UPDATED = "UPDATED"


class AlertTreatment(Base):
    __tablename__ = "alert_treatments"
    __table_args__ = (
        Index("ix_alert_treatments_alert_id", "alert_id"),
        Index("ix_alert_treatments_analyst_id", "analyst_id"),
        Index("ix_alert_treatments_action_type", "action_type"),
        Index("ix_alert_treatments_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    alert_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
    )
    analyst_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("utilisateurs.id", ondelete="RESTRICT"),
        nullable=False,
    )

    action_type: Mapped[AlertTreatmentActionType] = mapped_column(
        Enum(AlertTreatmentActionType, name="alert_treatment_action_type"),
        nullable=False,
    )
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    previous_status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, name="alert_status"),
        nullable=False,
    )
    new_status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, name="alert_status"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    alert = relationship("Alert", back_populates="treatments")
    analyst = relationship("Utilisateur", back_populates="alert_treatments")

    def __repr__(self) -> str:
        return f"<AlertTreatment {self.action_type.value} {self.alert_id}>"
