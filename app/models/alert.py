"""
Modele des alertes SOC issues des correlations.

La phase 5.2 conserve la severite technique CVSS et ajoute une priorite SOC
explicable, calculee a partir du CVSS, de l'actif et de la correlation.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, Numeric, String, Text
from sqlalchemy import UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base

if TYPE_CHECKING:
    from app.models.alert_treatment import AlertTreatment
    from app.models.notification import Notification


class AlertStatus(str, enum.Enum):
    NEW = "NEW"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class AlertSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertPriority(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("correlation_id", name="uq_alerts_correlation_id"),
        Index("ix_alerts_asset_id", "asset_id"),
        Index("ix_alerts_vulnerability_id", "vulnerability_id"),
        Index("ix_alerts_status", "status"),
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_is_active", "is_active"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )

    correlation_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("asset_vulnerability_correlations.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    vulnerability_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, name="alert_severity"),
        nullable=False,
        default=AlertSeverity.MEDIUM,
    )
    priority_score: Mapped[Decimal] = mapped_column(
        Numeric(5, 2),
        nullable=False,
        default=0,
    )
    priority_level: Mapped[AlertPriority] = mapped_column(
        Enum(AlertPriority, name="alert_priority"),
        nullable=False,
        default=AlertPriority.LOW,
    )
    priority_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, name="alert_status"),
        nullable=False,
        default=AlertStatus.NEW,
    )

    source: Mapped[str] = mapped_column(
        String(80), nullable=False, default="CORRELATION"
    )
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    first_detected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    treatments: Mapped[list["AlertTreatment"]] = relationship(
        back_populates="alert",
        cascade="all, delete-orphan",
        order_by="AlertTreatment.created_at.desc()",
    )
    notifications: Mapped[list["Notification"]] = relationship(
        back_populates="alert",
        cascade="all, delete-orphan",
        order_by="Notification.created_at.desc()",
    )

    def __repr__(self) -> str:
        return f"<Alert {self.title} {self.status.value}>"
