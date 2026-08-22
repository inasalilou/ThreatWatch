"""
Modele persistant des notifications SOC.

La phase 6.2.1 enregistre uniquement des notifications IN_APP. Aucun envoi
email, push ou reseau n'est effectue ici.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, String, Text
from sqlalchemy import UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.user import Utilisateur


class NotificationType(str, enum.Enum):
    ALERT_CREATED = "ALERT_CREATED"
    ALERT_CRITICAL = "ALERT_CRITICAL"
    ALERT_UPDATED = "ALERT_UPDATED"
    ALERT_RESOLVED = "ALERT_RESOLVED"


class NotificationChannel(str, enum.Enum):
    IN_APP = "IN_APP"
    EMAIL = "EMAIL"


class NotificationStatus(str, enum.Enum):
    PENDING = "PENDING"
    SENT = "SENT"
    FAILED = "FAILED"


class Notification(Base):
    __tablename__ = "notifications"
    __table_args__ = (
        UniqueConstraint(
            "alert_id",
            "notification_type",
            "channel",
            name="uq_notifications_alert_type_channel",
        ),
        Index("ix_notifications_alert_id", "alert_id"),
        Index("ix_notifications_recipient_user_id", "recipient_user_id"),
        Index("ix_notifications_notification_type", "notification_type"),
        Index("ix_notifications_channel", "channel"),
        Index("ix_notifications_status", "status"),
        Index("ix_notifications_is_read", "is_read"),
        Index("ix_notifications_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    alert_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
    )
    recipient_user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("utilisateurs.id", ondelete="SET NULL"),
        nullable=True,
    )

    notification_type: Mapped[NotificationType] = mapped_column(
        Enum(NotificationType, name="notification_type"),
        nullable=False,
        default=NotificationType.ALERT_CREATED,
    )
    channel: Mapped[NotificationChannel] = mapped_column(
        Enum(NotificationChannel, name="notification_channel"),
        nullable=False,
        default=NotificationChannel.IN_APP,
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[NotificationStatus] = mapped_column(
        Enum(NotificationStatus, name="notification_status"),
        nullable=False,
        default=NotificationStatus.PENDING,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    read_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    alert: Mapped["Alert"] = relationship(back_populates="notifications")
    recipient_user: Mapped["Utilisateur | None"] = relationship(
        back_populates="notifications"
    )

    def __repr__(self) -> str:
        return f"<Notification {self.notification_type.value} {self.channel.value}>"
