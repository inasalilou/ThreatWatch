"""
Modele des alertes SIEM recues depuis Wazuh.

Ces evenements conservent le signal brut et son enrichissement MITRE ATT&CK,
puis le rattachent a un actif ThreatWatch lorsque la correlation est possible.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base

if TYPE_CHECKING:
    from app.models.asset import Asset

JSON_VARIANT = JSON().with_variant(JSONB, "postgresql")


class SiemAlert(Base):
    __tablename__ = "siem_alerts"
    __table_args__ = (
        Index("ix_siem_alerts_agent_name", "agent_name"),
        Index("ix_siem_alerts_asset_id", "asset_id"),
        Index("ix_siem_alerts_rule_level", "rule_level"),
        Index("ix_siem_alerts_date_detection", "date_detection"),
        Index("ix_siem_alerts_mitre_technique_id", "mitre_technique_id"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )

    agent_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    agent_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    agent_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    rule_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    rule_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    mitre_technique_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(120), nullable=True)

    raw_payload: Mapped[dict | list | None] = mapped_column(JSON_VARIANT, nullable=True)

    date_detection: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    asset_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
    )

    asset: Mapped["Asset | None"] = relationship(back_populates="siem_alerts")

    def __repr__(self) -> str:
        return f"<SiemAlert {self.agent_name or '-'} {self.rule_id or '-'}>"
