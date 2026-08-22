"""
Modele persistant des sources de veille.

Phase 6.3: represente les sources comme DGSSI / maCERT sans modifier les
collecteurs existants.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Index, Integer, String, Text
from sqlalchemy import UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class ThreatSourceType(str, enum.Enum):
    WEB = "WEB"
    API = "API"
    RSS = "RSS"
    MANUAL = "MANUAL"


class ThreatSource(Base):
    __tablename__ = "threat_sources"
    __table_args__ = (
        UniqueConstraint("code", name="uq_threat_sources_code"),
        Index("ix_threat_sources_name", "name"),
        Index("ix_threat_sources_code", "code"),
        Index("ix_threat_sources_source_type", "source_type"),
        Index("ix_threat_sources_is_active", "is_active"),
        Index("ix_threat_sources_sync_enabled", "sync_enabled"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    code: Mapped[str] = mapped_column(String(40), nullable=False)
    source_type: Mapped[ThreatSourceType] = mapped_column(
        Enum(ThreatSourceType, name="threat_source_type"),
        nullable=False,
        default=ThreatSourceType.WEB,
    )
    base_url: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    provider: Mapped[str | None] = mapped_column(String(120), nullable=True)
    country: Mapped[str | None] = mapped_column(String(80), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    sync_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    sync_interval_minutes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=60,
    )
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_sync_status: Mapped[str | None] = mapped_column(String(20), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    def __repr__(self) -> str:
        return f"<ThreatSource {self.code} {self.source_type.value}>"
