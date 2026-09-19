"""
Modele d'inventaire des actifs surveilles par ThreatWatch.

La phase 4.1 stocke les equipements, applications et services qui pourront
etre correles plus tard avec les vulnerabilites connues.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base

if TYPE_CHECKING:
    from app.models.siem_alert import SiemAlert


class AssetType(str, enum.Enum):
    SERVER = "SERVER"
    WORKSTATION = "WORKSTATION"
    NETWORK_DEVICE = "NETWORK_DEVICE"
    APPLICATION = "APPLICATION"
    DATABASE = "DATABASE"
    SECURITY_DEVICE = "SECURITY_DEVICE"
    SERVICE = "SERVICE"
    OTHER = "OTHER"


class AssetCriticality(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AssetEnvironment(str, enum.Enum):
    PRODUCTION = "PRODUCTION"
    PREPRODUCTION = "PREPRODUCTION"
    DEVELOPMENT = "DEVELOPMENT"
    TEST = "TEST"
    OTHER = "OTHER"


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        Index("ix_assets_name", "name"),
        Index("ix_assets_asset_type", "asset_type"),
        Index("ix_assets_criticality", "criticality"),
        Index("ix_assets_environment", "environment"),
        Index("ix_assets_is_active", "is_active"),
        Index("ix_assets_vendor_product", "vendor", "product"),
        Index("ix_assets_cpe", "cpe"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    asset_type: Mapped[AssetType] = mapped_column(
        Enum(AssetType, name="asset_type"),
        nullable=False,
    )

    vendor: Mapped[str | None] = mapped_column(String(150), nullable=True)
    product: Mapped[str | None] = mapped_column(String(200), nullable=True)
    product_version: Mapped[str | None] = mapped_column(String(100), nullable=True)

    operating_system: Mapped[str | None] = mapped_column(String(200), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(100), nullable=True)

    criticality: Mapped[AssetCriticality] = mapped_column(
        Enum(AssetCriticality, name="asset_criticality"),
        nullable=False,
        default=AssetCriticality.MEDIUM,
    )
    environment: Mapped[AssetEnvironment] = mapped_column(
        Enum(AssetEnvironment, name="asset_environment"),
        nullable=False,
        default=AssetEnvironment.PRODUCTION,
    )

    owner: Mapped[str | None] = mapped_column(String(150), nullable=True)
    location: Mapped[str | None] = mapped_column(String(150), nullable=True)

    cpe: Mapped[str | None] = mapped_column(String(500), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    siem_alerts: Mapped[list["SiemAlert"]] = relationship(
        back_populates="asset",
        order_by="SiemAlert.date_detection.desc()",
    )

    def __repr__(self) -> str:
        return f"<Asset {self.name} ({self.asset_type.value})>"
