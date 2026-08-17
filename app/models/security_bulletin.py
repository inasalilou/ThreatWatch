"""
Modeles lies aux bulletins de securite collectes par ThreatWatch.

La phase 2 stocke les bulletins DGSSI normalises et les identifiants CVE
detectes, sans encore lancer de moteur de correlation ou d'enrichissement CVE.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import Date, DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class SecurityBulletin(Base):
    __tablename__ = "security_bulletins"
    __table_args__ = (
        UniqueConstraint("source", "reference", name="uq_security_bulletins_source_reference"),
        UniqueConstraint("canonical_key", name="uq_security_bulletins_canonical_key"),
        Index("ix_security_bulletins_source_publication_date", "source", "publication_date"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    external_id: Mapped[str | None] = mapped_column(String(150), nullable=True, index=True)
    reference: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    bulletin_type: Mapped[str | None] = mapped_column(String(80), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(80), nullable=True)
    impact_level: Mapped[str | None] = mapped_column(String(80), nullable=True)
    publication_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(80), nullable=False, default="DGSSI", index=True)
    source_url: Mapped[str] = mapped_column(String(1000), nullable=False)
    canonical_key: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    raw_content: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    cves: Mapped[list["BulletinCVE"]] = relationship(
        back_populates="bulletin",
        cascade="all, delete-orphan",
        order_by="BulletinCVE.cve_id",
    )

    def __repr__(self) -> str:
        return f"<SecurityBulletin {self.reference} ({self.source})>"


class BulletinCVE(Base):
    __tablename__ = "bulletin_cves"
    __table_args__ = (
        UniqueConstraint("bulletin_id", "cve_id", name="uq_bulletin_cves_bulletin_cve"),
        Index("ix_bulletin_cves_cve_id", "cve_id"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    bulletin_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("security_bulletins.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    bulletin: Mapped[SecurityBulletin] = relationship(back_populates="cves")

    def __repr__(self) -> str:
        return f"<BulletinCVE {self.cve_id}>"
