"""
Service de lecture des bulletins de securite.

Les routes web appellent ce service pour garder la logique PostgreSQL hors des
templates et eviter les requetes SQL construites a la main.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import date

from sqlalchemy import distinct, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.models.security_bulletin import BulletinCVE, SecurityBulletin


PER_PAGE = 20


@dataclass(frozen=True)
class BulletinListItem:
    bulletin: SecurityBulletin
    cve_count: int


@dataclass(frozen=True)
class BulletinSearchResult:
    items: list[BulletinListItem]
    total: int
    page: int
    per_page: int
    total_pages: int
    query: str
    severity: str

    @property
    def has_previous(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages


@dataclass(frozen=True)
class BulletinStats:
    total_bulletins: int
    total_cves: int
    critical_bulletins: int
    latest_publication_date: date | None


def list_bulletins(
    db: Session,
    query: str = "",
    severity: str = "",
    page: int = 1,
    per_page: int = PER_PAGE,
) -> BulletinSearchResult:
    page = max(page, 1)
    per_page = max(per_page, 1)
    cleaned_query = query.strip()
    cleaned_severity = severity.strip()
    filters = build_bulletin_filters(cleaned_query, cleaned_severity)

    total_statement = select(func.count(distinct(SecurityBulletin.id)))
    if cleaned_query:
        total_statement = total_statement.outerjoin(SecurityBulletin.cves)
    if filters:
        total_statement = total_statement.where(*filters)

    total = db.scalar(total_statement) or 0
    total_pages = max(math.ceil(total / per_page), 1)
    if page > total_pages:
        page = total_pages

    cve_count = func.count(BulletinCVE.id).label("cve_count")
    statement = (
        select(SecurityBulletin, cve_count)
        .outerjoin(SecurityBulletin.cves)
        .group_by(SecurityBulletin.id)
        .order_by(
            SecurityBulletin.publication_date.desc(),
            SecurityBulletin.created_at.desc(),
            SecurityBulletin.reference.desc(),
        )
        .limit(per_page)
        .offset((page - 1) * per_page)
    )
    if filters:
        statement = statement.where(*filters)

    rows = db.execute(statement).all()
    items = [
        BulletinListItem(bulletin=bulletin, cve_count=cve_count_value)
        for bulletin, cve_count_value in rows
    ]

    return BulletinSearchResult(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        query=cleaned_query,
        severity=cleaned_severity,
    )


def get_bulletin_by_id(db: Session, bulletin_id: str) -> SecurityBulletin | None:
    return db.get(
        SecurityBulletin,
        bulletin_id,
        options=[selectinload(SecurityBulletin.cves)],
    )


def get_bulletin_stats(db: Session) -> BulletinStats:
    total_bulletins = db.scalar(select(func.count(SecurityBulletin.id))) or 0
    total_cves = db.scalar(select(func.count(BulletinCVE.id))) or 0
    critical_bulletins = (
        db.scalar(
            select(func.count(SecurityBulletin.id)).where(
                SecurityBulletin.severity.ilike("critique")
            )
        )
        or 0
    )
    latest_publication_date = db.scalar(select(func.max(SecurityBulletin.publication_date)))

    return BulletinStats(
        total_bulletins=total_bulletins,
        total_cves=total_cves,
        critical_bulletins=critical_bulletins,
        latest_publication_date=latest_publication_date,
    )


def get_available_severities(db: Session) -> list[str]:
    rows = db.execute(
        select(distinct(SecurityBulletin.severity))
        .where(SecurityBulletin.severity.is_not(None))
        .order_by(SecurityBulletin.severity.asc())
    ).scalars()
    return [severity for severity in rows if severity]


def build_bulletin_filters(query: str, severity: str):
    filters = []

    if query:
        pattern = f"%{query}%"
        filters.append(
            or_(
                SecurityBulletin.reference.ilike(pattern),
                SecurityBulletin.title.ilike(pattern),
                BulletinCVE.cve_id.ilike(pattern),
            )
        )

    if severity:
        filters.append(SecurityBulletin.severity == severity)

    return filters


def severity_tone(severity: str | None) -> str:
    if not severity:
        return "tone-neutral"

    normalized = severity.strip().lower()
    if normalized == "critique":
        return "tone-critical"
    if normalized in {"important", "eleve", "elevé"}:
        return "tone-warning"
    if normalized in {"modere", "modéré", "moyen"}:
        return "tone-info"
    if normalized == "faible":
        return "tone-success"
    return "tone-neutral"
