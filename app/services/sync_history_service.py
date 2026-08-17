"""
Service de lecture de l'historique des synchronisations.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.sync_history import SyncHistory, SyncStatus

PER_PAGE = 20


@dataclass(frozen=True)
class SyncHistorySearchResult:
    items: list[SyncHistory]
    total: int
    page: int
    per_page: int
    total_pages: int

    @property
    def has_previous(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages


@dataclass(frozen=True)
class SyncOverview:
    total_runs: int
    successful_runs: int
    failed_runs: int
    partial_runs: int
    latest_sync: SyncHistory | None


def list_sync_history(
    db: Session,
    page: int = 1,
    per_page: int = PER_PAGE,
) -> SyncHistorySearchResult:
    page = max(page, 1)
    per_page = max(per_page, 1)
    total = db.scalar(select(func.count(SyncHistory.id))) or 0
    total_pages = max(math.ceil(total / per_page), 1)
    if page > total_pages:
        page = total_pages

    statement = (
        select(SyncHistory)
        .order_by(SyncHistory.started_at.desc(), SyncHistory.created_at.desc())
        .limit(per_page)
        .offset((page - 1) * per_page)
    )
    items = list(db.execute(statement).scalars())

    return SyncHistorySearchResult(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
    )


def get_sync_overview(db: Session) -> SyncOverview:
    total_runs = db.scalar(select(func.count(SyncHistory.id))) or 0
    successful_runs = _count_by_status(db, SyncStatus.SUCCESS)
    failed_runs = _count_by_status(db, SyncStatus.FAILED)
    partial_runs = _count_by_status(db, SyncStatus.PARTIAL)
    latest_sync = db.scalar(
        select(SyncHistory).order_by(SyncHistory.started_at.desc()).limit(1)
    )

    return SyncOverview(
        total_runs=total_runs,
        successful_runs=successful_runs,
        failed_runs=failed_runs,
        partial_runs=partial_runs,
        latest_sync=latest_sync,
    )


def status_tone(status: SyncStatus | str) -> str:
    value = status.value if isinstance(status, SyncStatus) else str(status)
    if value == SyncStatus.SUCCESS.value:
        return "tone-success"
    if value == SyncStatus.FAILED.value:
        return "tone-critical"
    if value == SyncStatus.PARTIAL.value:
        return "tone-warning"
    return "tone-neutral"


def format_duration(started_at: datetime, finished_at: datetime | None) -> str:
    if finished_at is None:
        return "-"

    seconds = max(int((finished_at - started_at).total_seconds()), 0)
    if seconds < 60:
        return f"{seconds}s"

    minutes, remaining_seconds = divmod(seconds, 60)
    return f"{minutes}m {remaining_seconds}s"


def _count_by_status(db: Session, status: SyncStatus) -> int:
    return (
        db.scalar(select(func.count(SyncHistory.id)).where(SyncHistory.status == status))
        or 0
    )
