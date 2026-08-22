"""
Service metier des sources de veille.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from urllib.parse import urlparse

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.sync_history import SyncHistory, SyncStatus
from app.models.threat_source import ThreatSource, ThreatSourceType


PER_PAGE = 20
DGSSI_CODE = "DGSSI"


class ThreatSourceValidationError(ValueError):
    """Erreur controlee de validation d'une source de veille."""


@dataclass(frozen=True)
class ThreatSourceSearchResult:
    items: list[ThreatSource]
    total: int
    page: int
    per_page: int
    total_pages: int
    search: str
    source_type: str
    status: str
    sync_enabled: str

    @property
    def has_previous(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages


@dataclass(frozen=True)
class ThreatSourceStats:
    total_sources: int
    active_sources: int
    sync_enabled_sources: int
    failed_sources: int


def initialize_default_threat_sources(db: Session) -> tuple[ThreatSource, bool]:
    latest_sync = get_latest_sync_for_source(db, DGSSI_CODE)
    source = get_source_by_code(db, DGSSI_CODE)
    if source is not None:
        apply_latest_sync(source, latest_sync)
        db.flush()
        return source, False

    source = ThreatSource(
        name="DGSSI / maCERT",
        code=DGSSI_CODE,
        source_type=ThreatSourceType.WEB,
        base_url=settings.DGSSI_SOURCE_URL,
        description=(
            "Source officielle marocaine de bulletins de securite utilisee "
            "par ThreatWatch pour alimenter la veille."
        ),
        provider="DGSSI / maCERT",
        country="Maroc",
        is_active=True,
        sync_enabled=True,
        sync_interval_minutes=settings.DGSSI_SYNC_INTERVAL_MINUTES,
    )
    apply_latest_sync(source, latest_sync)
    db.add(source)
    db.flush()
    return source, True


def create_source(
    db: Session,
    *,
    name: str,
    code: str,
    source_type: str,
    base_url: str,
    description: str = "",
    sync_enabled: bool = True,
    sync_interval_minutes: int | str = 60,
) -> ThreatSource:
    cleaned = clean_source_data(
        name=name,
        code=code,
        source_type=source_type,
        base_url=base_url,
        description=description,
        sync_enabled=sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
    )
    if get_source_by_code(db, cleaned["code"]) is not None:
        raise ThreatSourceValidationError("Une source avec ce code existe deja.")

    source = ThreatSource(**cleaned)
    db.add(source)
    db.flush()
    return source


def update_source(
    db: Session,
    source_id: str,
    *,
    name: str,
    code: str,
    source_type: str,
    base_url: str,
    description: str = "",
    sync_enabled: bool = True,
    sync_interval_minutes: int | str = 60,
) -> ThreatSource | None:
    source = get_source_by_id(db, source_id)
    if source is None:
        return None

    cleaned = clean_source_data(
        name=name,
        code=code,
        source_type=source_type,
        base_url=base_url,
        description=description,
        sync_enabled=sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
    )
    existing = get_source_by_code(db, cleaned["code"])
    if existing is not None and existing.id != source.id:
        raise ThreatSourceValidationError("Une source avec ce code existe deja.")

    for key, value in cleaned.items():
        setattr(source, key, value)
    db.flush()
    return source


def get_source_by_id(db: Session, source_id: str) -> ThreatSource | None:
    return db.get(ThreatSource, source_id)


def get_source_by_code(db: Session, code: str) -> ThreatSource | None:
    normalized = normalize_code(code)
    if not normalized:
        return None
    return db.execute(
        select(ThreatSource).where(ThreatSource.code == normalized)
    ).scalar_one_or_none()


def enable_source(db: Session, source_id: str) -> ThreatSource | None:
    source = get_source_by_id(db, source_id)
    if source is None:
        return None
    source.is_active = True
    db.flush()
    return source


def disable_source(db: Session, source_id: str) -> ThreatSource | None:
    source = get_source_by_id(db, source_id)
    if source is None:
        return None
    source.is_active = False
    db.flush()
    return source


def list_sources(
    db: Session,
    *,
    search: str = "",
    source_type: str = "",
    status: str = "",
    sync_enabled: str = "",
    page: int = 1,
    per_page: int = PER_PAGE,
) -> ThreatSourceSearchResult:
    page = max(page, 1)
    per_page = max(per_page, 1)
    cleaned_search = search.strip()
    cleaned_type = source_type.strip().upper()
    cleaned_status = status.strip().lower()
    cleaned_sync = sync_enabled.strip().lower()
    filters = build_source_filters(
        search=cleaned_search,
        source_type=cleaned_type,
        status=cleaned_status,
        sync_enabled=cleaned_sync,
    )

    total = db.scalar(select(func.count(ThreatSource.id)).where(*filters)) or 0
    total_pages = max(math.ceil(total / per_page), 1)
    if page > total_pages:
        page = total_pages

    items = list(
        db.execute(
            select(ThreatSource)
            .where(*filters)
            .order_by(
                ThreatSource.is_active.desc(),
                ThreatSource.sync_enabled.desc(),
                ThreatSource.name.asc(),
            )
            .limit(per_page)
            .offset((page - 1) * per_page)
        ).scalars()
    )

    return ThreatSourceSearchResult(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        search=cleaned_search,
        source_type=cleaned_type,
        status=cleaned_status,
        sync_enabled=cleaned_sync,
    )


def get_source_stats(db: Session) -> ThreatSourceStats:
    return ThreatSourceStats(
        total_sources=db.scalar(select(func.count(ThreatSource.id))) or 0,
        active_sources=db.scalar(
            select(func.count(ThreatSource.id)).where(ThreatSource.is_active.is_(True))
        )
        or 0,
        sync_enabled_sources=db.scalar(
            select(func.count(ThreatSource.id)).where(
                ThreatSource.sync_enabled.is_(True)
            )
        )
        or 0,
        failed_sources=db.scalar(
            select(func.count(ThreatSource.id)).where(
                ThreatSource.last_sync_status == SyncStatus.FAILED.value
            )
        )
        or 0,
    )


def get_latest_sync_for_source(db: Session, code: str) -> SyncHistory | None:
    normalized = normalize_code(code)
    if not normalized:
        return None
    return db.execute(
        select(SyncHistory)
        .where(SyncHistory.source == normalized)
        .order_by(SyncHistory.started_at.desc(), SyncHistory.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def list_recent_syncs_for_source(
    db: Session,
    code: str,
    limit: int = 5,
) -> list[SyncHistory]:
    normalized = normalize_code(code)
    if not normalized:
        return []
    return list(
        db.execute(
            select(SyncHistory)
            .where(SyncHistory.source == normalized)
            .order_by(SyncHistory.started_at.desc(), SyncHistory.created_at.desc())
            .limit(limit)
        ).scalars()
    )


def apply_latest_sync(
    source: ThreatSource,
    latest_sync: SyncHistory | None,
) -> None:
    if latest_sync is None:
        return
    source.last_sync_at = latest_sync.finished_at or latest_sync.started_at
    source.last_sync_status = latest_sync.status.value


def clean_source_data(
    *,
    name: str,
    code: str,
    source_type: str,
    base_url: str,
    description: str,
    sync_enabled: bool,
    sync_interval_minutes: int | str,
) -> dict:
    cleaned_name = (name or "").strip()
    cleaned_code = normalize_code(code)
    cleaned_url = (base_url or "").strip()
    cleaned_description = (description or "").strip()
    cleaned_type = (source_type or "").strip().upper()

    if not cleaned_name:
        raise ThreatSourceValidationError("Le nom est obligatoire.")
    if not cleaned_code:
        raise ThreatSourceValidationError("Le code est obligatoire.")
    if cleaned_type not in {item.value for item in ThreatSourceType}:
        raise ThreatSourceValidationError("Type de source invalide.")
    if not is_valid_url(cleaned_url):
        raise ThreatSourceValidationError("URL invalide.")

    try:
        interval = int(sync_interval_minutes)
    except (TypeError, ValueError):
        raise ThreatSourceValidationError("Intervalle de synchronisation invalide.")
    if interval <= 0:
        raise ThreatSourceValidationError("L'intervalle doit etre positif.")

    return {
        "name": cleaned_name,
        "code": cleaned_code,
        "source_type": ThreatSourceType(cleaned_type),
        "base_url": cleaned_url,
        "description": cleaned_description or None,
        "sync_enabled": bool(sync_enabled),
        "sync_interval_minutes": interval,
    }


def build_source_filters(
    *,
    search: str,
    source_type: str,
    status: str,
    sync_enabled: str,
):
    filters = []
    if search:
        pattern = f"%{search}%"
        filters.append(
            or_(
                ThreatSource.name.ilike(pattern),
                ThreatSource.code.ilike(pattern),
                ThreatSource.base_url.ilike(pattern),
            )
        )
    if source_type in {item.value for item in ThreatSourceType}:
        filters.append(ThreatSource.source_type == source_type)
    if status == "active":
        filters.append(ThreatSource.is_active.is_(True))
    elif status == "inactive":
        filters.append(ThreatSource.is_active.is_(False))
    if sync_enabled == "enabled":
        filters.append(ThreatSource.sync_enabled.is_(True))
    elif sync_enabled == "disabled":
        filters.append(ThreatSource.sync_enabled.is_(False))
    return filters


def is_valid_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def normalize_code(value: str | None) -> str:
    return (value or "").strip().upper()


def get_source_type_options() -> list[tuple[str, str]]:
    return [(item.value, source_type_label(item)) for item in ThreatSourceType]


def get_source_status_options() -> list[tuple[str, str]]:
    return [("active", "Actives"), ("inactive", "Inactives")]


def get_source_sync_options() -> list[tuple[str, str]]:
    return [("enabled", "Activee"), ("disabled", "Desactivee")]


def source_type_label(value: ThreatSourceType | str | None) -> str:
    normalized = getattr(value, "value", str(value or "")).strip().upper()
    return {
        ThreatSourceType.WEB.value: "Web",
        ThreatSourceType.API.value: "API",
        ThreatSourceType.RSS.value: "RSS",
        ThreatSourceType.MANUAL.value: "Manuelle",
    }.get(normalized, "Inconnu")


def active_label(value: bool | None) -> str:
    return "Oui" if value else "Non"


def active_tone(value: bool | None) -> str:
    return "tone-success" if value else "tone-neutral"


def sync_status_tone(value: str | None) -> str:
    if value == SyncStatus.SUCCESS.value:
        return "tone-success"
    if value == SyncStatus.FAILED.value:
        return "tone-critical"
    if value == SyncStatus.PARTIAL.value:
        return "tone-warning"
    return "tone-neutral"
