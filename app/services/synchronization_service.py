"""
Service de synchronisation des sources de veille.

Cette phase orchestre uniquement l'import DGSSI vers PostgreSQL. Elle ne cree
pas d'alertes et ne fait aucun enrichissement externe des CVE.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.security_bulletin import BulletinCVE, SecurityBulletin
from app.models.sync_history import SyncHistory, SyncStatus
from app.services.dgssi_collector import (
    DGSSICollector,
    DGSSICollectorError,
    DGSSIBulletinLink,
    NormalizedDgssiBulletin,
)

logger = logging.getLogger(__name__)
_DGSSI_SYNC_LOCK = threading.Lock()


@dataclass(frozen=True)
class DgssiSyncResult:
    source: str
    status: SyncStatus
    items_found: int
    items_processed: int
    items_created: int
    items_known: int
    items_updated: int
    cves_created: int
    errors: list[str]
    sync_history_id: str
    started_at: datetime
    finished_at: datetime | None


def sync_dgssi_bulletins(
    db: Session,
    collector: DGSSICollector | None = None,
    limit: int | None = None,
) -> DgssiSyncResult:
    if not _DGSSI_SYNC_LOCK.acquire(blocking=False):
        return _record_skipped_sync(db)

    try:
        return _sync_dgssi_bulletins_unlocked(db=db, collector=collector, limit=limit)
    finally:
        _DGSSI_SYNC_LOCK.release()


def _record_skipped_sync(db: Session) -> DgssiSyncResult:
    source = "DGSSI"
    message = "Synchronisation DGSSI deja en cours."
    started_at = datetime.utcnow()
    history = SyncHistory(
        source=source,
        started_at=started_at,
        finished_at=started_at,
        status=SyncStatus.PARTIAL,
        items_found=0,
        items_created=0,
        items_updated=0,
        error_message=message,
    )
    db.add(history)
    db.commit()
    db.refresh(history)
    logger.warning(message)

    return DgssiSyncResult(
        source=source,
        status=SyncStatus.PARTIAL,
        items_found=0,
        items_processed=0,
        items_created=0,
        items_known=0,
        items_updated=0,
        cves_created=0,
        errors=[message],
        sync_history_id=history.id,
        started_at=history.started_at,
        finished_at=history.finished_at,
    )


def _sync_dgssi_bulletins_unlocked(
    db: Session,
    collector: DGSSICollector | None = None,
    limit: int | None = None,
) -> DgssiSyncResult:
    collector = collector or DGSSICollector()
    source = "DGSSI"
    started_at = datetime.utcnow()
    history = SyncHistory(
        source=source,
        started_at=started_at,
        status=SyncStatus.PARTIAL,
        items_found=0,
        items_created=0,
        items_updated=0,
    )

    logger.info("Debut synchronisation DGSSI")
    db.add(history)
    db.commit()
    db.refresh(history)

    items_found = 0
    items_processed = 0
    items_created = 0
    items_known = 0
    cves_created = 0
    errors: list[str] = []

    try:
        listing = collector.fetch_listing()
        links = collector.parse_bulletin_links(listing.html, base_url=listing.url)
        items_found = len(links)
        logger.info("%s bulletins detectes", items_found)

        selected_links = links[:limit] if limit is not None else links
        parsed_bulletins = _fetch_bulletins(collector, selected_links, errors)
        items_processed = len(parsed_bulletins)

        for bulletin_data in parsed_bulletins:
            if not bulletin_data.reference:
                message = f"Bulletin ignore sans reference: {bulletin_data.source_url}"
                logger.warning(message)
                errors.append(message)
                continue

            if bulletin_data.publication_date is None:
                message = f"Bulletin ignore sans date de publication: {bulletin_data.source_url}"
                logger.warning(message)
                errors.append(message)
                continue

            if bulletin_exists(db, bulletin_data):
                items_known += 1
                logger.info("Bulletin %s deja connu", bulletin_data.reference)
                continue

            bulletin = create_security_bulletin(bulletin_data)
            db.add(bulletin)
            db.flush()

            unique_cves = sorted({cve_id.upper() for cve_id in bulletin_data.cves})
            for cve_id in unique_cves:
                db.add(BulletinCVE(bulletin_id=bulletin.id, cve_id=cve_id))

            items_created += 1
            cves_created += len(unique_cves)
            logger.info(
                "Nouveau bulletin %s avec %s CVE",
                bulletin.reference,
                len(unique_cves),
            )

        finished_at = datetime.utcnow()
        status = SyncStatus.PARTIAL if errors else SyncStatus.SUCCESS
        history.status = status
        history.finished_at = finished_at
        history.items_found = items_found
        history.items_created = items_created
        history.items_updated = 0
        history.error_message = "\n".join(errors) if errors else None

        db.add(history)
        db.commit()
        db.refresh(history)

        logger.info("Synchronisation DGSSI terminee: %s", status.value)
        return DgssiSyncResult(
            source=source,
            status=status,
            items_found=items_found,
            items_processed=items_processed,
            items_created=items_created,
            items_known=items_known,
            items_updated=0,
            cves_created=cves_created,
            errors=errors,
            sync_history_id=history.id,
            started_at=history.started_at,
            finished_at=history.finished_at,
        )
    except (DGSSICollectorError, SQLAlchemyError, Exception) as exc:
        logger.error("Echec synchronisation DGSSI: %s", exc)
        db.rollback()

        finished_at = datetime.utcnow()
        error_message = f"{exc.__class__.__name__}: {exc}"
        history.status = SyncStatus.FAILED
        history.finished_at = finished_at
        history.items_found = items_found
        history.items_created = 0
        history.items_updated = 0
        history.error_message = error_message

        db.add(history)
        db.commit()
        db.refresh(history)

        return DgssiSyncResult(
            source=source,
            status=SyncStatus.FAILED,
            items_found=items_found,
            items_processed=items_processed,
            items_created=0,
            items_known=items_known,
            items_updated=0,
            cves_created=0,
            errors=[error_message],
            sync_history_id=history.id,
            started_at=history.started_at,
            finished_at=history.finished_at,
        )


def _fetch_bulletins(
    collector: DGSSICollector,
    links: list[DGSSIBulletinLink],
    errors: list[str],
) -> list[NormalizedDgssiBulletin]:
    parsed_bulletins: list[NormalizedDgssiBulletin] = []

    for link in links:
        try:
            parsed_bulletins.append(collector.fetch_and_parse_bulletin(link))
        except DGSSICollectorError as exc:
            message = f"Bulletin non importe ({link.url}): {exc}"
            logger.error(message)
            errors.append(message)

    return parsed_bulletins


def bulletin_exists(db: Session, bulletin_data: NormalizedDgssiBulletin) -> bool:
    conditions = [SecurityBulletin.canonical_key == bulletin_data.canonical_key]
    if bulletin_data.reference:
        conditions.append(
            (SecurityBulletin.source == bulletin_data.source)
            & (SecurityBulletin.reference == bulletin_data.reference)
        )

    statement = select(SecurityBulletin.id).where(or_(*conditions)).limit(1)
    return db.execute(statement).scalar_one_or_none() is not None


def create_security_bulletin(
    bulletin_data: NormalizedDgssiBulletin,
) -> SecurityBulletin:
    return SecurityBulletin(
        external_id=bulletin_data.external_id,
        reference=bulletin_data.reference or "",
        title=bulletin_data.title,
        summary=bulletin_data.summary,
        description=bulletin_data.description,
        bulletin_type=bulletin_data.bulletin_type,
        severity=bulletin_data.severity,
        impact_level=bulletin_data.impact_level,
        publication_date=bulletin_data.publication_date,
        source=bulletin_data.source,
        source_url=bulletin_data.source_url,
        canonical_key=bulletin_data.canonical_key,
        raw_content=bulletin_data.raw_content,
    )
