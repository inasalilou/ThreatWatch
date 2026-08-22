"""
Planification legere des synchronisations automatiques.

Le scheduler reste optionnel : si la configuration le desactive, l'application
FastAPI demarre sans tache de fond.
"""
from __future__ import annotations

import logging
import traceback
from datetime import datetime, timezone
from typing import Any

try:
    from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED, EVENT_JOB_MISSED
    from apscheduler.schedulers.background import BackgroundScheduler
except ImportError:  # pragma: no cover - dependance installee via requirements.txt
    BackgroundScheduler = None  # type: ignore[assignment]
    EVENT_JOB_ERROR = EVENT_JOB_EXECUTED = EVENT_JOB_MISSED = None  # type: ignore[assignment]

from app.core.config import settings
from app.db.database import SessionLocal
from app.models.sync_history import SyncStatus
from app.services.soc_orchestration_service import process_pending_security_pipeline
from app.services.synchronization_service import sync_dgssi_bulletins

logger = logging.getLogger(__name__)
uvicorn_logger = logging.getLogger("uvicorn.error")

_scheduler: Any | None = None
_DGSSI_JOB_ID = "dgssi_sync"


def run_scheduled_dgssi_sync() -> None:
    """Execute une synchronisation DGSSI avec sa propre session SQLAlchemy."""
    _log_info("[DGSSI Scheduler] Automatic synchronization started")
    db = SessionLocal()
    try:
        result = sync_dgssi_bulletins(db)
        _log_info(
            "[DGSSI Scheduler] Automatic synchronization completed: "
            "status=%s found=%s created=%s known=%s",
            result.status.value,
            result.items_found,
            result.items_created,
            result.items_known,
        )
        if result.status in {SyncStatus.SUCCESS, SyncStatus.PARTIAL}:
            pipeline_result = process_pending_security_pipeline(db)
            _log_info(
                "[SOC Pipeline] Scheduler run completed: selected=%s success=%s "
                "matches=%s alerts=%s notifications=%s duration=%ss",
                pipeline_result.selected_vulnerabilities,
                pipeline_result.enriched_success,
                pipeline_result.matches,
                pipeline_result.alerts_created_or_updated,
                pipeline_result.notifications_created_or_updated,
                pipeline_result.duration_seconds,
            )
    except Exception as exc:  # le scheduler ne doit jamais arreter FastAPI
        _log_exception("[DGSSI Scheduler] ERROR: automatic synchronization failed: %s", exc)
    finally:
        db.close()


def start_scheduler() -> None:
    """Demarre le scheduler si DGSSI_SYNC_ENABLED=true."""
    global _scheduler

    if not settings.DGSSI_SYNC_ENABLED:
        _log_info("[DGSSI Scheduler] Scheduler disabled")
        return

    if BackgroundScheduler is None:
        _log_error(
            "[DGSSI Scheduler] ERROR: APScheduler unavailable; "
            "install dependencies with requirements.txt"
        )
        return

    try:
        if _scheduler is not None and getattr(_scheduler, "running", False):
            _log_info("[DGSSI Scheduler] Scheduler already running")
            return

        interval_minutes = max(settings.DGSSI_SYNC_INTERVAL_MINUTES, 1)
        scheduler = BackgroundScheduler(timezone="UTC")
        job_options: dict[str, Any] = {
            "func": run_scheduled_dgssi_sync,
            "trigger": "interval",
            "minutes": interval_minutes,
            "id": _DGSSI_JOB_ID,
            "replace_existing": True,
            "max_instances": 1,
            "coalesce": True,
        }
        if settings.DGSSI_SYNC_ON_STARTUP:
            job_options["next_run_time"] = datetime.now(timezone.utc)

        job = scheduler.add_job(**job_options)
        if EVENT_JOB_ERROR is not None:
            scheduler.add_listener(
                _scheduler_listener,
                EVENT_JOB_EXECUTED | EVENT_JOB_ERROR | EVENT_JOB_MISSED,
            )
        scheduler.start()
        _scheduler = scheduler
        _log_info(
            "[DGSSI Scheduler] Scheduler started: interval=%s minute(s), "
            "on_startup=%s",
            interval_minutes,
            settings.DGSSI_SYNC_ON_STARTUP,
        )
        _log_info("[DGSSI Scheduler] Job registered: id=%s", job.id)
        _log_info("[DGSSI Scheduler] Next run: %s", job.next_run_time)
    except Exception as exc:
        _log_exception("[DGSSI Scheduler] ERROR: scheduler startup failed: %s", exc)


def stop_scheduler() -> None:
    """Arrete proprement le scheduler au shutdown FastAPI."""
    global _scheduler

    if _scheduler is None:
        return

    try:
        if getattr(_scheduler, "running", False):
            _scheduler.shutdown(wait=False)
            _log_info("[DGSSI Scheduler] Scheduler stopped")
    except Exception as exc:
        _log_exception("[DGSSI Scheduler] ERROR: scheduler shutdown failed: %s", exc)
    finally:
        _scheduler = None


def get_scheduler_state() -> dict[str, Any]:
    """Expose l'etat courant pour l'interface /synchronizations."""
    running = _scheduler is not None and getattr(_scheduler, "running", False)
    next_run_time = None
    if running:
        job = _scheduler.get_job(_DGSSI_JOB_ID)
        next_run_time = job.next_run_time if job else None

    return {
        "enabled": settings.DGSSI_SYNC_ENABLED,
        "interval_minutes": max(settings.DGSSI_SYNC_INTERVAL_MINUTES, 1),
        "on_startup": settings.DGSSI_SYNC_ON_STARTUP,
        "running": running,
        "next_run_time": next_run_time,
    }


def _scheduler_listener(event: Any) -> None:
    if getattr(event, "exception", None):
        _log_error("[DGSSI Scheduler] ERROR: job event failed: %s", event.exception)
        if getattr(event, "traceback", None):
            print(event.traceback, flush=True)
        return

    if getattr(event, "code", None) == EVENT_JOB_MISSED:
        _log_error("[DGSSI Scheduler] ERROR: job missed: %s", event.job_id)


def _log_info(message: str, *args: Any) -> None:
    print(_format_message(message, args), flush=True)
    logger.info(message, *args)
    uvicorn_logger.info(message, *args)


def _log_error(message: str, *args: Any) -> None:
    print(_format_message(message, args), flush=True)
    logger.error(message, *args)
    uvicorn_logger.error(message, *args)


def _log_exception(message: str, *args: Any) -> None:
    print(_format_message(message, args), flush=True)
    traceback.print_exc()
    logger.exception(message, *args)
    uvicorn_logger.exception(message, *args)


def _format_message(message: str, args: tuple[Any, ...]) -> str:
    if not args:
        return message
    try:
        return message % args
    except TypeError:
        return f"{message} {' '.join(str(arg) for arg in args)}"
