"""Webhook d'integration SIEM Wazuh."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Body, Depends, Query, Request, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.core.deps import require_authenticated_user
from app.core.templating import templates
from app.db.database import get_db
from app.models.user import Utilisateur
from app.services.siem_service import (
    NormalizedWazuhAlert,
    asset_correlation_label,
    asset_correlation_tone,
    format_datetime,
    get_available_mitre_techniques,
    get_siem_severity_options,
    get_siem_stats,
    ingest_wazuh_alert,
    list_siem_alerts,
    siem_level_label,
    siem_level_tone,
)

router = APIRouter(tags=["SIEM Integration"])


@router.get("/siem", response_class=HTMLResponse)
def siem_page(
    request: Request,
    q: str = Query("", max_length=120),
    severity: str = Query("", max_length=20),
    technique: str = Query("", max_length=40),
    page: int = Query(1, ge=1),
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    result = list_siem_alerts(
        db=db,
        search=q,
        severity=severity,
        technique=technique,
        page=page,
    )
    return templates.TemplateResponse(
        request,
        "siem/index.html",
        {
            "current_user": current_user,
            "active_page": "siem",
            "result": result,
            "stats": get_siem_stats(db),
            "severity_options": get_siem_severity_options(),
            "mitre_techniques": get_available_mitre_techniques(db),
            "pagination_query": siem_query_string(result),
            "siem_level_label": siem_level_label,
            "siem_level_tone": siem_level_tone,
            "asset_correlation_label": asset_correlation_label,
            "asset_correlation_tone": asset_correlation_tone,
            "format_datetime": format_datetime,
        },
    )


@router.post("/api/v1/siem/wazuh-alert", status_code=status.HTTP_201_CREATED)
async def receive_wazuh_alert(
    payload: dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
):
    rule = payload.get("rule") or {}
    agent = payload.get("agent") or {}
    mitre = rule.get("mitre") or {}

    normalized_alert = NormalizedWazuhAlert(
        agent_id=as_optional_string(agent.get("id")),
        agent_name=as_optional_string(agent.get("name")),
        agent_ip=extract_agent_ip(agent, payload),
        rule_id=as_optional_string(rule.get("id")),
        rule_level=as_optional_int(rule.get("level")),
        description=as_optional_string(rule.get("description")),
        mitre_technique_id=first_value(mitre.get("id")),
        mitre_tactic=first_value(mitre.get("tactic")),
        raw_payload=payload,
    )

    result = ingest_wazuh_alert(db, normalized_alert)
    return {
        "status": "success",
        "siem_alert_id": result.alert.id,
        "asset_id": result.asset.id if result.asset else None,
        "asset_matched": result.asset is not None,
        "boosted_alerts": result.boosted_alerts,
        "agent": result.alert.agent_name,
        "rule_level": result.alert.rule_level,
        "mitre_technique_id": result.alert.mitre_technique_id,
    }


def extract_agent_ip(agent: dict[str, Any], payload: dict[str, Any]) -> str | None:
    data = payload.get("data") or {}
    return (
        as_optional_string(agent.get("ip"))
        or as_optional_string(agent.get("ip_address"))
        or as_optional_string(data.get("srcip"))
        or as_optional_string(data.get("dstip"))
    )


def first_value(value: Any) -> str | None:
    if isinstance(value, list):
        for item in value:
            cleaned = as_optional_string(item)
            if cleaned:
                return cleaned
        return None
    return as_optional_string(value)


def as_optional_string(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def as_optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def siem_query_string(result) -> str:
    return urlencode(
        {
            "q": result.search,
            "severity": result.severity,
            "technique": result.technique,
        }
    )
