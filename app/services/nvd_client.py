"""
Client HTTP minimal pour NVD API 2.0.

Cette couche ne connait pas le modele SQLAlchemy. Elle recupere uniquement le
JSON NVD pour un identifiant CVE precis et transforme les erreurs HTTP/reseau
en exceptions controlees.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from app.core.config import settings


class NVDClientError(RuntimeError):
    """Erreur maitrisee lors d'un appel a NVD."""


@dataclass(frozen=True)
class NVDClient:
    base_url: str = settings.NVD_API_BASE_URL
    api_key: str = settings.NVD_API_KEY
    timeout: float = settings.NVD_HTTP_TIMEOUT
    user_agent: str = settings.NVD_USER_AGENT

    def fetch_cve(self, cve_id: str) -> dict[str, Any]:
        headers = {
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            with httpx.Client(
                timeout=httpx.Timeout(
                    timeout=self.timeout,
                    connect=min(self.timeout, 10),
                    read=self.timeout,
                    write=min(self.timeout, 10),
                    pool=min(self.timeout, 10),
                ),
                headers=headers,
            ) as client:
                response = client.get(self.base_url, params={"cveId": cve_id})
        except httpx.TimeoutException as exc:
            raise NVDClientError("Timeout lors de l'appel NVD") from exc
        except httpx.RequestError as exc:
            raise NVDClientError(f"Erreur reseau NVD: {exc.__class__.__name__}") from exc

        if response.status_code != 200:
            raise NVDClientError(f"Erreur HTTP NVD {response.status_code}")

        try:
            data = response.json()
        except ValueError as exc:
            raise NVDClientError("Reponse JSON NVD invalide") from exc

        if not isinstance(data, dict):
            raise NVDClientError("Format NVD inattendu")

        return data
