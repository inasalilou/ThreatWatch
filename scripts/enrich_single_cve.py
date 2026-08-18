"""
Enrichit une seule CVE locale via NVD API 2.0.

Usage :
    .\\.venv\\Scripts\\python.exe scripts\\enrich_single_cve.py CVE-2026-15748

Le script ne traite jamais plusieurs CVE et ne cree pas de Vulnerability
absente de ThreatWatch.
"""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, get_safe_database_url, test_database_connection
from app.models.vulnerability import Vulnerability
from app.services.cve_enrichment_service import (
    CveEnrichmentError,
    enrich_single_cve,
    is_valid_cve_id,
    normalize_cve_id,
)


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: .\\.venv\\Scripts\\python.exe scripts\\enrich_single_cve.py CVE-YYYY-NNNN")
        return 1

    cve_id = normalize_cve_id(sys.argv[1])
    if not is_valid_cve_id(cve_id):
        print(f"Identifiant CVE invalide: {sys.argv[1]}")
        return 1

    print(f"Enrichissement d'une seule CVE avec DATABASE_URL={get_safe_database_url()}")

    try:
        test_database_connection()
        with SessionLocal() as db:
            vulnerability = db.execute(
                select(Vulnerability).where(Vulnerability.cve_id == cve_id)
            ).scalar_one_or_none()
            if vulnerability is None:
                print(f"CVE absente de ThreatWatch: {cve_id}")
                return 1

            result = enrich_single_cve(db=db, cve_id=cve_id)
            print_result(result)
            return 0 if result.new_status.value == "SUCCESS" else 1
    except CveEnrichmentError as exc:
        print(f"ERREUR: {exc}")
        return 1
    except SQLAlchemyError as exc:
        print(f"ERREUR PostgreSQL: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def print_result(result) -> None:
    print(f"CVE: {result.cve_id}")
    print(f"Ancien statut: {result.old_status.value}")
    print(f"Source: {result.source}")

    if result.description:
        summary = result.description
        if len(summary) > 300:
            summary = summary[:297] + "..."
        print(f"Description: {summary}")
    else:
        print("Description: -")

    print(f"CVSS: {result.cvss_score if result.cvss_score is not None else '-'}")
    print(f"Severity: {result.cvss_severity or '-'}")
    print(f"Version: {result.cvss_version or '-'}")
    print(f"Vector: {result.cvss_vector or '-'}")
    print(f"CWE: {', '.join(result.cwes) if result.cwes else '-'}")
    print(f"References: {result.reference_count}")
    print(f"Published: {result.published_at or '-'}")
    print(f"Modified: {result.modified_at or '-'}")
    if result.error_message:
        print(f"Erreur: {result.error_message}")
    print(f"Nouveau statut: {result.new_status.value}")

    if result.new_status.value == "SUCCESS":
        print("CVE ENRICHMENT: OK")
    else:
        print("CVE ENRICHMENT: FAILED")


if __name__ == "__main__":
    raise SystemExit(main())
