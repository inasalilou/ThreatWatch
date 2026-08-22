r"""
Diagnostic read-only des configurations NVD pour une CVE.

Usage:
    .\.venv\Scripts\python.exe scripts\diagnose_nvd_affected_products.py CVE-2026-15748

Le script appelle le client NVD existant, n'ecrit rien en base et ne commit
jamais la session.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import func, select

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, get_safe_database_url, test_database_connection  # noqa: E402
from app.models.vulnerability import Vulnerability  # noqa: E402
from app.models.vulnerability_affected_product import VulnerabilityAffectedProduct  # noqa: E402
from app.services.cve_enrichment_service import (  # noqa: E402
    extract_affected_products,
    extract_matching_nvd_record,
    normalize_cve_id,
)
from app.services.nvd_client import NVDClient, NVDClientError  # noqa: E402


@dataclass
class CpeMatchSummary:
    criteria: str | None
    vulnerable: bool | None
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None


@dataclass
class ConfigurationSummary:
    has_configurations: bool = False
    has_nodes: bool = False
    has_cpe_match: bool = False
    configuration_count: int = 0
    node_count: int = 0
    cpe_match_count: int = 0
    cpe_matches: list[CpeMatchSummary] = field(default_factory=list)
    structure_notes: list[str] = field(default_factory=list)


def main() -> int:
    args = parse_args()
    cve_id = normalize_cve_id(args.cve_id)

    print("ThreatWatch - diagnostic NVD affected products")
    print(f"DATABASE_URL={get_safe_database_url()}")
    print(f"CVE cible={cve_id}")
    print("")

    try:
        test_database_connection()
        db_summary = load_db_summary(cve_id)
        nvd_data = NVDClient().fetch_cve(cve_id)
        record = extract_matching_nvd_record(nvd_data, cve_id)
        if record is None:
            print_db_summary(db_summary)
            print("=== Resume NVD ===")
            print("record_found: false")
            print("configurations: false")
            print("nodes: false")
            print("cpeMatch: false")
            print("")
            print("Conclusion: D. erreur parsing")
            print("Detail: la reponse NVD ne contient pas de record CVE correspondant.")
            return 1

        nvd_summary = summarize_configurations(record)
        parser_count = count_products_extracted_by_existing_parser(record)
        print_nvd_summary(nvd_summary, parser_count)
        print_db_summary(db_summary)
        print_conclusion(nvd_summary, db_summary.affected_product_count, parser_count)
        return 0
    except NVDClientError as exc:
        print(f"ERREUR NVD: {exc}")
        return 1
    except Exception as exc:
        print("Conclusion: D. erreur parsing")
        print(f"Detail: {exc.__class__.__name__}: {exc}")
        return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Diagnostique en read-only les cpeMatch NVD d'une CVE.",
    )
    parser.add_argument("cve_id", help="Identifiant CVE, exemple CVE-2026-15748")
    return parser.parse_args()


@dataclass(frozen=True)
class DbSummary:
    vulnerability_exists: bool
    enrichment_status: str
    affected_product_count: int


def load_db_summary(cve_id: str) -> DbSummary:
    with SessionLocal() as db:
        vulnerability = db.execute(
            select(Vulnerability).where(Vulnerability.cve_id == cve_id)
        ).scalar_one_or_none()
        if vulnerability is None:
            db.rollback()
            return DbSummary(
                vulnerability_exists=False,
                enrichment_status="-",
                affected_product_count=0,
            )

        count = (
            db.scalar(
                select(func.count(VulnerabilityAffectedProduct.id)).where(
                    VulnerabilityAffectedProduct.vulnerability_id == vulnerability.id
                )
            )
            or 0
        )
        status = enum_value(vulnerability.enrichment_status)
        db.rollback()
        return DbSummary(
            vulnerability_exists=True,
            enrichment_status=status,
            affected_product_count=count,
        )


def summarize_configurations(record: dict[str, Any]) -> ConfigurationSummary:
    summary = ConfigurationSummary()
    configurations = record.get("configurations")
    summary.has_configurations = "configurations" in record and configurations is not None

    if isinstance(configurations, dict):
        configuration_items = [configurations]
    elif isinstance(configurations, list):
        configuration_items = configurations
    elif configurations is None:
        configuration_items = []
    else:
        summary.structure_notes.append(
            f"configurations type inattendu: {type(configurations).__name__}"
        )
        configuration_items = []

    summary.configuration_count = len(configuration_items)
    for configuration in configuration_items:
        if not isinstance(configuration, dict):
            summary.structure_notes.append(
                f"configuration item type inattendu: {type(configuration).__name__}"
            )
            continue
        nodes = configuration.get("nodes")
        if nodes is not None:
            summary.has_nodes = True
        if not isinstance(nodes, list):
            if nodes is not None:
                summary.structure_notes.append(
                    f"nodes type inattendu: {type(nodes).__name__}"
                )
            continue
        for node in nodes:
            summarize_node(node, summary)

    summary.has_cpe_match = summary.cpe_match_count > 0
    return summary


def summarize_node(node: Any, summary: ConfigurationSummary) -> None:
    if not isinstance(node, dict):
        summary.structure_notes.append(f"node type inattendu: {type(node).__name__}")
        return

    summary.node_count += 1

    cpe_matches = node.get("cpeMatch")
    if cpe_matches is not None:
        summary.has_cpe_match = True
    if isinstance(cpe_matches, list):
        for cpe_match in cpe_matches:
            summarize_cpe_match(cpe_match, summary)
    elif cpe_matches is not None:
        summary.structure_notes.append(
            f"cpeMatch type inattendu: {type(cpe_matches).__name__}"
        )

    child_nodes = node.get("nodes")
    if isinstance(child_nodes, list):
        for child_node in child_nodes:
            summarize_node(child_node, summary)
    elif child_nodes is not None:
        summary.structure_notes.append(
            f"child nodes type inattendu: {type(child_nodes).__name__}"
        )


def summarize_cpe_match(cpe_match: Any, summary: ConfigurationSummary) -> None:
    if not isinstance(cpe_match, dict):
        summary.structure_notes.append(
            f"cpeMatch item type inattendu: {type(cpe_match).__name__}"
        )
        return

    summary.cpe_match_count += 1
    summary.cpe_matches.append(
        CpeMatchSummary(
            criteria=as_optional_string(
                cpe_match.get("criteria")
                or cpe_match.get("cpe23Uri")
                or cpe_match.get("cpe22Uri")
            ),
            vulnerable=cpe_match.get("vulnerable"),
            version_start_including=as_optional_string(
                cpe_match.get("versionStartIncluding")
            ),
            version_start_excluding=as_optional_string(
                cpe_match.get("versionStartExcluding")
            ),
            version_end_including=as_optional_string(cpe_match.get("versionEndIncluding")),
            version_end_excluding=as_optional_string(cpe_match.get("versionEndExcluding")),
        )
    )


def count_products_extracted_by_existing_parser(record: dict[str, Any]) -> int:
    configurations = record.get("configurations") or []
    return len(extract_affected_products(configurations))


def print_nvd_summary(summary: ConfigurationSummary, parser_count: int) -> None:
    print("=== Resume NVD ===")
    print(f"configurations: {summary.has_configurations}")
    print(f"nodes: {summary.has_nodes}")
    print(f"cpeMatch: {summary.has_cpe_match}")
    print(f"nombre de configurations: {summary.configuration_count}")
    print(f"nombre de nodes: {summary.node_count}")
    print(f"nombre de cpeMatch: {summary.cpe_match_count}")
    print(f"extract_affected_products() en memoire: {parser_count}")
    if summary.structure_notes:
        print("structure_notes:")
        for note in summary.structure_notes:
            print(f"- {note}")
    print("")

    print("=== cpeMatch NVD ===")
    if not summary.cpe_matches:
        print("Aucun cpeMatch dans le JSON NVD.")
        print("")
        return

    for index, cpe_match in enumerate(summary.cpe_matches, start=1):
        print(f"[{index}]")
        print(f"  criteria: {value_or_dash(cpe_match.criteria)}")
        print(f"  vulnerable: {value_or_dash(cpe_match.vulnerable)}")
        print(
            "  versionStartIncluding: "
            f"{value_or_dash(cpe_match.version_start_including)}"
        )
        print(
            "  versionStartExcluding: "
            f"{value_or_dash(cpe_match.version_start_excluding)}"
        )
        print(f"  versionEndIncluding: {value_or_dash(cpe_match.version_end_including)}")
        print(f"  versionEndExcluding: {value_or_dash(cpe_match.version_end_excluding)}")
    print("")


def print_db_summary(summary: DbSummary) -> None:
    print("=== Resume DB ===")
    print(f"Vulnerability exists: {summary.vulnerability_exists}")
    print(f"enrichment_status: {summary.enrichment_status}")
    print(f"VulnerabilityAffectedProduct count: {summary.affected_product_count}")
    print("")


def print_conclusion(
    nvd_summary: ConfigurationSummary,
    db_count: int,
    parser_count: int,
) -> None:
    print("=== Conclusion ===")
    if nvd_summary.structure_notes:
        print("Conclusion: C. structure NVD differente/non geree")
        print("Detail: des champs configurations/nodes/cpeMatch ont une forme inattendue.")
        return

    if nvd_summary.cpe_match_count > 0 and db_count == 0:
        print("Conclusion: A. NVD retourne des cpeMatch mais ThreatWatch ne les persiste pas")
        if parser_count == 0:
            print(
                "Detail: le parseur actuel n'extrait aucun produit affecte en memoire, "
                "probablement car aucun cpeMatch vulnerable=true exploitable n'est present."
            )
        else:
            print(
                "Detail: le parseur actuel extrait des produits en memoire, mais la DB "
                "n'en contient aucun pour cette CVE."
            )
        return

    if nvd_summary.cpe_match_count == 0:
        print("Conclusion: B. NVD ne retourne aucun cpeMatch pour cette CVE")
        return

    if parser_count != db_count:
        print("Conclusion: A. NVD retourne des cpeMatch mais ThreatWatch ne les persiste pas")
        print(
            f"Detail: NVD cpeMatch={nvd_summary.cpe_match_count}, "
            f"parseur={parser_count}, DB={db_count}."
        )
        return

    print("Conclusion: aucune anomalie de persistance detectee sur les affected products")


def as_optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def enum_value(value) -> str:
    return getattr(value, "value", str(value or "")).strip() or "-"


def value_or_dash(value) -> str:
    if value is None:
        return "-"
    text = str(value)
    return text if text else "-"


if __name__ == "__main__":
    raise SystemExit(main())
