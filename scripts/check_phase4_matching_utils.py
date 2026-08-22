"""
Verification locale de la phase 4.2.2.

Le script teste les fonctions de normalisation/matching et lit les produits
affectes deja stockes pour CVE-2025-58057 sans modifier la base.
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
from app.models.vulnerability_affected_product import VulnerabilityAffectedProduct
from app.services.correlation_normalization_service import (
    MatchResult,
    cpe_matches,
    normalize_technical_name,
    product_matches,
    vendor_matches,
    version_matches,
)


SAMPLE_CVE_ID = "CVE-2025-58057"


def main() -> int:
    print(
        "Verification phase 4.2 matching utils avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        if not check_normalization():
            return 1
        if not check_vendor_product_matching():
            return 1
        if not check_version_matching():
            return 1
        if not check_cpe_matching():
            return 1
        if not show_existing_affected_products():
            return 1

        print("PHASE 4.2 MATCHING UTILS CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR PostgreSQL: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def check_normalization() -> bool:
    checks = [
        ("Apache", "apache"),
        ("apache", "apache"),
        ("APACHE", "apache"),
        ("HTTP Server", "http server"),
        ("http_server", "http server"),
        ("http-server", "http server"),
        ("  PostgreSQL  ", "postgresql"),
    ]
    for raw_value, expected in checks:
        if normalize_technical_name(raw_value) != expected:
            print(f"Normalization: FAILED ({raw_value!r})")
            return False

    print("Normalization: OK")
    return True


def check_vendor_product_matching() -> bool:
    checks = [
        vendor_matches("Apache", "apache") == MatchResult.MATCH,
        product_matches("HTTP Server", "http_server") == MatchResult.MATCH,
        product_matches("PostgreSQL", "mysql") == MatchResult.NO_MATCH,
        vendor_matches(None, "apache") == MatchResult.UNKNOWN,
        product_matches("", "http_server") == MatchResult.UNKNOWN,
    ]
    if not all(checks):
        print("Vendor/Product matching: FAILED")
        return False

    print("Vendor/Product matching: OK")
    return True


def check_version_matching() -> bool:
    checks = [
        version_matches("2.4.49", "2.4.49") == MatchResult.MATCH,
        version_matches("2.4.50", "2.4.49") == MatchResult.NO_MATCH,
        version_matches("9.9.9", "*") == MatchResult.MATCH,
        version_matches("2.4.49", "-") == MatchResult.UNKNOWN,
        version_matches(None, "2.4.49") == MatchResult.UNKNOWN,
        version_matches(
            asset_version="2.4.49",
            cpe_version="*",
            version_start_including="2.4.0",
            version_end_excluding="2.4.50",
        )
        == MatchResult.MATCH,
        version_matches(
            asset_version="2.4.50",
            cpe_version="*",
            version_start_including="2.4.0",
            version_end_excluding="2.4.50",
        )
        == MatchResult.NO_MATCH,
        version_matches(
            asset_version="2.4.49",
            cpe_version="*",
            version_start_including="2.4.0",
            version_end_including="2.4.49",
        )
        == MatchResult.MATCH,
        version_matches("release-final", "release-next") == MatchResult.UNKNOWN,
    ]
    if not all(checks):
        print("Version matching: FAILED")
        return False

    print("Version matching: OK")
    return True


def check_cpe_matching() -> bool:
    checks = [
        cpe_matches(
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        )
        == MatchResult.MATCH,
        cpe_matches(
            "cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        )
        == MatchResult.NO_MATCH,
        cpe_matches(None, "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")
        == MatchResult.UNKNOWN,
    ]
    if not all(checks):
        print("CPE matching: FAILED")
        return False

    print("CPE matching: OK")
    return True


def show_existing_affected_products() -> bool:
    with SessionLocal() as db:
        rows = (
            db.execute(
                select(VulnerabilityAffectedProduct)
                .join(Vulnerability)
                .where(Vulnerability.cve_id == SAMPLE_CVE_ID)
                .order_by(VulnerabilityAffectedProduct.cpe)
            )
            .scalars()
            .all()
        )

    print(f"{SAMPLE_CVE_ID} affected products: {len(rows)}")
    for product in rows:
        print(
            "- "
            f"vendor={product.vendor or '-'} "
            f"normalized_vendor={normalize_technical_name(product.vendor) or '-'} "
            f"product={product.product or '-'} "
            f"normalized_product={normalize_technical_name(product.product) or '-'} "
            f"version={product.version or '-'} "
            f"cpe_part={product.cpe_part or '-'}"
        )

    if not rows:
        print(f"{SAMPLE_CVE_ID} affected products: AUCUNE DONNEE")
        return False
    return True


if __name__ == "__main__":
    raise SystemExit(main())
