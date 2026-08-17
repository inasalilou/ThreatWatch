"""
Teste le collecteur DGSSI sans insertion PostgreSQL.

Le script contacte la page publique DGSSI, detecte les liens de bulletins,
recupere quelques pages detail et affiche les champs normalises.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.dgssi_collector import (
    DGSSICollector,
    DGSSICollectorError,
    candidate_listing_urls,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Teste la collecte publique DGSSI.")
    parser.add_argument(
        "--limit",
        type=int,
        default=3,
        help="Nombre de bulletins detail a recuperer pour le test.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Timeout HTTP en secondes pour diagnostiquer la connexion DGSSI.",
    )
    parser.add_argument(
        "--list-candidates",
        action="store_true",
        help="Affiche les URLs DGSSI candidates sans lancer de requete reseau.",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    collector = DGSSICollector(timeout=args.timeout)

    if args.list_candidates:
        print("URLs DGSSI candidates :")
        for url in candidate_listing_urls(collector.source_url):
            print(f"- {url}")
        return 0

    try:
        listing = collector.fetch_listing()
        links = collector.parse_bulletin_links(listing.html, base_url=listing.url)
    except DGSSICollectorError as exc:
        print(f"ERREUR: impossible de contacter ou parser la DGSSI: {exc}")
        return 1

    print("Connexion DGSSI OK.")
    print(f"Code HTTP : {listing.status_code}")
    print(f"Bulletins detectes : {len(links)}")

    if not links:
        print("ERREUR: aucun lien de bulletin DGSSI detecte.")
        return 1

    parsed_count = 0
    for index, link in enumerate(links[: args.limit], start=1):
        try:
            bulletin = collector.fetch_and_parse_bulletin(link)
        except DGSSICollectorError as exc:
            print("")
            print(f"--- BULLETIN {index} ---")
            print(f"URL : {link.url}")
            print(f"ERREUR: {exc}")
            continue

        parsed_count += 1
        print("")
        print(f"--- BULLETIN {index} ---")
        print(f"Reference : {bulletin.reference or 'Non disponible'}")
        print(f"Titre : {bulletin.title}")
        date_value = bulletin.publication_date.isoformat() if bulletin.publication_date else "Non disponible"
        print(f"Date : {date_value}")
        print(f"Risque : {bulletin.severity or 'Non disponible'}")
        print(f"Impact : {bulletin.impact_level or 'Non disponible'}")
        print(f"URL : {bulletin.source_url}")
        print(f"Canonical key : {bulletin.canonical_key}")
        print("CVE detectees :")
        if bulletin.cves:
            for cve_id in bulletin.cves:
                print(f"- {cve_id}")
        else:
            print("- Aucune")

    if parsed_count == 0:
        print("")
        print("ERREUR: aucun bulletin detail n'a pu etre parse.")
        return 1

    print("")
    print("Test du collecteur termine avec succes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
