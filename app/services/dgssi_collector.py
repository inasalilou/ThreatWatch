"""
Collecteur DGSSI.

Cette couche recupere les pages publiques DGSSI, extrait les champs utiles et
retourne des objets Python normalises. Elle ne fait aucune insertion en base.
"""
from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import asdict, dataclass
from datetime import date
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from bs4 import BeautifulSoup

from app.core.config import settings

logger = logging.getLogger(__name__)

SOURCE_NAME = "DGSSI"
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,10}\b", re.IGNORECASE)


class DGSSICollectorError(RuntimeError):
    """Erreur maitrisee du collecteur DGSSI."""


@dataclass(frozen=True)
class DGSSIFetchResult:
    url: str
    status_code: int
    html: str


@dataclass(frozen=True)
class DGSSIBulletinLink:
    title: str
    url: str


@dataclass(frozen=True)
class NormalizedDgssiBulletin:
    external_id: str | None
    reference: str | None
    title: str
    summary: str | None
    description: str | None
    bulletin_type: str | None
    severity: str | None
    impact_level: str | None
    publication_date: date | None
    source: str
    source_url: str
    canonical_key: str
    raw_content: str
    cves: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class DGSSICollector:
    def __init__(
        self,
        source_url: str | None = None,
        timeout: float | None = None,
        user_agent: str | None = None,
    ):
        self.source_url = source_url or settings.DGSSI_SOURCE_URL
        self.timeout = timeout if timeout is not None else settings.DGSSI_HTTP_TIMEOUT
        self.user_agent = user_agent or settings.DGSSI_USER_AGENT

    def fetch_html(self, url: str) -> DGSSIFetchResult:
        logger.info("Connexion a la source DGSSI: %s", url)
        try:
            with httpx.Client(
                follow_redirects=False,
                timeout=httpx.Timeout(
                    timeout=self.timeout,
                    connect=min(self.timeout, 10),
                    read=self.timeout,
                    write=min(self.timeout, 10),
                    pool=min(self.timeout, 10),
                ),
                headers={
                    "User-Agent": self.user_agent,
                    "Accept": "text/html,application/xhtml+xml",
                    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.7",
                    "Connection": "close",
                },
            ) as client:
                response = self._get_with_safe_redirects(client, url)
                response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise DGSSICollectorError(f"Delai depasse lors de l'appel DGSSI: {url}") from exc
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            raise DGSSICollectorError(
                f"Erreur HTTP DGSSI {status_code} lors de l'appel: {url}"
            ) from exc
        except httpx.RequestError as exc:
            raise DGSSICollectorError(f"Erreur reseau DGSSI lors de l'appel: {url}") from exc

        content_type = response.headers.get("content-type", "")
        if "html" not in content_type.lower():
            logger.warning("Contenu DGSSI inattendu pour %s: %s", url, content_type)

        if not response.text.strip():
            raise DGSSICollectorError(f"Reponse DGSSI vide pour: {url}")

        logger.info("Page DGSSI recuperee: %s", response.url)
        return DGSSIFetchResult(
            url=str(response.url),
            status_code=response.status_code,
            html=response.text,
        )

    def _get_with_safe_redirects(self, client: httpx.Client, url: str) -> httpx.Response:
        current_url = url

        for _ in range(6):
            response = client.get(current_url)
            if not response.is_redirect:
                return response

            location = response.headers.get("location")
            if not location:
                return response

            next_url = normalize_dgssi_redirect(urljoin(str(response.url), location))
            logger.info("Redirection DGSSI: %s -> %s", response.status_code, next_url)
            current_url = next_url

        raise DGSSICollectorError(f"Trop de redirections DGSSI pour: {url}")

    def fetch_listing(self) -> DGSSIFetchResult:
        errors: list[str] = []
        for candidate_url in candidate_listing_urls(self.source_url):
            try:
                result = self.fetch_html(candidate_url)
            except DGSSICollectorError as exc:
                errors.append(str(exc))
                continue

            links = self.parse_bulletin_links(result.html, base_url=result.url)
            if links:
                return result

            logger.warning(
                "La page DGSSI recuperee ne contient pas de liens de bulletins: %s",
                result.url,
            )
            errors.append(f"Aucun lien de bulletin detecte sur {result.url}")

        raise DGSSICollectorError("; ".join(errors) or "Aucune source DGSSI exploitable")

    def parse_bulletin_links(
        self, html: str, base_url: str | None = None
    ) -> list[DGSSIBulletinLink]:
        soup = BeautifulSoup(html, "html.parser")
        links: list[DGSSIBulletinLink] = []
        seen_urls: set[str] = set()
        effective_base_url = base_url or self.source_url

        for anchor in soup.find_all("a", href=True):
            href = anchor.get("href", "")
            absolute_url = normalize_url(urljoin(effective_base_url, href))
            parsed = urlsplit(absolute_url)
            path = parsed.path.rstrip("/")

            if "/fr/bulletins/" not in path:
                continue
            if path.lower().endswith((".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp")):
                continue
            if absolute_url in seen_urls:
                continue

            title = clean_text(anchor.get_text(" ", strip=True))
            if not title:
                logger.warning("Lien bulletin DGSSI ignore car le titre est absent: %s", absolute_url)
                continue

            seen_urls.add(absolute_url)
            links.append(DGSSIBulletinLink(title=title, url=absolute_url))

        logger.info("%s bulletins detectes sur la page DGSSI", len(links))
        return links

    def fetch_and_parse_bulletin(
        self, link: DGSSIBulletinLink
    ) -> NormalizedDgssiBulletin:
        logger.info("Parsing du bulletin DGSSI: %s", link.url)
        detail = self.fetch_html(link.url)
        return self.parse_bulletin_detail(
            detail.html,
            source_url=detail.url,
            fallback_title=link.title,
        )

    def collect_sample(self, limit: int = 3) -> tuple[list[DGSSIBulletinLink], list[NormalizedDgssiBulletin]]:
        listing = self.fetch_listing()
        links = self.parse_bulletin_links(listing.html, base_url=listing.url)
        bulletins: list[NormalizedDgssiBulletin] = []

        for link in links[:limit]:
            try:
                bulletins.append(self.fetch_and_parse_bulletin(link))
            except DGSSICollectorError as exc:
                logger.error("Impossible de recuperer le bulletin %s: %s", link.url, exc)

        return links, bulletins

    def parse_bulletin_detail(
        self,
        html: str,
        source_url: str,
        fallback_title: str | None = None,
    ) -> NormalizedDgssiBulletin:
        soup = BeautifulSoup(html, "html.parser")
        remove_noisy_tags(soup)

        raw_content = clean_text(soup.get_text("\n", strip=True))
        if not raw_content:
            raise DGSSICollectorError(f"Contenu bulletin DGSSI vide ou invalide: {source_url}")

        title = (
            extract_labeled_value(soup, ("Titre",))
            or extract_h1_title(soup)
            or clean_text(fallback_title or "")
        )
        if not title:
            raise DGSSICollectorError(f"Titre bulletin absent: {source_url}")

        reference = extract_labeled_value(
            soup,
            ("Numero de Reference", "Numéro de Référence", "Reference", "Référence"),
        )
        reference = strip_known_label_prefix(
            reference,
            ("Numero de Reference", "Numéro de Référence", "Reference", "Référence"),
        )
        if reference is None:
            logger.warning("Champ reference absent pour le bulletin DGSSI: %s", source_url)

        publication_date_text = extract_labeled_value(
            soup,
            ("Date de publication", "Publication"),
        )
        publication_date = parse_french_date(publication_date_text)
        if publication_date_text and publication_date is None:
            logger.warning("Date de publication non parseable: %s", publication_date_text)
        elif publication_date_text is None:
            logger.warning("Champ date de publication absent pour le bulletin DGSSI: %s", source_url)

        severity = extract_labeled_value(soup, ("Niveau de Risque", "Risque"))
        severity = strip_known_label_prefix(severity, ("Niveau de Risque", "Risque"))
        if severity is None:
            logger.warning("Champ niveau de risque absent pour le bulletin DGSSI: %s", source_url)

        impact_level = extract_labeled_value(soup, ("Niveau d'Impact", "Impact"))
        impact_level = strip_known_label_prefix(impact_level, ("Niveau d'Impact", "Impact"))
        if impact_level is None:
            logger.warning("Champ niveau d'impact absent pour le bulletin DGSSI: %s", source_url)

        description = extract_section_text(
            soup,
            start_markers=("Bilan de la vulnerabilite", "Bilan de la vulnérabilité"),
            stop_markers=("Solution", "Risque", "Reference", "Référence", "Brochure", "Documents"),
        )
        if description is None:
            description = extract_first_meaningful_paragraph(soup)

        cves = extract_cves(raw_content)
        canonical_key = build_canonical_key(reference=reference, source_url=source_url)

        return NormalizedDgssiBulletin(
            external_id=reference,
            reference=reference,
            title=title,
            summary=description,
            description=description,
            bulletin_type=None,
            severity=severity,
            impact_level=impact_level,
            publication_date=publication_date,
            source=SOURCE_NAME,
            source_url=normalize_url(source_url),
            canonical_key=canonical_key,
            raw_content=raw_content,
            cves=cves,
        )


def clean_text(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", " ", value.replace("\xa0", " ")).strip()


def normalize_label(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_value = normalized.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", " ", ascii_value.lower()).strip()


def strip_known_label_prefix(value: str | None, labels: tuple[str, ...]) -> str | None:
    if not value:
        return None

    cleaned = clean_text(value)
    normalized_value = normalize_label(cleaned)

    for label in sorted(labels, key=len, reverse=True):
        normalized_label = normalize_label(label)
        if normalized_value == normalized_label:
            return None
        if normalized_value.startswith(normalized_label + " "):
            pattern = re.compile(rf"^\s*{re.escape(label)}\s*[:|\-]?\s*", re.IGNORECASE)
            stripped = clean_text(pattern.sub("", cleaned))
            if stripped != cleaned:
                return stripped or None

            words_to_remove = len(normalized_label.split())
            remaining_words = cleaned.split()[words_to_remove:]
            stripped = clean_text(" ".join(remaining_words))
            return stripped or None

    return cleaned


def normalize_url(url: str) -> str:
    split = urlsplit(url)
    path = split.path.rstrip("/") or "/"
    return urlunsplit(
        (
            split.scheme.lower(),
            split.netloc.lower(),
            path,
            split.query,
            "",
        )
    )


def normalize_dgssi_redirect(url: str) -> str:
    split = urlsplit(url)
    if split.scheme == "http" and split.netloc.lower() in {"www.dgssi.gov.ma", "dgssi.gov.ma"}:
        return urlunsplit(("https", split.netloc, split.path, split.query, ""))
    return url


def candidate_listing_urls(source_url: str) -> list[str]:
    normalized = normalize_url(source_url)
    split = urlsplit(normalized)
    candidates: list[str] = []
    paths = [split.path]
    if not split.path.endswith("/"):
        paths.append(f"{split.path}/")

    if split.netloc in {"www.dgssi.gov.ma", "dgssi.gov.ma"}:
        for path in paths:
            candidates.append(urlunsplit(("https", "www.dgssi.gov.ma", path, split.query, "")))
            candidates.append(urlunsplit(("https", "dgssi.gov.ma", path, split.query, "")))

    candidates.append(normalized)

    if split.netloc == "dgssi.gov.ma":
        for path in paths:
            candidates.append(urlunsplit((split.scheme, "www.dgssi.gov.ma", path, split.query, "")))
    elif split.netloc == "www.dgssi.gov.ma":
        for path in paths:
            candidates.append(urlunsplit((split.scheme, "dgssi.gov.ma", path, split.query, "")))

    if split.scheme == "http":
        for path in paths:
            candidates.append(urlunsplit(("http", split.netloc, path, split.query, "")))

    unique_candidates: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate not in seen:
            unique_candidates.append(candidate)
            seen.add(candidate)
    return unique_candidates


def build_canonical_key(reference: str | None, source_url: str) -> str:
    if reference and reference.strip():
        return f"{SOURCE_NAME}:{reference.strip().upper()}"
    return f"{SOURCE_NAME}:{normalize_url(source_url)}"


def extract_cves(text: str) -> list[str]:
    matches = {match.group(0).upper() for match in CVE_PATTERN.finditer(text)}
    return sorted(matches)


def parse_french_date(value: str | None) -> date | None:
    if not value:
        return None

    cleaned = clean_text(value)

    try:
        return date.fromisoformat(cleaned)
    except ValueError:
        pass

    numeric_match = re.search(r"\b(\d{1,2})/(\d{1,2})/(\d{4})\b", cleaned)
    if numeric_match:
        day, month, year = map(int, numeric_match.groups())
        try:
            return date(year, month, day)
        except ValueError:
            return None

    month_names = {
        "janvier": 1,
        "fevrier": 2,
        "mars": 3,
        "avril": 4,
        "mai": 5,
        "juin": 6,
        "juillet": 7,
        "aout": 8,
        "septembre": 9,
        "octobre": 10,
        "novembre": 11,
        "decembre": 12,
    }
    date_text = normalize_label(cleaned)
    match = re.search(r"\b(\d{1,2})\s+([a-z]+)\s+(\d{4})\b", date_text)
    if not match:
        return None

    day = int(match.group(1))
    month = month_names.get(match.group(2))
    year = int(match.group(3))
    if month is None:
        return None

    try:
        return date(year, month, day)
    except ValueError:
        return None


def remove_noisy_tags(soup: BeautifulSoup) -> None:
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()


def extract_h1_title(soup: BeautifulSoup) -> str | None:
    h1 = soup.find("h1")
    title = clean_text(h1.get_text(" ", strip=True)) if h1 else ""
    return title or None


def extract_labeled_value(soup: BeautifulSoup, labels: tuple[str, ...]) -> str | None:
    expected_labels = {normalize_label(label) for label in labels}
    label_pairs = tuple((label, normalize_label(label)) for label in labels)

    for row in soup.find_all("tr"):
        cells = row.find_all(["th", "td"])
        if len(cells) < 2:
            continue

        key = normalize_label(cells[0].get_text(" ", strip=True))
        if key in expected_labels:
            value = clean_text(cells[1].get_text(" ", strip=True))
            return value or None

    lines = text_lines(soup)
    for index, line in enumerate(lines):
        normalized_line = normalize_label(line)
        for original_label, normalized_label in label_pairs:
            if normalized_line == normalized_label and index + 1 < len(lines):
                return lines[index + 1] or None

            if normalized_line.startswith(normalized_label + " "):
                value = line[len(original_label) :].strip(" :|-")
                return clean_text(value) or None

        for separator in ("|", ":"):
            if separator not in line:
                continue
            key, value = line.split(separator, 1)
            if normalize_label(key) in expected_labels:
                cleaned_value = clean_text(value)
                return cleaned_value or None

    return None


def extract_section_text(
    soup: BeautifulSoup,
    start_markers: tuple[str, ...],
    stop_markers: tuple[str, ...],
) -> str | None:
    normalized_start_markers = tuple(normalize_label(marker) for marker in start_markers)
    normalized_stop_markers = tuple(normalize_label(marker) for marker in stop_markers)

    heading = None
    for candidate in soup.find_all(["h2", "h3", "h4", "h5", "h6"]):
        candidate_text = normalize_label(candidate.get_text(" ", strip=True))
        if any(marker in candidate_text for marker in normalized_start_markers):
            heading = candidate
            break

    if heading is None:
        return None

    parts: list[str] = []
    for sibling in heading.find_next_siblings():
        if sibling.name in {"h2", "h3", "h4", "h5", "h6"}:
            sibling_text = normalize_label(sibling.get_text(" ", strip=True))
            if any(marker in sibling_text for marker in normalized_stop_markers):
                break

        text = clean_text(sibling.get_text(" ", strip=True))
        if text:
            parts.append(text)

    description = clean_text(" ".join(parts))
    return description or None


def extract_first_meaningful_paragraph(soup: BeautifulSoup) -> str | None:
    ignored_fragments = (
        "direction generale",
        "documents",
        "coordonnees",
        "pour signaler tout contenu",
        "dgssi",
    )
    for paragraph in soup.find_all("p"):
        text = clean_text(paragraph.get_text(" ", strip=True))
        normalized = normalize_label(text)
        if len(text) < 80:
            continue
        if any(fragment in normalized for fragment in ignored_fragments):
            continue
        return text
    return None


def text_lines(soup: BeautifulSoup) -> list[str]:
    return [
        clean_text(line)
        for line in soup.get_text("\n", strip=True).splitlines()
        if clean_text(line)
    ]
