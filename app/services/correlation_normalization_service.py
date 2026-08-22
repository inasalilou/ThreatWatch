"""
Fonctions preparatoires pour la future correlation Asset <-> Vulnerability.

Ce module travaille uniquement sur des valeurs locales deja stockees. Il ne
cree aucun lien persistant, aucun score et ne contacte aucun service externe.
"""
from __future__ import annotations

import enum
import re
from dataclasses import dataclass


class MatchResult(str, enum.Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ParsedCPE:
    cpe: str
    part: str | None = None
    vendor: str | None = None
    product: str | None = None
    version: str | None = None


SEPARATOR_PATTERN = re.compile(r"[_\-]+")
PUNCTUATION_PATTERN = re.compile(r"[^a-z0-9 ]+")
SPACES_PATTERN = re.compile(r"\s+")
VERSION_TOKEN_PATTERN = re.compile(r"\d+|[a-z]+", re.IGNORECASE)


def normalize_technical_name(value: str | None) -> str | None:
    if value is None:
        return None

    normalized = str(value).strip().lower()
    if not normalized:
        return None

    normalized = SEPARATOR_PATTERN.sub(" ", normalized)
    normalized = PUNCTUATION_PATTERN.sub(" ", normalized)
    normalized = SPACES_PATTERN.sub(" ", normalized).strip()
    return normalized or None


def vendor_matches(
    asset_vendor: str | None,
    affected_vendor: str | None,
) -> MatchResult:
    return normalized_string_matches(asset_vendor, affected_vendor)


def product_matches(
    asset_product: str | None,
    affected_product: str | None,
) -> MatchResult:
    return normalized_string_matches(asset_product, affected_product)


def normalized_string_matches(
    left: str | None,
    right: str | None,
) -> MatchResult:
    normalized_left = normalize_technical_name(left)
    normalized_right = normalize_technical_name(right)
    if normalized_left is None or normalized_right is None:
        return MatchResult.UNKNOWN
    if normalized_left == normalized_right:
        return MatchResult.MATCH
    return MatchResult.NO_MATCH


def version_matches(
    asset_version: str | None,
    cpe_version: str | None,
    version_start_including: str | None = None,
    version_start_excluding: str | None = None,
    version_end_including: str | None = None,
    version_end_excluding: str | None = None,
) -> MatchResult:
    normalized_asset_version = normalize_version_value(asset_version)
    if normalized_asset_version is None:
        return MatchResult.UNKNOWN

    bounds = normalize_version_bounds(
        version_start_including=version_start_including,
        version_start_excluding=version_start_excluding,
        version_end_including=version_end_including,
        version_end_excluding=version_end_excluding,
    )
    if any(bounds.values()):
        return version_matches_bounds(normalized_asset_version, bounds)

    normalized_cpe_version = normalize_version_value(cpe_version)
    if normalized_cpe_version is None:
        return MatchResult.UNKNOWN
    if normalized_cpe_version == "*":
        return MatchResult.MATCH
    if normalized_cpe_version == "-":
        return MatchResult.UNKNOWN
    if normalized_asset_version == normalized_cpe_version:
        return MatchResult.MATCH

    comparison = compare_versions(normalized_asset_version, normalized_cpe_version)
    if comparison is None:
        return MatchResult.UNKNOWN
    return MatchResult.MATCH if comparison == 0 else MatchResult.NO_MATCH


def version_matches_bounds(
    asset_version: str,
    bounds: dict[str, str | None],
) -> MatchResult:
    comparisons = [
        (bounds["version_start_including"], lambda result: result >= 0),
        (bounds["version_start_excluding"], lambda result: result > 0),
        (bounds["version_end_including"], lambda result: result <= 0),
        (bounds["version_end_excluding"], lambda result: result < 0),
    ]

    for bound, accepts in comparisons:
        if not bound:
            continue
        comparison = compare_versions(asset_version, bound)
        if comparison is None:
            return MatchResult.UNKNOWN
        if not accepts(comparison):
            return MatchResult.NO_MATCH

    return MatchResult.MATCH


def normalize_version_bounds(
    version_start_including: str | None = None,
    version_start_excluding: str | None = None,
    version_end_including: str | None = None,
    version_end_excluding: str | None = None,
) -> dict[str, str | None]:
    return {
        "version_start_including": normalize_version_value(version_start_including),
        "version_start_excluding": normalize_version_value(version_start_excluding),
        "version_end_including": normalize_version_value(version_end_including),
        "version_end_excluding": normalize_version_value(version_end_excluding),
    }


def normalize_version_value(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    return normalized or None


def compare_versions(left: str, right: str) -> int | None:
    left_tokens = tokenize_version(left)
    right_tokens = tokenize_version(right)
    if left_tokens is None or right_tokens is None:
        return None

    max_length = max(len(left_tokens), len(right_tokens))
    padded_left = left_tokens + [0] * (max_length - len(left_tokens))
    padded_right = right_tokens + [0] * (max_length - len(right_tokens))

    for left_token, right_token in zip(padded_left, padded_right):
        if type(left_token) is not type(right_token):
            return None
        if left_token < right_token:
            return -1
        if left_token > right_token:
            return 1
    return 0


def tokenize_version(value: str) -> list[int | str] | None:
    if value in {"*", "-"}:
        return None

    tokens = VERSION_TOKEN_PATTERN.findall(value)
    compact = re.sub(r"[\s._+\-]+", "", value)
    if (
        not tokens
        or not any(token.isdigit() for token in tokens)
        or "".join(tokens).lower() != compact.lower()
    ):
        return None

    parsed_tokens: list[int | str] = []
    for token in tokens:
        if token.isdigit():
            parsed_tokens.append(int(token))
        else:
            parsed_tokens.append(token.lower())
    return parsed_tokens


def cpe_matches(asset_cpe: str | None, affected_cpe: str | None) -> MatchResult:
    if not asset_cpe or not affected_cpe:
        return MatchResult.UNKNOWN

    parsed_asset = parse_cpe_23(asset_cpe)
    parsed_affected = parse_cpe_23(affected_cpe)
    if parsed_asset is None or parsed_affected is None:
        return MatchResult.UNKNOWN

    if parsed_asset.part != parsed_affected.part:
        return MatchResult.NO_MATCH
    if vendor_matches(parsed_asset.vendor, parsed_affected.vendor) != MatchResult.MATCH:
        return MatchResult.NO_MATCH
    if product_matches(parsed_asset.product, parsed_affected.product) != MatchResult.MATCH:
        return MatchResult.NO_MATCH

    version_result = version_matches(
        asset_version=parsed_asset.version,
        cpe_version=parsed_affected.version,
    )
    if version_result == MatchResult.NO_MATCH:
        return MatchResult.NO_MATCH
    if version_result == MatchResult.UNKNOWN:
        return MatchResult.UNKNOWN
    return MatchResult.MATCH


def parse_cpe_23(cpe: str | None) -> ParsedCPE | None:
    if not cpe:
        return None

    parts = split_cpe_23(str(cpe).strip())
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None

    return ParsedCPE(
        cpe=str(cpe).strip(),
        part=unescape_cpe_component(parts[2]),
        vendor=unescape_cpe_component(parts[3]),
        product=unescape_cpe_component(parts[4]),
        version=unescape_cpe_component(parts[5]),
    )


def split_cpe_23(cpe: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False

    for character in cpe:
        if escaped:
            current.append("\\" + character)
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == ":":
            parts.append("".join(current))
            current = []
            continue
        current.append(character)

    if escaped:
        current.append("\\")
    parts.append("".join(current))
    return parts


def unescape_cpe_component(value: str) -> str:
    return value.replace("\\", "")
