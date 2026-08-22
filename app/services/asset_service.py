"""
Service metier pour l'inventaire des actifs.

Les fonctions preparent le futur CRUD web sans melanger la logique de
validation et les routes FastAPI. Le commit reste a la charge de l'appelant.
"""
from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
from datetime import datetime
from enum import Enum as PythonEnum
from typing import Any, TypeVar

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType


PER_PAGE = 20

EnumValue = TypeVar("EnumValue", bound=PythonEnum)

OPTIONAL_STRING_FIELDS = {
    "hostname",
    "ip_address",
    "vendor",
    "product",
    "product_version",
    "operating_system",
    "os_version",
    "owner",
    "location",
    "cpe",
    "description",
}
ENUM_FIELDS = {"asset_type", "criticality", "environment"}
BOOLEAN_FIELDS = {"is_active"}
UPDATE_FIELDS = {"name"} | OPTIONAL_STRING_FIELDS | ENUM_FIELDS | BOOLEAN_FIELDS


class AssetValidationError(ValueError):
    """Erreur de validation controlee pour les donnees d'actif."""


@dataclass(frozen=True)
class AssetSearchResult:
    items: list[Asset]
    total: int
    page: int
    per_page: int
    total_pages: int
    search: str
    asset_type: str
    criticality: str
    environment: str
    is_active: bool | None

    @property
    def has_previous(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages


@dataclass(frozen=True)
class AssetStats:
    total_assets: int
    active_assets: int
    inactive_assets: int
    critical_assets: int


def create_asset(
    db: Session,
    *,
    name: str,
    asset_type: AssetType | str,
    hostname: str | None = None,
    ip_address: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
    product_version: str | None = None,
    operating_system: str | None = None,
    os_version: str | None = None,
    criticality: AssetCriticality | str | None = None,
    environment: AssetEnvironment | str | None = None,
    owner: str | None = None,
    location: str | None = None,
    cpe: str | None = None,
    description: str | None = None,
    is_active: bool = True,
) -> Asset:
    """Cree un actif dans la session courante et retourne l'objet ORM."""
    asset = Asset(
        name=normalize_required_string(name, "name"),
        hostname=normalize_optional_string(hostname),
        ip_address=normalize_ip_address(ip_address),
        asset_type=coerce_enum(AssetType, asset_type, "asset_type"),
        vendor=normalize_optional_string(vendor),
        product=normalize_optional_string(product),
        product_version=normalize_optional_string(product_version),
        operating_system=normalize_optional_string(operating_system),
        os_version=normalize_optional_string(os_version),
        criticality=coerce_enum(
            AssetCriticality,
            criticality,
            "criticality",
            default=AssetCriticality.MEDIUM,
        ),
        environment=coerce_enum(
            AssetEnvironment,
            environment,
            "environment",
            default=AssetEnvironment.PRODUCTION,
        ),
        owner=normalize_optional_string(owner),
        location=normalize_optional_string(location),
        cpe=normalize_optional_string(cpe),
        description=normalize_optional_string(description),
        is_active=coerce_bool(is_active, "is_active"),
    )
    db.add(asset)
    db.flush()
    db.refresh(asset)
    return asset


def get_asset_by_id(db: Session, asset_id: str) -> Asset | None:
    """Retourne un actif par identifiant, ou None s'il n'existe pas."""
    cleaned_id = normalize_optional_string(asset_id)
    if not cleaned_id:
        return None
    return db.get(Asset, cleaned_id)


def update_asset(db: Session, asset_id: str, **changes: Any) -> Asset | None:
    """
    Met a jour un actif existant.

    Les champs id et created_at ne sont jamais modifiables par cette fonction.
    """
    asset = get_asset_by_id(db, asset_id)
    if asset is None:
        return None

    unknown_fields = set(changes) - UPDATE_FIELDS
    if unknown_fields:
        raise AssetValidationError(
            "Champs non modifiables ou inconnus: " + ", ".join(sorted(unknown_fields))
        )

    for field, value in changes.items():
        if field == "name":
            setattr(asset, field, normalize_required_string(value, field))
        elif field == "ip_address":
            setattr(asset, field, normalize_ip_address(value))
        elif field in OPTIONAL_STRING_FIELDS:
            setattr(asset, field, normalize_optional_string(value))
        elif field == "asset_type":
            setattr(asset, field, coerce_enum(AssetType, value, field))
        elif field == "criticality":
            setattr(asset, field, coerce_enum(AssetCriticality, value, field))
        elif field == "environment":
            setattr(asset, field, coerce_enum(AssetEnvironment, value, field))
        elif field == "is_active":
            setattr(asset, field, coerce_bool(value, field))

    asset.updated_at = datetime.utcnow()
    db.flush()
    db.refresh(asset)
    return asset


def disable_asset(db: Session, asset_id: str) -> Asset | None:
    """Desactive logiquement un actif sans suppression physique."""
    return update_asset(db, asset_id, is_active=False)


def enable_asset(db: Session, asset_id: str) -> Asset | None:
    """Reactive un actif desactive."""
    return update_asset(db, asset_id, is_active=True)


def list_assets(
    db: Session,
    *,
    search: str = "",
    asset_type: AssetType | str | None = None,
    criticality: AssetCriticality | str | None = None,
    environment: AssetEnvironment | str | None = None,
    is_active: bool | None = None,
    page: int = 1,
    per_page: int = PER_PAGE,
) -> AssetSearchResult:
    """Liste les actifs avec recherche, filtres et pagination SQL."""
    page = max(page, 1)
    per_page = max(per_page, 1)
    cleaned_search = normalize_optional_string(search) or ""
    cleaned_asset_type = coerce_optional_filter_enum(AssetType, asset_type, "asset_type")
    cleaned_criticality = coerce_optional_filter_enum(
        AssetCriticality, criticality, "criticality"
    )
    cleaned_environment = coerce_optional_filter_enum(
        AssetEnvironment, environment, "environment"
    )
    cleaned_is_active = coerce_optional_bool(is_active, "is_active")

    filters = build_asset_filters(
        search=cleaned_search,
        asset_type=cleaned_asset_type,
        criticality=cleaned_criticality,
        environment=cleaned_environment,
        is_active=cleaned_is_active,
    )

    total_statement = select(func.count(Asset.id))
    if filters:
        total_statement = total_statement.where(*filters)
    total = db.scalar(total_statement) or 0
    total_pages = max(math.ceil(total / per_page), 1)
    if page > total_pages:
        page = total_pages

    statement = (
        select(Asset)
        .order_by(Asset.name.asc(), Asset.created_at.desc())
        .limit(per_page)
        .offset((page - 1) * per_page)
    )
    if filters:
        statement = statement.where(*filters)

    items = list(db.execute(statement).scalars())

    return AssetSearchResult(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        search=cleaned_search,
        asset_type=cleaned_asset_type.value if cleaned_asset_type else "",
        criticality=cleaned_criticality.value if cleaned_criticality else "",
        environment=cleaned_environment.value if cleaned_environment else "",
        is_active=cleaned_is_active,
    )


def get_asset_stats(db: Session) -> AssetStats:
    total_assets = db.scalar(select(func.count(Asset.id))) or 0
    active_assets = (
        db.scalar(select(func.count(Asset.id)).where(Asset.is_active.is_(True))) or 0
    )
    inactive_assets = (
        db.scalar(select(func.count(Asset.id)).where(Asset.is_active.is_(False))) or 0
    )
    critical_assets = (
        db.scalar(
            select(func.count(Asset.id)).where(
                Asset.criticality == AssetCriticality.CRITICAL
            )
        )
        or 0
    )

    return AssetStats(
        total_assets=total_assets,
        active_assets=active_assets,
        inactive_assets=inactive_assets,
        critical_assets=critical_assets,
    )


def get_asset_type_options() -> list[tuple[str, str]]:
    return [(asset_type.value, asset_type_label(asset_type)) for asset_type in AssetType]


def get_criticality_options() -> list[tuple[str, str]]:
    return [
        (criticality.value, criticality_label(criticality))
        for criticality in AssetCriticality
    ]


def get_environment_options() -> list[tuple[str, str]]:
    return [
        (environment.value, environment_label(environment))
        for environment in AssetEnvironment
    ]


def asset_type_label(value: AssetType | str | None) -> str:
    normalized = enum_value(value)
    return {
        AssetType.SERVER.value: "Serveur",
        AssetType.WORKSTATION.value: "Poste de travail",
        AssetType.NETWORK_DEVICE.value: "Equipement reseau",
        AssetType.APPLICATION.value: "Application",
        AssetType.DATABASE.value: "Base de donnees",
        AssetType.SECURITY_DEVICE.value: "Equipement de securite",
        AssetType.SERVICE.value: "Service",
        AssetType.OTHER.value: "Autre",
    }.get(normalized, "Non renseigne")


def criticality_label(value: AssetCriticality | str | None) -> str:
    normalized = enum_value(value)
    return {
        AssetCriticality.LOW.value: "Faible",
        AssetCriticality.MEDIUM.value: "Moyenne",
        AssetCriticality.HIGH.value: "Elevee",
        AssetCriticality.CRITICAL.value: "Critique",
    }.get(normalized, "Non renseignee")


def environment_label(value: AssetEnvironment | str | None) -> str:
    normalized = enum_value(value)
    return {
        AssetEnvironment.PRODUCTION.value: "Production",
        AssetEnvironment.PREPRODUCTION.value: "Preproduction",
        AssetEnvironment.DEVELOPMENT.value: "Developpement",
        AssetEnvironment.TEST.value: "Test",
        AssetEnvironment.OTHER.value: "Autre",
    }.get(normalized, "Non renseigne")


def asset_status_label(is_active: bool | None) -> str:
    if is_active is True:
        return "Actif"
    if is_active is False:
        return "Inactif"
    return "Tous"


def criticality_tone(value: AssetCriticality | str | None) -> str:
    normalized = enum_value(value)
    if normalized == AssetCriticality.CRITICAL.value:
        return "tone-critical"
    if normalized == AssetCriticality.HIGH.value:
        return "tone-warning"
    if normalized == AssetCriticality.MEDIUM.value:
        return "tone-info"
    if normalized == AssetCriticality.LOW.value:
        return "tone-success"
    return "tone-neutral"


def status_tone(is_active: bool | None) -> str:
    if is_active is True:
        return "tone-success"
    if is_active is False:
        return "tone-neutral"
    return "tone-neutral"


def environment_tone(value: AssetEnvironment | str | None) -> str:
    normalized = enum_value(value)
    if normalized == AssetEnvironment.PRODUCTION.value:
        return "tone-info"
    if normalized == AssetEnvironment.PREPRODUCTION.value:
        return "tone-warning"
    return "tone-neutral"


def enum_value(value: PythonEnum | str | None) -> str:
    if isinstance(value, PythonEnum):
        return str(value.value)
    return str(value or "").strip().upper()


def build_asset_filters(
    *,
    search: str,
    asset_type: AssetType | None,
    criticality: AssetCriticality | None,
    environment: AssetEnvironment | None,
    is_active: bool | None,
):
    filters = []

    if search:
        pattern = f"%{search}%"
        filters.append(
            or_(
                Asset.name.ilike(pattern),
                Asset.hostname.ilike(pattern),
                Asset.ip_address.ilike(pattern),
                Asset.vendor.ilike(pattern),
                Asset.product.ilike(pattern),
            )
        )

    if asset_type is not None:
        filters.append(Asset.asset_type == asset_type)

    if criticality is not None:
        filters.append(Asset.criticality == criticality)

    if environment is not None:
        filters.append(Asset.environment == environment)

    if is_active is not None:
        filters.append(Asset.is_active.is_(is_active))

    return filters


def normalize_required_string(value: Any, field_name: str) -> str:
    cleaned = normalize_optional_string(value)
    if not cleaned:
        raise AssetValidationError(f"{field_name} est obligatoire")
    return cleaned


def normalize_optional_string(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def normalize_ip_address(value: Any) -> str | None:
    cleaned = normalize_optional_string(value)
    if cleaned is None:
        return None
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError as exc:
        raise AssetValidationError("ip_address doit etre une adresse IPv4 ou IPv6 valide") from exc


def coerce_enum(
    enum_class: type[EnumValue],
    value: EnumValue | str | None,
    field_name: str,
    *,
    default: EnumValue | None = None,
) -> EnumValue:
    if value is None:
        if default is not None:
            return default
        raise AssetValidationError(f"{field_name} est obligatoire")

    if isinstance(value, enum_class):
        return value

    cleaned = normalize_optional_string(value)
    if cleaned is None:
        if default is not None:
            return default
        raise AssetValidationError(f"{field_name} est obligatoire")

    normalized = cleaned.upper()
    try:
        return enum_class(normalized)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in enum_class)
        raise AssetValidationError(
            f"{field_name} invalide: {cleaned}. Valeurs autorisees: {allowed}"
        ) from exc


def coerce_optional_filter_enum(
    enum_class: type[EnumValue],
    value: EnumValue | str | None,
    field_name: str,
) -> EnumValue | None:
    cleaned = normalize_optional_string(value)
    if cleaned is None:
        return None
    return coerce_enum(enum_class, cleaned, field_name)


def coerce_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        cleaned = value.strip().lower()
        if cleaned in {"true", "1", "yes", "on", "actif", "active"}:
            return True
        if cleaned in {"false", "0", "no", "off", "inactif", "inactive"}:
            return False
    raise AssetValidationError(f"{field_name} doit etre un booleen")


def coerce_optional_bool(value: Any, field_name: str) -> bool | None:
    if value is None or value == "":
        return None
    return coerce_bool(value, field_name)
