"""
Service des parametres administratifs non sensibles.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.app_setting import AppSetting, AppSettingValueType


class SettingsValidationError(ValueError):
    """Erreur metier affichable sur la page de parametres."""


@dataclass(frozen=True)
class SettingDefinition:
    key: str
    label: str
    section: str
    value_type: AppSettingValueType
    default: str
    description: str
    is_editable: bool = True


@dataclass(frozen=True)
class SettingView:
    definition: SettingDefinition
    setting: AppSetting | None
    value: str
    effective_value: Any


SAFE_SETTING_DEFINITIONS: tuple[SettingDefinition, ...] = (
    SettingDefinition(
        key="APP_DISPLAY_NAME",
        label="Nom affiche",
        section="General",
        value_type=AppSettingValueType.STRING,
        default=settings.APP_NAME,
        description="Nom fonctionnel affiche dans les vues d'administration.",
    ),
    SettingDefinition(
        key="DGSSI_SYNC_ENABLED",
        label="Synchronisation DGSSI activee",
        section="Synchronisation DGSSI",
        value_type=AppSettingValueType.BOOLEAN,
        default="true" if settings.DGSSI_SYNC_ENABLED else "false",
        description="Activation administrative stockee en base. Un redemarrage peut etre necessaire.",
    ),
    SettingDefinition(
        key="DGSSI_SYNC_INTERVAL_MINUTES",
        label="Intervalle de synchronisation DGSSI",
        section="Synchronisation DGSSI",
        value_type=AppSettingValueType.INTEGER,
        default=str(settings.DGSSI_SYNC_INTERVAL_MINUTES),
        description="Intervalle en minutes. Un redemarrage peut etre necessaire.",
    ),
    SettingDefinition(
        key="NVD_BATCH_SIZE",
        label="Taille du lot NVD",
        section="Enrichissement NVD",
        value_type=AppSettingValueType.INTEGER,
        default=str(settings.NVD_BATCH_SIZE),
        description="Nombre de CVE traitees par lot controle.",
    ),
    SettingDefinition(
        key="NVD_REQUEST_DELAY_SECONDS",
        label="Delai entre appels NVD",
        section="Enrichissement NVD",
        value_type=AppSettingValueType.FLOAT,
        default=str(settings.NVD_REQUEST_DELAY_SECONDS),
        description="Pause en secondes entre deux appels NVD.",
    ),
    SettingDefinition(
        key="SOC_PIPELINE_ENABLED",
        label="Pipeline SOC automatique",
        section="Alertes / Notifications",
        value_type=AppSettingValueType.BOOLEAN,
        default="true",
        description="Declenchement automatique du pipeline SOC apres synchronisation DGSSI.",
    ),
    SettingDefinition(
        key="ALERT_NOTIFICATION_MIN_PRIORITY",
        label="Priorite minimale de notification",
        section="Alertes / Notifications",
        value_type=AppSettingValueType.STRING,
        default="HIGH",
        description="Seuil administratif non sensible pour les notifications.",
    ),
    SettingDefinition(
        key="DEFAULT_PAGE_SIZE",
        label="Taille de page par defaut",
        section="Interface",
        value_type=AppSettingValueType.INTEGER,
        default="20",
        description="Nombre d'elements affiche par page dans les listes.",
    ),
)

SAFE_SETTING_KEYS = {definition.key for definition in SAFE_SETTING_DEFINITIONS}
SENSITIVE_KEYWORDS = (
    "PASSWORD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "DATABASE_URL",
    "SESSION_SECRET",
    "SMTP_PASSWORD",
    "NVD_API_KEY",
)
SETTING_SECTIONS = (
    "General",
    "Synchronisation DGSSI",
    "Enrichissement NVD",
    "Alertes / Notifications",
    "Interface",
)


def get_setting(db: Session, key: str) -> AppSetting | None:
    return db.scalar(select(AppSetting).where(AppSetting.key == key))


def set_setting(db: Session, key: str, raw_value: str) -> AppSetting:
    definition = get_setting_definition(key)
    validate_safe_key(key)
    value = validate_setting_value(definition, raw_value)
    setting = get_setting(db, key)

    if setting is None:
        setting = AppSetting(
            key=definition.key,
            value=value,
            value_type=definition.value_type,
            description=definition.description,
            is_editable=definition.is_editable,
        )
        db.add(setting)
    else:
        if not setting.is_editable:
            raise SettingsValidationError("Ce parametre n'est pas modifiable.")
        setting.value = value
        setting.value_type = definition.value_type
        setting.description = definition.description
        setting.is_editable = definition.is_editable
        db.add(setting)

    db.flush()
    return setting


def list_settings(db: Session) -> list[SettingView]:
    existing = {setting.key: setting for setting in db.scalars(select(AppSetting)).all()}
    result: list[SettingView] = []
    for definition in SAFE_SETTING_DEFINITIONS:
        setting = existing.get(definition.key)
        value = setting.value if setting is not None else definition.default
        result.append(
            SettingView(
                definition=definition,
                setting=setting,
                value=value,
                effective_value=parse_setting_value(definition, value),
            )
        )
    return result


def get_effective_settings(db: Session) -> dict[str, Any]:
    return {view.definition.key: view.effective_value for view in list_settings(db)}


def initialize_default_settings(db: Session) -> list[AppSetting]:
    created: list[AppSetting] = []
    for definition in SAFE_SETTING_DEFINITIONS:
        validate_safe_key(definition.key)
        if get_setting(db, definition.key) is not None:
            continue
        setting = AppSetting(
            key=definition.key,
            value=validate_setting_value(definition, definition.default),
            value_type=definition.value_type,
            description=definition.description,
            is_editable=definition.is_editable,
        )
        db.add(setting)
        created.append(setting)
    db.flush()
    return created


def validate_setting_value(
    definition: SettingDefinition | str,
    raw_value: str,
) -> str:
    if isinstance(definition, str):
        definition = get_setting_definition(definition)
    value = raw_value.strip()

    if definition.key == "APP_DISPLAY_NAME":
        if not value:
            raise SettingsValidationError("Le nom affiche est obligatoire.")
        if len(value) > 80:
            raise SettingsValidationError("Le nom affiche ne doit pas depasser 80 caracteres.")
        return value

    if definition.key == "DGSSI_SYNC_INTERVAL_MINUTES":
        parsed = parse_integer(value, definition.label)
        if parsed <= 0 or parsed > 1440:
            raise SettingsValidationError("L'intervalle DGSSI doit etre entre 1 et 1440 minutes.")
        return str(parsed)

    if definition.key == "DGSSI_SYNC_ENABLED":
        return "true" if parse_boolean(value, definition.label) else "false"

    if definition.key == "NVD_BATCH_SIZE":
        parsed = parse_integer(value, definition.label)
        if parsed < 1 or parsed > 100:
            raise SettingsValidationError("La taille du lot NVD doit etre entre 1 et 100.")
        return str(parsed)

    if definition.key == "NVD_REQUEST_DELAY_SECONDS":
        parsed = parse_float(value, definition.label)
        if parsed < 0 or parsed > 3600:
            raise SettingsValidationError("Le delai NVD doit etre entre 0 et 3600 secondes.")
        return format_float(parsed)

    if definition.key == "DEFAULT_PAGE_SIZE":
        parsed = parse_integer(value, definition.label)
        if parsed < 5 or parsed > 100:
            raise SettingsValidationError("La taille de page doit etre entre 5 et 100.")
        return str(parsed)

    if definition.key == "SOC_PIPELINE_ENABLED":
        return "true" if parse_boolean(value, definition.label) else "false"

    if definition.key == "ALERT_NOTIFICATION_MIN_PRIORITY":
        value = value.upper()
        if value not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise SettingsValidationError(
                "La priorite minimale doit etre LOW, MEDIUM, HIGH ou CRITICAL."
            )
        return value

    if definition.value_type == AppSettingValueType.BOOLEAN:
        return "true" if parse_boolean(value, definition.label) else "false"

    raise SettingsValidationError("Parametre non autorise.")


def get_setting_definition(key: str) -> SettingDefinition:
    for definition in SAFE_SETTING_DEFINITIONS:
        if definition.key == key:
            return definition
    raise SettingsValidationError("Parametre non autorise.")


def grouped_settings(setting_views: list[SettingView]) -> list[tuple[str, list[SettingView]]]:
    return [
        (
            section,
            [view for view in setting_views if view.definition.section == section],
        )
        for section in SETTING_SECTIONS
    ]


def get_sensitive_configuration_status() -> dict[str, str]:
    return {
        "database": "Configuree" if settings.DATABASE_URL else "Non configuree",
        "smtp": "Active" if settings.SMTP_ENABLED else "Desactive",
        "nvd_api": "Configuree" if settings.NVD_API_BASE_URL else "Non configuree",
        "nvd_api_key": "Configuree" if settings.NVD_API_KEY else "Non configuree",
        "session": "Configuree" if settings.SESSION_SECRET_KEY else "Non configuree",
    }


def parse_setting_value(definition: SettingDefinition, value: str) -> Any:
    if definition.value_type == AppSettingValueType.INTEGER:
        return int(value)
    if definition.value_type == AppSettingValueType.FLOAT:
        return float(value)
    if definition.value_type == AppSettingValueType.BOOLEAN:
        return parse_boolean(value, definition.label)
    return value


def validate_safe_key(key: str) -> None:
    if key not in SAFE_SETTING_KEYS:
        raise SettingsValidationError("Parametre non autorise.")
    upper_key = key.upper()
    if any(keyword in upper_key for keyword in SENSITIVE_KEYWORDS):
        raise SettingsValidationError("Les secrets ne peuvent pas etre stockes ici.")


def parse_integer(value: str, label: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        raise SettingsValidationError(f"{label} doit etre un entier.") from exc


def parse_float(value: str, label: str) -> float:
    try:
        return float(value.replace(",", "."))
    except ValueError as exc:
        raise SettingsValidationError(f"{label} doit etre un nombre.") from exc


def parse_boolean(value: str, label: str) -> bool:
    clean = value.strip().lower()
    if clean in {"true", "1", "yes", "on", "oui"}:
        return True
    if clean in {"false", "0", "no", "off", "non"}:
        return False
    raise SettingsValidationError(f"{label} doit etre un booleen.")


def format_float(value: float) -> str:
    return f"{value:g}"
