"""
Verification locale de la phase 6.5 Parametres administratifs.

Controle le modele, l'initialisation, les validations, les routes et l'absence
de secrets dans le rendu HTML. Les changements de test sont annules a la fin.
"""
from __future__ import annotations

import html
import re
import sys
from pathlib import Path
from uuid import uuid4

from sqlalchemy import func, inspect, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.core import config as config_module  # noqa: E402
from app.core.deps import require_authenticated_user  # noqa: E402
from app.db.database import (  # noqa: E402
    SessionLocal,
    create_database_tables,
    engine,
    get_db,
    get_safe_database_url,
    test_database_connection,
)
from app.main import app  # noqa: E402
from app.models.app_setting import AppSetting  # noqa: E402
from app.models.user import RoleUtilisateur, Utilisateur  # noqa: E402
from app.services.settings_service import (  # noqa: E402
    SAFE_SETTING_KEYS,
    SettingsValidationError,
    get_effective_settings,
    get_setting,
    initialize_default_settings,
    list_settings,
    set_setting,
    validate_setting_value,
)


TOKEN_RE = re.compile(r'name="_csrf_token" value="([^"]+)"')


def main() -> int:
    print(
        "Verification phase 6.5 settings avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        create_database_tables()
        if not check_table_structure():
            return 1

        initial_count = count_persistent_settings()
        connection = engine.connect()
        transaction = connection.begin()
        db = Session(bind=connection, join_transaction_mode="create_savepoint")
        try:
            admin = create_test_user(db, RoleUtilisateur.ADMIN)
            analyst = create_test_user(db, RoleUtilisateur.ANALYSTE)
            checks = [
                check_initialization_and_services(db),
                check_validation(db),
                check_no_secret_in_settings(db),
                check_routes(db, admin, analyst),
            ]
            db.close()
            transaction.rollback()
        finally:
            connection.close()
            app.dependency_overrides.clear()

        if count_persistent_settings() != initial_count:
            print("Rollback final settings: FAILED")
            return 1
        if not all(checks):
            return 1

        print("Rollback final settings: OK")
        print("PHASE 6.5 SETTINGS CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR SQLAlchemy: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def check_table_structure() -> bool:
    inspector = inspect(engine)
    if "app_settings" not in inspector.get_table_names():
        print("Table app_settings presente: FAILED")
        return False

    columns = {column["name"] for column in inspector.get_columns("app_settings")}
    expected = {
        "id",
        "key",
        "value",
        "value_type",
        "description",
        "is_editable",
        "created_at",
        "updated_at",
    }
    if expected - columns:
        print("Colonnes app_settings: FAILED")
        return False

    unique_constraints = inspector.get_unique_constraints("app_settings")
    unique_indexes = inspector.get_indexes("app_settings")
    unique_columns = {tuple(item["column_names"]) for item in unique_constraints}
    unique_index_columns = {
        tuple(item["column_names"]) for item in unique_indexes if item.get("unique")
    }
    if ("key",) not in unique_columns and ("key",) not in unique_index_columns:
        print("Unicite key app_settings: FAILED")
        return False

    print("Table app_settings presente: OK")
    print("Unicite key app_settings: OK")
    return True


def check_initialization_and_services(db: Session) -> bool:
    first_created = initialize_default_settings(db)
    second_created = initialize_default_settings(db)
    views = list_settings(db)
    effective = get_effective_settings(db)

    if second_created:
        print("Init app_settings idempotente: FAILED")
        return False
    if {view.definition.key for view in views} != SAFE_SETTING_KEYS:
        print("Cles settings autorisees: FAILED")
        return False
    if set(effective.keys()) != SAFE_SETTING_KEYS:
        print("Effective settings: FAILED")
        return False

    set_setting(db, "APP_DISPLAY_NAME", "ThreatWatch SOC")
    set_setting(db, "DEFAULT_PAGE_SIZE", "25")
    set_setting(db, "DGSSI_SYNC_ENABLED", "false")
    if (
        get_setting(db, "APP_DISPLAY_NAME").value != "ThreatWatch SOC"
        or get_setting(db, "DEFAULT_PAGE_SIZE").value != "25"
        or get_setting(db, "DGSSI_SYNC_ENABLED").value != "false"
    ):
        print("Update settings: FAILED")
        return False

    print(f"Init app_settings idempotente: OK ({len(first_created)} cree(s) au plus)")
    print("Cles settings autorisees: OK")
    print("Update settings: OK")
    return True


def check_validation(db: Session) -> bool:
    integer_ok = validate_setting_value("DGSSI_SYNC_INTERVAL_MINUTES", "15") == "15"
    boolean_ok = validate_setting_value("DGSSI_SYNC_ENABLED", "false") == "false"
    enum_ok = validate_setting_value("ALERT_NOTIFICATION_MIN_PRIORITY", "critical") == "CRITICAL"

    invalid_cases = [
        ("DGSSI_SYNC_INTERVAL_MINUTES", "0"),
        ("NVD_BATCH_SIZE", "500"),
        ("DEFAULT_PAGE_SIZE", "3"),
        ("ALERT_NOTIFICATION_MIN_PRIORITY", "URGENT"),
        ("SMTP_PASSWORD", "secret"),
    ]
    rejected = 0
    for key, value in invalid_cases:
        try:
            set_setting(db, key, value)
        except SettingsValidationError:
            rejected += 1

    if not integer_ok or not boolean_ok or not enum_ok or rejected != len(invalid_cases):
        print("Validation settings: FAILED")
        return False

    print("Validation INTEGER: OK")
    print("Validation BOOLEAN: OK")
    print("Validation enum: OK")
    print("Valeurs invalides refusees: OK")
    return True


def check_no_secret_in_settings(db: Session) -> bool:
    initialize_default_settings(db)
    settings_rows = list(db.scalars(select(AppSetting)))
    forbidden_fragments = [
        "PASSWORD",
        "SECRET",
        "TOKEN",
        "API_KEY",
        "DATABASE_URL",
        "SESSION_SECRET",
        "SMTP_PASSWORD",
        "NVD_API_KEY",
    ]
    for row in settings_rows:
        combined = f"{row.key} {row.value}".upper()
        if any(fragment in combined for fragment in forbidden_fragments):
            print("Secret absent de app_settings: FAILED")
            return False

    print("Secret absent de app_settings: OK")
    return True


def check_routes(
    db: Session,
    admin: Utilisateur,
    analyst: Utilisateur,
) -> bool:
    client = TestClient(app, follow_redirects=False)
    response = client.get("/settings")
    if response.status_code != 303 or "/login" not in response.headers.get("location", ""):
        print("Route /settings hors session: FAILED")
        return False

    if not route_admin_returns_200_and_no_secret(db, admin):
        print("Route /settings ADMIN/securite HTML: FAILED")
        return False
    if not route_analyst_forbidden(db, analyst):
        print("Route /settings ANALYSTE interdit: FAILED")
        return False
    if not route_update_and_invalid_work(db, admin):
        print("Route /settings update/validation: FAILED")
        return False

    print("Route /settings hors session: OK")
    print("Route /settings ADMIN: OK")
    print("Route /settings ANALYSTE interdit: OK")
    print("Aucun secret rendu dans HTML: OK")
    print("Route /settings update/validation: OK")
    return True


def route_admin_returns_200_and_no_secret(db: Session, admin: Utilisateur) -> bool:
    install_overrides(db, admin)
    original_values = (
        config_module.settings.SMTP_PASSWORD,
        config_module.settings.NVD_API_KEY,
        config_module.settings.SESSION_SECRET_KEY,
        config_module.settings.DATABASE_URL,
    )
    sentinels = {
        "TW_SMTP_SECRET_SENTINEL",
        "TW_NVD_SECRET_SENTINEL",
        "TW_SESSION_SECRET_SENTINEL",
        "TW_DATABASE_SECRET_SENTINEL",
    }
    try:
        config_module.settings.SMTP_PASSWORD = "TW_SMTP_SECRET_SENTINEL"
        config_module.settings.NVD_API_KEY = "TW_NVD_SECRET_SENTINEL"
        config_module.settings.SESSION_SECRET_KEY = "TW_SESSION_SECRET_SENTINEL"
        config_module.settings.DATABASE_URL = (
            "postgresql+psycopg://postgres:TW_DATABASE_SECRET_SENTINEL@localhost/threatwatch"
        )

        client = TestClient(app, follow_redirects=False)
        response = client.get("/settings")
        body = response.text
        return (
            response.status_code == 200
            and "Parametres" in body
            and "Configuration sensible" in body
            and not any(secret in body for secret in sentinels)
            and "SMTP_PASSWORD" not in body
            and "NVD_API_KEY" not in body
            and "SESSION_SECRET" not in body
            and "DATABASE_URL" not in body
        )
    finally:
        (
            config_module.settings.SMTP_PASSWORD,
            config_module.settings.NVD_API_KEY,
            config_module.settings.SESSION_SECRET_KEY,
            config_module.settings.DATABASE_URL,
        ) = original_values
        app.dependency_overrides.clear()


def route_analyst_forbidden(db: Session, analyst: Utilisateur) -> bool:
    install_overrides(db, analyst)
    try:
        client = TestClient(app, follow_redirects=False)
        responses = [client.get("/settings"), client.post("/settings", data={})]
        return all(response.status_code == 403 for response in responses)
    finally:
        app.dependency_overrides.clear()


def route_update_and_invalid_work(db: Session, admin: Utilisateur) -> bool:
    install_overrides(db, admin)
    try:
        client = TestClient(app, follow_redirects=False)
        valid_response = client.post(
            "/settings",
            data={
                "APP_DISPLAY_NAME": "ThreatWatch Settings Test",
                "DGSSI_SYNC_ENABLED": "on",
                "DGSSI_SYNC_INTERVAL_MINUTES": "45",
                "NVD_BATCH_SIZE": "8",
                "NVD_REQUEST_DELAY_SECONDS": "1.5",
                "SOC_PIPELINE_ENABLED": "on",
                "ALERT_NOTIFICATION_MIN_PRIORITY": "HIGH",
                "DEFAULT_PAGE_SIZE": "30",
            },
        )
        csrf_token = extract_csrf_token(valid_response.text)
        db.expire_all()
        valid_saved = (
            get_setting(db, "APP_DISPLAY_NAME").value == "ThreatWatch Settings Test"
            and get_setting(db, "DGSSI_SYNC_INTERVAL_MINUTES").value == "45"
            and get_setting(db, "NVD_REQUEST_DELAY_SECONDS").value == "1.5"
        )
        invalid_response = client.post(
            "/settings",
            data={
                "_csrf_token": csrf_token,
                "APP_DISPLAY_NAME": "ThreatWatch Settings Test",
                "DGSSI_SYNC_INTERVAL_MINUTES": "0",
                "NVD_BATCH_SIZE": "8",
                "NVD_REQUEST_DELAY_SECONDS": "1.5",
                "SOC_PIPELINE_ENABLED": "on",
                "ALERT_NOTIFICATION_MIN_PRIORITY": "HIGH",
                "DEFAULT_PAGE_SIZE": "30",
            },
        )
        return valid_response.status_code == 200 and valid_saved and invalid_response.status_code == 400
    finally:
        app.dependency_overrides.clear()


def install_overrides(db: Session, user: Utilisateur) -> None:
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[require_authenticated_user] = lambda: user


def create_test_user(db: Session, role: RoleUtilisateur) -> Utilisateur:
    token = uuid4().hex
    user = Utilisateur(
        nom=f"TEST SETTINGS {role.value} {token[:6]}",
        email=f"test-settings-{role.value.lower()}-{token}@example.test",
        mot_de_passe_hash="not-used",
        role=role,
        actif=True,
    )
    db.add(user)
    db.flush()
    return user


def count_persistent_settings() -> int:
    with SessionLocal() as db:
        return db.scalar(select(func.count(AppSetting.id))) or 0


def extract_csrf_token(body: str) -> str:
    match = TOKEN_RE.search(body)
    if not match:
        raise RuntimeError("Token CSRF introuvable dans /settings.")
    return html.unescape(match.group(1))


if __name__ == "__main__":
    raise SystemExit(main())
