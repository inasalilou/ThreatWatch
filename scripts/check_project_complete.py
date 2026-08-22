"""
Validation finale agregee de ThreatWatch.

Ce script lance les checks de non-regression, controle l'authentification,
la protection CSRF, l'hygiene Git/secrets et l'absence de pollution evidente
de donnees demo/test. Aucun batch global et aucun appel reseau massif.
"""
from __future__ import annotations

import html
import re
import subprocess
import sys
from pathlib import Path

from sqlalchemy import func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, engine, get_db, get_safe_database_url, test_database_connection  # noqa: E402
from app.main import app  # noqa: E402
from app.models.alert import Alert  # noqa: E402
from app.models.asset import Asset  # noqa: E402
from app.models.notification import Notification  # noqa: E402
from app.models.user import RoleUtilisateur, Utilisateur  # noqa: E402
from app.models.vulnerability import Vulnerability  # noqa: E402
from app.core.security import hash_password  # noqa: E402


CHECK_SCRIPTS = [
    "scripts/check_phase2_complete.py",
    "scripts/check_phase3_vulnerabilities.py",
    "scripts/check_phase3_enrichment.py",
    "scripts/check_phase4_assets.py",
    "scripts/check_phase4_affected_products.py",
    "scripts/check_phase4_matching_utils.py",
    "scripts/check_phase4_correlation.py",
    "scripts/check_phase4_correlation_persistence.py",
    "scripts/check_phase4_correlations_page.py",
    "scripts/check_phase5_alerts.py",
    "scripts/check_phase5_priority.py",
    "scripts/check_phase5_alerts_ui.py",
    "scripts/check_phase5_alert_trigger.py",
    "scripts/check_phase6_analyst_treatment.py",
    "scripts/check_phase6_treatments_page.py",
    "scripts/check_phase6_notifications.py",
    "scripts/check_phase6_notifications_ui.py",
    "scripts/check_phase6_email_notifications.py",
    "scripts/check_phase6_sources.py",
    "scripts/check_phase6_users.py",
    "scripts/check_phase6_settings.py",
    "scripts/check_phase6_soc_pipeline.py",
    "scripts/check_phase6_dashboard.py",
    "scripts/check_final_e2e.py",
]

TOKEN_RE = re.compile(r'name="_csrf_token" value="([^"]+)"')


def main() -> int:
    print(f"Validation finale ThreatWatch avec DATABASE_URL={get_safe_database_url()}")
    try:
        test_database_connection()
        checks = [
            check_health_route(),
            check_auth_and_csrf(),
            check_git_and_secret_hygiene(),
            check_demo_test_residue_report(),
            run_non_regression_scripts(),
        ]
    except SQLAlchemyError as exc:
        print(f"ERREUR SQLAlchemy: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1
    finally:
        app.dependency_overrides.clear()

    if not all(checks):
        print("THREATWATCH FINAL CHECK: FAILED")
        return 1

    print("Permissions finales: ADMIN=administration complete, ANALYSTE=consultation SOC et traitements, inactif=refuse")
    print("Phases validees: 1-2 collecte, 3 enrichissement, 4 correlation, 5 alertes, 6 traitements/notifications/sources/users/settings/pipeline/dashboard")
    print("THREATWATCH FINAL CHECK: OK")
    return 0


def check_health_route() -> bool:
    client = TestClient(app, follow_redirects=False)
    response = client.get("/health")
    if response.status_code == 200 and response.json().get("status") == "ok":
        print("/health: OK")
        return True
    print("/health: FAILED")
    return False


def check_auth_and_csrf() -> bool:
    connection = engine.connect()
    transaction = connection.begin()
    db = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        admin = create_user(db, RoleUtilisateur.ADMIN, "Admin")
        analyst = create_user(db, RoleUtilisateur.ANALYSTE, "Analyst")
        inactive = create_user(db, RoleUtilisateur.ANALYSTE, "Inactive", active=False)
        install_db_override(db)

        checks = [
            check_protected_redirect(),
            check_login_valid_invalid_logout(admin, inactive),
            check_role_permissions(admin, analyst),
            check_csrf_rejection(admin),
        ]
        db.close()
        transaction.rollback()
    finally:
        connection.close()
        app.dependency_overrides.clear()

    if all(checks):
        print("Authentification/session/CSRF: OK")
        return True
    print("Authentification/session/CSRF: FAILED")
    return False


def check_protected_redirect() -> bool:
    client = TestClient(app, follow_redirects=False)
    response = client.get("/dashboard")
    return response.status_code == 303 and "/login" in response.headers.get("location", "")


def check_login_valid_invalid_logout(admin: Utilisateur, inactive: Utilisateur) -> bool:
    client = TestClient(app, follow_redirects=False)

    login_page = client.get("/login")
    token = extract_csrf_token(login_page.text)
    invalid = client.post(
        "/login",
        data={
            "_csrf_token": token,
            "email": admin.email,
            "password": "wrong-password",
            "next": "/dashboard",
        },
    )
    if invalid.status_code != 401:
        return False

    login_page = client.get("/login")
    token = extract_csrf_token(login_page.text)
    valid = client.post(
        "/login",
        data={
            "_csrf_token": token,
            "email": admin.email,
            "password": test_password(admin),
            "next": "/dashboard",
        },
    )
    if valid.status_code != 303 or valid.headers.get("location") != "/dashboard":
        return False

    logout = client.get("/logout")
    if logout.status_code != 303 or "/login" not in logout.headers.get("location", ""):
        return False

    inactive_page = client.get("/login")
    token = extract_csrf_token(inactive_page.text)
    inactive_login = client.post(
        "/login",
        data={
            "_csrf_token": token,
            "email": inactive.email,
            "password": test_password(inactive),
            "next": "/dashboard",
        },
    )
    return inactive_login.status_code == 401


def check_role_permissions(admin: Utilisateur, analyst: Utilisateur) -> bool:
    admin_client = logged_client(admin)
    analyst_client = logged_client(analyst)
    admin_users = admin_client.get("/users")
    analyst_users = analyst_client.get("/users")
    analyst_dashboard = analyst_client.get("/dashboard")
    return (
        admin_users.status_code == 200
        and analyst_users.status_code == 403
        and analyst_dashboard.status_code == 200
    )


def check_csrf_rejection(admin: Utilisateur) -> bool:
    client = logged_client(admin)
    response = client.post("/settings", data={})
    return response.status_code == 403


def logged_client(user: Utilisateur) -> TestClient:
    client = TestClient(app, follow_redirects=False)
    login_page = client.get("/login")
    token = extract_csrf_token(login_page.text)
    response = client.post(
        "/login",
        data={
            "_csrf_token": token,
            "email": user.email,
            "password": test_password(user),
            "next": "/dashboard",
        },
    )
    if response.status_code != 303:
        raise RuntimeError(f"Login de test impossible pour {user.email}.")
    return client


def install_db_override(db: Session) -> None:
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db


def create_user(
    db: Session,
    role: RoleUtilisateur,
    label: str,
    *,
    active: bool = True,
) -> Utilisateur:
    email = f"test-final-{label.lower()}-{Path.cwd().name.lower()}-{id(db)}@example.test"
    user = Utilisateur(
        nom=f"TEST FINAL {label}",
        email=email,
        mot_de_passe_hash=hash_password(test_password_from_label(label)),
        role=role,
        actif=active,
    )
    db.add(user)
    db.flush()
    return user


def test_password(user: Utilisateur) -> str:
    label = user.nom.replace("TEST FINAL ", "")
    return test_password_from_label(label)


def test_password_from_label(label: str) -> str:
    return f"Valid-{label}-Password-42"


def extract_csrf_token(body: str) -> str:
    match = TOKEN_RE.search(body)
    if not match:
        raise RuntimeError("Token CSRF introuvable dans le formulaire.")
    return html.unescape(match.group(1))


def check_git_and_secret_hygiene() -> bool:
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8", errors="replace")
    env_example = (PROJECT_ROOT / ".env.example").read_text(
        encoding="utf-8",
        errors="replace",
    )
    required_ignores = [".env", ".venv/", "venv/", "__pycache__/", "*.pyc"]
    ignores_ok = all(item in gitignore for item in required_ignores)
    env_not_tracked = command_returns_nonzero(["git", "ls-files", "--error-unmatch", ".env"])
    placeholders_ok = secrets_are_placeholders(env_example)

    if ignores_ok and env_not_tracked and placeholders_ok:
        print("Hygiene Git/secrets: OK")
        return True

    print("Hygiene Git/secrets: FAILED")
    return False


def secrets_are_placeholders(env_example: str) -> bool:
    for raw_line in env_example.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        sensitive = any(part in key for part in ["PASSWORD", "SECRET", "API_KEY", "TOKEN"])
        if sensitive and value and value not in {
            "change-moi-en-production",
            "MOT_DE_PASSE_POSTGRES",
        }:
            return False
    return True


def command_returns_nonzero(command: list[str]) -> bool:
    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode != 0


def check_demo_test_residue_report() -> bool:
    with SessionLocal() as db:
        counts = {
            "assets": count_like(db, Asset.name),
            "alerts": count_like(db, Alert.title),
            "notifications": count_like(db, Notification.title),
            "users": count_like(db, Utilisateur.email),
            "vulnerabilities_test_descriptions": count_like(db, Vulnerability.description),
        }

    print(
        "Residus TEST/DEMO/TEMP detectes (rapport sans suppression): "
        + ", ".join(f"{key}={value}" for key, value in counts.items())
    )
    return True


def count_like(db: Session, column) -> int:
    patterns = ["%TEST-%", "%DEMO-%", "%TEMP-%"]
    return (
        db.scalar(select(func.count()).where(or_(*(column.ilike(item) for item in patterns))))
        or 0
    )


def run_non_regression_scripts() -> bool:
    for script in CHECK_SCRIPTS:
        result = subprocess.run(
            [sys.executable, script],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=180,
        )
        if result.returncode != 0:
            print(f"{script}: FAILED")
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr)
            return False
        print(f"{script}: OK")
    return True


if __name__ == "__main__":
    raise SystemExit(main())
