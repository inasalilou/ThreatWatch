"""
Verification locale de la phase 6.4 Gestion des utilisateurs.

Controle le service, les routes admin et les protections principales. Les
donnees de test et les commits de routes sont annules par une transaction
globale.
"""
from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

from sqlalchemy import func, inspect, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.core.deps import require_authenticated_user  # noqa: E402
from app.core.security import verify_password  # noqa: E402
from app.db.database import (  # noqa: E402
    SessionLocal,
    engine,
    get_db,
    get_safe_database_url,
    test_database_connection,
)
from app.main import app  # noqa: E402
from app.models.user import RoleUtilisateur, Utilisateur  # noqa: E402
from app.services.auth_service import authenticate_user  # noqa: E402
from app.services.user_service import (  # noqa: E402
    UserValidationError,
    change_password,
    create_user,
    disable_user,
    enable_user,
    get_user_stats,
    list_users,
    update_user,
)


def main() -> int:
    print(
        "Verification phase 6.4 utilisateurs avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        if not check_table_structure():
            return 1

        initial_count = count_persistent_users()
        connection = engine.connect()
        transaction = connection.begin()
        db = Session(bind=connection, join_transaction_mode="create_savepoint")
        try:
            admin = create_test_user(db, RoleUtilisateur.ADMIN, "ADMIN")
            analyst = create_test_user(db, RoleUtilisateur.ANALYSTE, "ANALYST")
            checks = [
                check_services(db),
                check_last_admin_protection(db),
                check_routes(db, admin, analyst),
            ]
            db.close()
            transaction.rollback()
        finally:
            connection.close()
            app.dependency_overrides.clear()

        if count_persistent_users() != initial_count:
            print("Rollback final utilisateurs: FAILED")
            return 1
        if not all(checks):
            return 1

        print("Rollback final utilisateurs: OK")
        print("PHASE 6.4 USERS CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR SQLAlchemy: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def check_table_structure() -> bool:
    inspector = inspect(engine)
    if "utilisateurs" not in inspector.get_table_names():
        print("Table utilisateurs presente: FAILED")
        return False

    columns = {column["name"] for column in inspector.get_columns("utilisateurs")}
    expected = {
        "id",
        "nom",
        "email",
        "mot_de_passe_hash",
        "role",
        "actif",
        "date_creation",
        "derniere_connexion",
    }
    if expected - columns:
        print("Colonnes utilisateurs: FAILED")
        return False

    unique_constraints = inspector.get_unique_constraints("utilisateurs")
    unique_indexes = inspector.get_indexes("utilisateurs")
    unique_columns = {tuple(item["column_names"]) for item in unique_constraints}
    unique_index_columns = {
        tuple(item["column_names"]) for item in unique_indexes if item.get("unique")
    }
    if ("email",) not in unique_columns and ("email",) not in unique_index_columns:
        print("Unicite email: FAILED")
        return False

    print("Table utilisateurs presente: OK")
    print("Unicite email: OK")
    return True


def check_services(db: Session) -> bool:
    token = uuid4().hex[:8]
    password = "Phase64Test1"
    user = create_user(
        db,
        nom=f"TEST USERS Analyst {token}",
        email=f"test-users-{token}@example.test",
        role=RoleUtilisateur.ANALYSTE.value,
        password=password,
        password_confirmation=password,
        actif=True,
    )

    hashed = user.mot_de_passe_hash != password and verify_password(
        password, user.mot_de_passe_hash
    )
    auth_ok = authenticate_user(db, user.email, password).success

    duplicate_rejected = False
    try:
        create_user(
            db,
            nom="Duplicate",
            email=user.email.upper(),
            role=RoleUtilisateur.ANALYSTE.value,
            password=password,
            password_confirmation=password,
            actif=True,
        )
    except UserValidationError:
        duplicate_rejected = True

    updated = update_user(
        db,
        user_id=user.id,
        nom=f"TEST USERS Updated {token}",
        email=f"test-users-updated-{token}@example.test",
        role=RoleUtilisateur.ADMIN.value,
    )
    disable_user(db, user.id)
    disabled = user.actif is False
    enable_user(db, user.id)
    enabled = user.actif is True
    change_password(
        db,
        user_id=user.id,
        password="Phase64Reset1",
        password_confirmation="Phase64Reset1",
    )
    reset_ok = authenticate_user(db, user.email, "Phase64Reset1").success

    search_result = list_users(db, search=token)
    role_result = list_users(db, role=RoleUtilisateur.ADMIN.value)
    inactive_result = list_users(db, status="inactive")
    page_result = list_users(db, per_page=1)
    stats = get_user_stats(db)

    if (
        not hashed
        or not auth_ok
        or not duplicate_rejected
        or updated is None
        or updated.role != RoleUtilisateur.ADMIN
        or not disabled
        or not enabled
        or not reset_ok
        or search_result.total < 1
        or role_result.total < 1
        or inactive_result.total < 0
        or page_result.per_page != 1
        or stats.total_users < 1
        or stats.admin_users < 1
    ):
        print("Services utilisateurs create/update/listing: FAILED")
        return False

    print("Mot de passe hash et connexion: OK")
    print("Services utilisateurs create/update/listing: OK")
    print("Activation/desactivation/reset password service: OK")
    print("Email duplicate refuse: OK")
    return True


def check_last_admin_protection(db: Session) -> bool:
    active_admins = list(
        db.scalars(
            select(Utilisateur).where(
                Utilisateur.role == RoleUtilisateur.ADMIN,
                Utilisateur.actif.is_(True),
            )
        )
    )
    for admin in active_admins:
        admin.actif = False
    db.flush()

    token = uuid4().hex[:8]
    solo_admin = create_user(
        db,
        nom=f"TEST USERS Solo Admin {token}",
        email=f"test-users-solo-admin-{token}@example.test",
        role=RoleUtilisateur.ADMIN.value,
        password="Phase64Solo1",
        password_confirmation="Phase64Solo1",
        actif=True,
    )

    disable_rejected = False
    try:
        disable_user(db, solo_admin.id)
    except UserValidationError:
        disable_rejected = True

    downgrade_rejected = False
    try:
        update_user(
            db,
            user_id=solo_admin.id,
            nom=solo_admin.nom,
            email=solo_admin.email,
            role=RoleUtilisateur.ANALYSTE.value,
        )
    except UserValidationError:
        downgrade_rejected = True

    if not disable_rejected or not downgrade_rejected:
        print("Protection dernier ADMIN actif: FAILED")
        return False

    print("Protection dernier ADMIN actif: OK")
    return True


def check_routes(
    db: Session,
    admin: Utilisateur,
    analyst: Utilisateur,
) -> bool:
    client = TestClient(app, follow_redirects=False)
    response = client.get("/users")
    if response.status_code != 303 or "/login" not in response.headers.get("location", ""):
        print("Route /users hors session: FAILED")
        return False

    if not route_admin_returns_200(db, admin):
        print("Route /users ADMIN: FAILED")
        return False
    if not route_analyst_forbidden(db, analyst):
        print("Route /users ANALYSTE interdit: FAILED")
        return False
    if not route_mutations_work(db, admin):
        print("Routes utilisateurs mutations ADMIN: FAILED")
        return False
    if not route_login_with_created_user_works(db):
        print("Connexion compte cree: FAILED")
        return False

    print("Route /users hors session: OK")
    print("Route /users ADMIN: OK")
    print("Route /users ANALYSTE interdit: OK")
    print("Routes utilisateurs mutations ADMIN: OK")
    print("Connexion compte cree: OK")
    return True


def route_admin_returns_200(db: Session, admin: Utilisateur) -> bool:
    install_overrides(db, admin)
    try:
        client = TestClient(app, follow_redirects=False)
        responses = [
            client.get("/users"),
            client.get("/users/new"),
            client.get(f"/users/{admin.id}"),
            client.get(f"/users/{admin.id}/edit"),
            client.get("/users", params={"q": admin.email, "role": "ADMIN"}),
        ]
        body = "".join(response.text for response in responses)
        return all(response.status_code == 200 for response in responses) and (
            "Utilisateurs" in body and admin.email in body and "mot_de_passe_hash" not in body
        )
    finally:
        app.dependency_overrides.clear()


def route_analyst_forbidden(db: Session, analyst: Utilisateur) -> bool:
    install_overrides(db, analyst)
    try:
        client = TestClient(app, follow_redirects=False)
        responses = [
            client.get("/users"),
            client.get("/users/new"),
            client.get(f"/users/{analyst.id}"),
            client.get(f"/users/{analyst.id}/edit"),
        ]
        return all(response.status_code == 403 for response in responses)
    finally:
        app.dependency_overrides.clear()


def route_mutations_work(db: Session, admin: Utilisateur) -> bool:
    token = uuid4().hex[:8]
    install_overrides(db, admin)
    try:
        client = TestClient(app, follow_redirects=False)
        create_response = client.post(
            "/users",
            data={
                "nom": f"TEST USERS ROUTE {token}",
                "email": f"test-users-route-{token}@example.test",
                "role": "ANALYSTE",
                "password": "Phase64Route1",
                "password_confirmation": "Phase64Route1",
                "actif": "on",
            },
        )
        user = db.scalar(
            select(Utilisateur).where(
                Utilisateur.email == f"test-users-route-{token}@example.test"
            )
        )
        if create_response.status_code != 303 or user is None:
            return False

        edit_response = client.post(
            f"/users/{user.id}/edit",
            data={
                "nom": f"TEST USERS ROUTE UPDATED {token}",
                "email": f"test-users-route-updated-{token}@example.test",
                "role": "ADMIN",
            },
        )
        reset_response = client.post(
            f"/users/{user.id}/reset-password",
            data={
                "password": "Phase64RouteReset1",
                "password_confirmation": "Phase64RouteReset1",
            },
        )
        disable_response = client.post(f"/users/{user.id}/disable")
        db.refresh(user)
        disabled = user.actif is False
        enable_response = client.post(f"/users/{user.id}/enable")
        db.refresh(user)
        enabled = user.actif is True
        duplicate_response = client.post(
            "/users",
            data={
                "nom": "Duplicate Route",
                "email": user.email,
                "role": "ANALYSTE",
                "password": "Phase64Route1",
                "password_confirmation": "Phase64Route1",
                "actif": "on",
            },
        )

        return (
            edit_response.status_code == 303
            and reset_response.status_code == 303
            and disable_response.status_code == 303
            and enable_response.status_code == 303
            and duplicate_response.status_code == 400
            and disabled
            and enabled
            and user.role == RoleUtilisateur.ADMIN
            and verify_password("Phase64RouteReset1", user.mot_de_passe_hash)
        )
    finally:
        app.dependency_overrides.clear()


def route_login_with_created_user_works(db: Session) -> bool:
    token = uuid4().hex[:8]
    email = f"test-users-login-{token}@example.test"
    password = "Phase64Login1"
    create_user(
        db,
        nom=f"TEST USERS LOGIN {token}",
        email=email,
        role=RoleUtilisateur.ANALYSTE.value,
        password=password,
        password_confirmation=password,
        actif=True,
    )

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app, follow_redirects=False)
        response = client.post(
            "/login",
            data={"email": email, "password": password, "next": "/dashboard"},
        )
        return response.status_code == 303 and response.headers.get("location") == "/dashboard"
    finally:
        app.dependency_overrides.clear()


def install_overrides(db: Session, user: Utilisateur) -> None:
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[require_authenticated_user] = lambda: user


def create_test_user(db: Session, role: RoleUtilisateur, label: str) -> Utilisateur:
    token = uuid4().hex
    user = Utilisateur(
        nom=f"TEST USERS {label} {token[:6]}",
        email=f"test-users-{label.lower()}-{token}@example.test",
        mot_de_passe_hash="not-used",
        role=role,
        actif=True,
    )
    db.add(user)
    db.flush()
    return user


def count_persistent_users() -> int:
    with SessionLocal() as db:
        return db.scalar(select(func.count(Utilisateur.id))) or 0


if __name__ == "__main__":
    raise SystemExit(main())
