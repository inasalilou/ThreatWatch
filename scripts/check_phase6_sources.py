"""
Verification locale de la phase 6.3 Sources de veille.

Controle le modele ThreatSource, l'initialisation DGSSI, les services et les
routes /sources. Les donnees de test sont annulees a la fin.
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
from app.db.database import SessionLocal, engine, get_db, get_safe_database_url, test_database_connection  # noqa: E402
from app.main import app  # noqa: E402
from app.models.threat_source import ThreatSource, ThreatSourceType  # noqa: E402
from app.models.user import RoleUtilisateur, Utilisateur  # noqa: E402
from app.services.threat_source_service import (  # noqa: E402
    DGSSI_CODE,
    ThreatSourceValidationError,
    create_source,
    disable_source,
    enable_source,
    get_source_by_code,
    get_source_stats,
    list_sources,
    update_source,
)


def main() -> int:
    print(
        "Verification phase 6.3 sources avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        if not check_table_structure():
            return 1

        initial_count = count_persistent_sources()
        connection = engine.connect()
        transaction = connection.begin()
        db = Session(bind=connection, join_transaction_mode="create_savepoint")
        try:
            checks = [
                check_dgssi_initialized(db),
                check_services(db),
                check_routes(db),
            ]
            db.close()
            transaction.rollback()
        finally:
            connection.close()
            app.dependency_overrides.clear()

        if count_persistent_sources() != initial_count:
            print("Rollback final sources: FAILED")
            return 1
        if not all(checks):
            return 1

        print("Rollback final sources: OK")
        print("PHASE 6.3 SOURCES CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR SQLAlchemy: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def check_table_structure() -> bool:
    inspector = inspect(engine)
    if "threat_sources" not in inspector.get_table_names():
        print("Table threat_sources presente: FAILED")
        return False

    columns = {column["name"] for column in inspector.get_columns("threat_sources")}
    expected = {
        "id",
        "name",
        "code",
        "source_type",
        "base_url",
        "description",
        "is_active",
        "sync_enabled",
        "sync_interval_minutes",
        "last_sync_at",
        "last_sync_status",
        "created_at",
        "updated_at",
    }
    if expected - columns:
        print("Colonnes threat_sources: FAILED")
        return False

    unique_constraints = inspector.get_unique_constraints("threat_sources")
    unique_columns = {tuple(item["column_names"]) for item in unique_constraints}
    if ("code",) not in unique_columns:
        print("Unicite code: FAILED")
        return False

    print("Table threat_sources presente: OK")
    print("Unicite code: OK")
    return True


def check_dgssi_initialized(db: Session) -> bool:
    source = get_source_by_code(db, DGSSI_CODE)
    if (
        source is None
        or source.name != "DGSSI / maCERT"
        or source.source_type != ThreatSourceType.WEB
        or source.is_active is not True
        or source.sync_enabled is not True
    ):
        print("DGSSI initialisee: FAILED")
        return False

    print("DGSSI initialisee: OK")
    return True


def check_services(db: Session) -> bool:
    token = uuid4().hex[:8].upper()
    code = f"TST{token}"
    source = create_source(
        db,
        name=f"TEST SOURCE {token}",
        code=code,
        source_type=ThreatSourceType.WEB.value,
        base_url=f"https://example.test/{token.lower()}",
        description="Source temporaire de test.",
        sync_enabled=True,
        sync_interval_minutes="30",
    )

    try:
        create_source(
            db,
            name="Duplicate",
            code=code,
            source_type=ThreatSourceType.WEB.value,
            base_url="https://example.test/duplicate",
            sync_interval_minutes="30",
        )
        duplicate_rejected = False
    except ThreatSourceValidationError:
        duplicate_rejected = True

    updated = update_source(
        db,
        source.id,
        name=f"TEST SOURCE UPDATED {token}",
        code=code,
        source_type=ThreatSourceType.API.value,
        base_url=f"https://api.example.test/{token.lower()}",
        description="Source temporaire mise a jour.",
        sync_enabled=False,
        sync_interval_minutes="45",
    )
    disable_source(db, source.id)
    disabled = source.is_active is False
    enable_source(db, source.id)
    enabled = source.is_active is True
    listed = list_sources(db, search=token)
    filtered = list_sources(
        db,
        source_type=ThreatSourceType.API.value,
        sync_enabled="disabled",
        status="active",
    )
    empty = list_sources(db, search="NO-SOURCE-SHOULD-MATCH-THIS")
    stats = get_source_stats(db)

    if (
        updated is None
        or updated.source_type != ThreatSourceType.API
        or updated.sync_enabled is not False
        or not duplicate_rejected
        or not disabled
        or not enabled
        or listed.total < 1
        or filtered.total < 1
        or empty.total != 0
        or stats.total_sources < 1
    ):
        print("Services sources create/update/listing: FAILED")
        return False

    print("Services sources create/update/listing: OK")
    print("Activation/desactivation service: OK")
    return True


def check_routes(db: Session) -> bool:
    admin = create_test_user(db, RoleUtilisateur.ADMIN)
    analyst = create_test_user(db, RoleUtilisateur.ANALYSTE)
    source = get_source_by_code(db, DGSSI_CODE)

    client = TestClient(app, follow_redirects=False)
    response = client.get("/sources")
    if response.status_code != 303 or "/login" not in response.headers.get("location", ""):
        print("Route /sources hors session: FAILED")
        return False

    if not route_read_returns_200(db, admin, source):
        print("Route /sources ADMIN: FAILED")
        return False
    if not route_read_returns_200(db, analyst, source):
        print("Route /sources ANALYSTE: FAILED")
        return False
    if not route_permissions_are_enforced(db, analyst, source):
        print("Permissions sources ANALYSTE lecture seule: FAILED")
        return False
    if not route_admin_mutations_work(db, admin):
        print("Routes sources ADMIN mutations: FAILED")
        return False

    print("Route /sources hors session: OK")
    print("Route /sources ADMIN: OK")
    print("Route /sources ANALYSTE: OK")
    print("Permissions sources: OK")
    return True


def route_read_returns_200(
    db: Session,
    user: Utilisateur,
    source: ThreatSource,
) -> bool:
    install_overrides(db, user)
    try:
        client = TestClient(app, follow_redirects=False)
        list_response = client.get("/sources?q=DGSSI&source_type=WEB")
        detail_response = client.get(f"/sources/{source.id}")
        body = list_response.text + detail_response.text
        return (
            list_response.status_code == 200
            and detail_response.status_code == 200
            and "DGSSI / maCERT" in body
            and "Synchronisation" in body
        )
    finally:
        app.dependency_overrides.clear()


def route_permissions_are_enforced(
    db: Session,
    analyst: Utilisateur,
    source: ThreatSource,
) -> bool:
    install_overrides(db, analyst)
    try:
        client = TestClient(app, follow_redirects=False)
        responses = [
            client.get("/sources/new"),
            client.get(f"/sources/{source.id}/edit"),
            client.post(f"/sources/{source.id}/disable"),
        ]
        return all(response.status_code == 403 for response in responses)
    finally:
        app.dependency_overrides.clear()


def route_admin_mutations_work(db: Session, admin: Utilisateur) -> bool:
    token = uuid4().hex[:8].upper()
    install_overrides(db, admin)
    try:
        client = TestClient(app, follow_redirects=False)
        create_response = client.post(
            "/sources",
            data={
                "name": f"TEST ROUTE SOURCE {token}",
                "code": f"RT{token}",
                "source_type": "WEB",
                "base_url": f"https://route.example.test/{token.lower()}",
                "description": "Source route test.",
                "sync_enabled": "on",
                "sync_interval_minutes": "20",
            },
        )
        if create_response.status_code != 303:
            return False
        source = get_source_by_code(db, f"RT{token}")
        if source is None:
            return False
        edit_response = client.post(
            f"/sources/{source.id}/edit",
            data={
                "name": f"TEST ROUTE SOURCE UPDATED {token}",
                "code": f"RT{token}",
                "source_type": "RSS",
                "base_url": f"https://route.example.test/rss/{token.lower()}",
                "description": "Source route test update.",
                "sync_interval_minutes": "25",
            },
        )
        disable_response = client.post(f"/sources/{source.id}/disable")
        db.refresh(source)
        disabled = source.is_active is False
        enable_response = client.post(f"/sources/{source.id}/enable")
        db.refresh(source)
        enabled = source.is_active is True
        return (
            edit_response.status_code == 303
            and disable_response.status_code == 303
            and enable_response.status_code == 303
            and disabled
            and enabled
            and source.source_type == ThreatSourceType.RSS
            and source.sync_enabled is False
        )
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
        nom=f"TEST SOURCES {role.value} {token[:6]}",
        email=f"test-sources-{role.value.lower()}-{token}@example.test",
        mot_de_passe_hash="not-used",
        role=role,
        actif=True,
    )
    db.add(user)
    db.flush()
    return user


def count_persistent_sources() -> int:
    with SessionLocal() as db:
        return db.scalar(select(func.count(ThreatSource.id))) or 0


if __name__ == "__main__":
    raise SystemExit(main())
