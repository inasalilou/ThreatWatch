"""
Service de gestion des utilisateurs.

Centralise la validation metier du module d'administration des comptes sans
dupliquer les mecanismes d'authentification ni de hash.
"""
from __future__ import annotations

from dataclasses import dataclass
from math import ceil
from re import compile as compile_regex

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.user import RoleUtilisateur, Utilisateur

EMAIL_RE = compile_regex(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DEFAULT_PER_PAGE = 20


class UserValidationError(ValueError):
    """Erreur metier affichable dans l'interface d'administration."""


@dataclass(frozen=True)
class UserListResult:
    items: list[Utilisateur]
    total: int
    page: int
    per_page: int
    total_pages: int
    search: str
    role: str
    status: str

    @property
    def has_previous(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages


@dataclass(frozen=True)
class UserStats:
    total_users: int
    admin_users: int
    analyst_users: int
    inactive_users: int


def list_users(
    db: Session,
    *,
    search: str = "",
    role: str = "",
    status: str = "",
    page: int = 1,
    per_page: int = DEFAULT_PER_PAGE,
) -> UserListResult:
    filters = build_user_filters(search=search, role=role, status=status)
    page = max(page, 1)
    per_page = max(per_page, 1)

    total = db.scalar(select(func.count(Utilisateur.id)).where(*filters)) or 0
    total_pages = max(ceil(total / per_page), 1)
    page = min(page, total_pages)

    items = list(
        db.scalars(
            select(Utilisateur)
            .where(*filters)
            .order_by(Utilisateur.date_creation.desc(), Utilisateur.nom.asc())
            .offset((page - 1) * per_page)
            .limit(per_page)
        )
    )

    return UserListResult(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        search=search.strip(),
        role=normalise_role_filter(role),
        status=normalise_status_filter(status),
    )


def get_user_by_id(db: Session, user_id: str) -> Utilisateur | None:
    return db.get(Utilisateur, user_id)


def get_user_by_email(db: Session, email: str) -> Utilisateur | None:
    return db.scalar(
        select(Utilisateur).where(Utilisateur.email == normalise_email(email))
    )


def create_user(
    db: Session,
    *,
    nom: str,
    email: str,
    role: str,
    password: str,
    password_confirmation: str,
    actif: bool = True,
) -> Utilisateur:
    nom_clean = validate_nom(nom)
    email_clean = validate_email(email)
    role_value = validate_role(role)
    validate_password_pair(password, password_confirmation)

    if get_user_by_email(db, email_clean) is not None:
        raise UserValidationError("Cette adresse e-mail est deja utilisee.")

    user = Utilisateur(
        nom=nom_clean,
        email=email_clean,
        role=role_value,
        actif=bool(actif),
        mot_de_passe_hash=hash_password(password),
    )
    db.add(user)
    db.flush()
    return user


def update_user(
    db: Session,
    *,
    user_id: str,
    nom: str,
    email: str,
    role: str,
) -> Utilisateur | None:
    user = get_user_by_id(db, user_id)
    if user is None:
        return None

    nom_clean = validate_nom(nom)
    email_clean = validate_email(email)
    role_value = validate_role(role)

    existing = get_user_by_email(db, email_clean)
    if existing is not None and existing.id != user.id:
        raise UserValidationError("Cette adresse e-mail est deja utilisee.")

    if user.role == RoleUtilisateur.ADMIN and role_value != RoleUtilisateur.ADMIN:
        ensure_not_last_active_admin(db, user)

    user.nom = nom_clean
    user.email = email_clean
    user.role = role_value
    db.add(user)
    db.flush()
    return user


def enable_user(db: Session, user_id: str) -> Utilisateur | None:
    user = get_user_by_id(db, user_id)
    if user is None:
        return None
    user.actif = True
    db.add(user)
    db.flush()
    return user


def disable_user(db: Session, user_id: str) -> Utilisateur | None:
    user = get_user_by_id(db, user_id)
    if user is None:
        return None
    if user.role == RoleUtilisateur.ADMIN:
        ensure_not_last_active_admin(db, user)
    user.actif = False
    db.add(user)
    db.flush()
    return user


def change_password(
    db: Session,
    *,
    user_id: str,
    password: str,
    password_confirmation: str,
) -> Utilisateur | None:
    user = get_user_by_id(db, user_id)
    if user is None:
        return None
    validate_password_pair(password, password_confirmation)
    user.mot_de_passe_hash = hash_password(password)
    db.add(user)
    db.flush()
    return user


def get_user_stats(db: Session) -> UserStats:
    total_users = db.scalar(select(func.count(Utilisateur.id))) or 0
    admin_users = (
        db.scalar(
            select(func.count(Utilisateur.id)).where(
                Utilisateur.role == RoleUtilisateur.ADMIN
            )
        )
        or 0
    )
    analyst_users = (
        db.scalar(
            select(func.count(Utilisateur.id)).where(
                Utilisateur.role == RoleUtilisateur.ANALYSTE
            )
        )
        or 0
    )
    inactive_users = (
        db.scalar(
            select(func.count(Utilisateur.id)).where(Utilisateur.actif.is_(False))
        )
        or 0
    )
    return UserStats(
        total_users=total_users,
        admin_users=admin_users,
        analyst_users=analyst_users,
        inactive_users=inactive_users,
    )


def get_role_options() -> list[tuple[str, str]]:
    return [
        (RoleUtilisateur.ADMIN.value, "Administrateur"),
        (RoleUtilisateur.ANALYSTE.value, "Analyste"),
    ]


def get_status_options() -> list[tuple[str, str]]:
    return [("active", "Actif"), ("inactive", "Inactif")]


def role_label(role: RoleUtilisateur | str) -> str:
    value = role.value if isinstance(role, RoleUtilisateur) else str(role)
    if value == RoleUtilisateur.ADMIN.value:
        return "Administrateur"
    if value == RoleUtilisateur.ANALYSTE.value:
        return "Analyste"
    return value


def user_status_label(is_active: bool) -> str:
    return "Actif" if is_active else "Inactif"


def user_status_tone(is_active: bool) -> str:
    return "tone-success" if is_active else "tone-neutral"


def validate_nom(nom: str) -> str:
    value = nom.strip()
    if not value:
        raise UserValidationError("Le nom est obligatoire.")
    if len(value) > 150:
        raise UserValidationError("Le nom ne doit pas depasser 150 caracteres.")
    return value


def validate_email(email: str) -> str:
    value = normalise_email(email)
    if not value:
        raise UserValidationError("L'adresse e-mail est obligatoire.")
    if len(value) > 255:
        raise UserValidationError("L'adresse e-mail ne doit pas depasser 255 caracteres.")
    if not EMAIL_RE.match(value):
        raise UserValidationError("L'adresse e-mail est invalide.")
    return value


def validate_role(role: str) -> RoleUtilisateur:
    try:
        return RoleUtilisateur(role)
    except ValueError as exc:
        raise UserValidationError("Le role selectionne est invalide.") from exc


def validate_password_pair(password: str, password_confirmation: str) -> None:
    if password != password_confirmation:
        raise UserValidationError("Les deux mots de passe ne correspondent pas.")
    validate_password(password)


def validate_password(password: str) -> None:
    if len(password) < 8:
        raise UserValidationError("Le mot de passe doit contenir au moins 8 caracteres.")
    if len(password.encode("utf-8")) > 72:
        raise UserValidationError("Le mot de passe est trop long (72 octets maximum).")
    if password.lower() == password or password.upper() == password:
        raise UserValidationError(
            "Le mot de passe doit contenir des minuscules et des majuscules."
        )
    if not any(char.isdigit() for char in password):
        raise UserValidationError("Le mot de passe doit contenir au moins un chiffre.")


def ensure_not_last_active_admin(db: Session, user: Utilisateur) -> None:
    active_admins = (
        db.scalar(
            select(func.count(Utilisateur.id)).where(
                Utilisateur.role == RoleUtilisateur.ADMIN,
                Utilisateur.actif.is_(True),
            )
        )
        or 0
    )
    if user.actif and active_admins <= 1:
        raise UserValidationError(
            "Impossible de desactiver ou retrograder le dernier administrateur actif."
        )


def build_user_filters(*, search: str, role: str, status: str):
    filters = []
    search_clean = search.strip()
    if search_clean:
        pattern = f"%{search_clean}%"
        filters.append(or_(Utilisateur.nom.ilike(pattern), Utilisateur.email.ilike(pattern)))

    role_clean = normalise_role_filter(role)
    if role_clean:
        filters.append(Utilisateur.role == RoleUtilisateur(role_clean))

    status_clean = normalise_status_filter(status)
    if status_clean == "active":
        filters.append(Utilisateur.actif.is_(True))
    elif status_clean == "inactive":
        filters.append(Utilisateur.actif.is_(False))

    return filters


def normalise_email(email: str) -> str:
    return email.strip().lower()


def normalise_role_filter(role: str) -> str:
    return role if role in {item.value for item in RoleUtilisateur} else ""


def normalise_status_filter(status: str) -> str:
    return status if status in {"active", "inactive"} else ""
