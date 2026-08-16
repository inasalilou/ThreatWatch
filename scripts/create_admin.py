"""
Cree le premier administrateur ThreatWatch.

Le mot de passe est saisi sans affichage et stocke uniquement sous forme de
hash bcrypt. Si l'e-mail existe deja, aucun doublon n'est cree.
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.security import hash_password
from app.db.database import SessionLocal, create_database_tables
from app.models.user import RoleUtilisateur, Utilisateur


def ask_password() -> str:
    password = getpass.getpass("Mot de passe administrateur: ")
    confirmation = getpass.getpass("Confirmer le mot de passe: ")
    if password != confirmation:
        raise ValueError("Les deux mots de passe ne correspondent pas.")
    if not password:
        raise ValueError("Le mot de passe ne peut pas etre vide.")
    return password


def main() -> int:
    parser = argparse.ArgumentParser(description="Cree le premier administrateur ThreatWatch.")
    parser.add_argument("--nom", help="Nom affiche dans ThreatWatch")
    parser.add_argument("--email", help="Adresse e-mail de connexion")
    parser.add_argument(
        "--password",
        help="Mot de passe en clair. Si absent, il sera demande sans affichage.",
    )
    args = parser.parse_args()

    nom = (args.nom or input("Nom: ")).strip()
    email = (args.email or input("E-mail: ")).strip().lower()
    password = args.password or ask_password()

    if not nom:
        print("ERREUR: le nom est obligatoire.")
        return 1
    if not email:
        print("ERREUR: l'e-mail est obligatoire.")
        return 1

    try:
        create_database_tables()
        db = SessionLocal()
        try:
            existing_user = (
                db.query(Utilisateur)
                .filter(Utilisateur.email == email)
                .first()
            )

            if existing_user is not None:
                print(f"Aucun utilisateur cree: l'adresse {email} existe deja.")
                return 0

            admin = Utilisateur(
                nom=nom,
                email=email,
                role=RoleUtilisateur.ADMIN,
                actif=True,
                mot_de_passe_hash=hash_password(password),
            )
            db.add(admin)
            db.commit()
        finally:
            db.close()
    except Exception as exc:
        print("ERREUR: impossible de creer l'administrateur.")
        print(f"Detail technique: {exc.__class__.__name__}")
        return 1

    print("Administrateur ThreatWatch cree avec succes.")
    print(f"  nom   : {nom}")
    print(f"  e-mail: {email}")
    print("  role  : ADMIN")
    print("  actif : true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
