"""
Crée (ou met à jour le mot de passe d') un utilisateur initial, pour pouvoir
tester la page de connexion sans passer par un écran d'inscription (qui
n'existe pas encore côté produit : les comptes sont créés par un admin).

Usage :
    python scripts/seed_admin.py
    python scripts/seed_admin.py --email autre@exemple.com --password Abc12345 --role ANALYSTE
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.security import hash_password
from app.db.database import Base, SessionLocal, engine
from app.models.user import RoleUtilisateur, Utilisateur


def main():
    parser = argparse.ArgumentParser(description="Crée un utilisateur de test.")
    parser.add_argument("--nom", default="Admin Principal")
    parser.add_argument("--email", default="admin@veille-securitaire.local")
    parser.add_argument("--password", default="Admin1234!")
    parser.add_argument("--role", default="ADMIN", choices=["ADMIN", "ANALYSTE"])
    args = parser.parse_args()

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        email = args.email.strip().lower()
        user = db.query(Utilisateur).filter(Utilisateur.email == email).first()

        if user is None:
            user = Utilisateur(
                nom=args.nom,
                email=email,
                role=RoleUtilisateur(args.role),
                actif=True,
                mot_de_passe_hash=hash_password(args.password),
            )
            db.add(user)
            action = "créé"
        else:
            user.mot_de_passe_hash = hash_password(args.password)
            user.actif = True
            action = "mis à jour"

        db.commit()
        print(f"Utilisateur {action} avec succès :")
        print(f"  e-mail    : {email}")
        print(f"  mot de passe : {args.password}")
        print(f"  rôle      : {args.role}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
