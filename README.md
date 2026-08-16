# Plateforme de Veille Sécuritaire — Phase 4 (Interface utilisateur, v1)

Cette première version couvre **uniquement** : connexion, session, layout
(sidebar + navbar), page Dashboard (structure), déconnexion.
Alertes, bulletins, CVE, actifs, traitements et collecte DGSSI arriveront
dans les prochaines phases — le menu les affiche déjà (grisées, badge
« bientôt ») pour montrer l'architecture cible à l'encadrant.

## Arborescence

```
soc-platform/
├── app/
│   ├── main.py                 # Point d'entrée FastAPI (middleware, routers, static)
│   ├── core/
│   │   ├── config.py           # Paramètres (lus depuis .env)
│   │   ├── security.py         # Hash / vérification des mots de passe (bcrypt)
│   │   ├── deps.py             # Dépendances d'auth (get_current_user, protection de route)
│   │   └── templating.py       # Instance Jinja2Templates partagée
│   ├── db/
│   │   └── database.py         # Engine SQLAlchemy, session, Base déclarative
│   ├── models/
│   │   └── user.py             # Modèle Utilisateur (id, nom, email, role, actif, ...)
│   ├── services/
│   │   └── auth_service.py     # Logique métier de l'authentification
│   ├── routers/
│   │   ├── auth.py             # /login (GET/POST), /logout, /
│   │   └── dashboard.py        # /dashboard (protégée)
│   ├── templates/
│   │   ├── layout/base.html    # <head> commun
│   │   ├── layout/app.html     # Sidebar + navbar (héritée par les pages protégées)
│   │   ├── auth/login.html
│   │   └── dashboard/index.html
│   └── static/
│       ├── css/style.css       # Design system (couleurs, typo, composants)
│       └── js/app.js           # Toggle mot de passe, loader, menu utilisateur
├── scripts/
│   └── seed_admin.py           # Crée un utilisateur de test
├── requirements.txt
├── .env.example
└── README.md
```

**Séparation des responsabilités** : les routes (`routers/`) ne font que
recevoir la requête et appeler un service ; la logique métier vit dans
`services/` ; l'accès aux données passe par SQLAlchemy (`models/`, `db/`) ;
la présentation est dans `templates/` + `static/`. Aucune logique n'est
mélangée dans un seul fichier.

## Installation

```bash
cd soc-platform
python3 -m venv venv
source venv/bin/activate        # Windows : venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env            # puis éditez SESSION_SECRET_KEY

### Utiliser PostgreSQL (option recommandé pour la démo finale)

1. Créez la base de données PostgreSQL (exemple local) :

```bash
createdb threatwatch
```

2. Dans `.env`, définissez `DATABASE_URL` :

```
DATABASE_URL=postgresql+psycopg2://<user>:<password>@localhost:5432/threatwatch
```

3. Installez les dépendances et seed l'utilisateur :

```bash
pip install -r requirements.txt
python scripts/seed_admin.py
```

4. Lancez l'application :

```bash
uvicorn app.main:app --reload
```
```

## Créer un utilisateur de test

Il n'y a pas (encore) d'écran d'inscription : les comptes sont créés par un
administrateur. Le script suivant crée un admin par défaut :

```bash
python scripts/seed_admin.py
# e-mail    : admin@veille-securitaire.local
# mot de passe : Admin1234!
```

Vous pouvez créer d'autres comptes :
```bash
python scripts/seed_admin.py --nom "Sara Analyste" --email sara@exemple.com --password Test1234! --role ANALYSTE
```

## Lancer l'application

```bash
uvicorn app.main:app --reload
```

Puis ouvrir http://127.0.0.1:8000/login

## Tester le scénario complet

1. Aller sur `/` → redirigé vers `/login` (non authentifié).
2. Se connecter avec de mauvais identifiants → message d'erreur générique.
3. Se connecter avec `admin@veille-securitaire.local` / `Admin1234!` → redirection vers `/dashboard`.
4. Le Dashboard affiche 4 cartes à 0 et « Aucune alerte disponible pour le moment » (aucune donnée inventée).
5. Cliquer sur l'avatar en haut à droite → menu → **Déconnexion**.
6. Tenter de retourner sur `/dashboard` → redirigé vers `/login`.
7. (Optionnel) Désactiver un utilisateur en base (`actif = False`) → la connexion est refusée avec un message dédié.

## Prochaines phases (déjà préparées dans l'architecture)

Le dossier `models/`, la logique DGSSI déjà livrée (connecteur, normalisation,
matching d'actifs, score de risque) et cette couche web sont conçus pour
être assemblés sans réécriture : Alertes, Bulletins, CVE, Actifs et
Traitements viendront comme nouveaux `routers/` + `templates/`, en
réutilisant `require_authenticated_user` pour la protection des pages.
