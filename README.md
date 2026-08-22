# ThreatWatch

Application PFE de veille securitaire et de traitement SOC.

ThreatWatch collecte des bulletins DGSSI, extrait les CVE, enrichit les
vulnerabilites via NVD, correle les CVE avec l'inventaire des actifs, genere
des alertes SOC priorisees, puis permet le suivi analyste jusqu'a la cloture.

## Fonctionnalites validees

- Authentification par session signee, roles `ADMIN` et `ANALYSTE`.
- Collecte DGSSI et historique des synchronisations.
- Catalogue des bulletins et des vulnerabilites CVE.
- Enrichissement NVD controle, avec produits/CPE affectes.
- Inventaire des actifs et correlations `MATCH`, `POSSIBLE_MATCH`, `NO_MATCH`, `UNKNOWN`.
- Alertes SOC issues des correlations `MATCH`, avec anti-doublon.
- Priorite SOC explicable, distincte de la severite CVSS.
- Traitements analystes : prise en charge, commentaire, resolution, cloture.
- Notifications `IN_APP` et preparation `EMAIL` sans envoi obligatoire.
- Sources de veille, utilisateurs, parametres applicatifs non sensibles.
- Pipeline SOC post-synchronisation, sans batch massif.
- Dashboard SOC final.
- Protection CSRF centralisee sur les formulaires POST authentifies.

## Prerequis

- Python 3.12 ou plus recent.
- PostgreSQL local avec une base `threatwatch`.
- Un environnement virtuel `.venv`.

## Installation locale

```powershell
cd C:\Users\hp\Downloads\ThreatWatch
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Renseigner ensuite `.env` avec les valeurs locales. Ne jamais commiter `.env`.

Initialisation minimale :

```powershell
.\.venv\Scripts\python.exe scripts\seed_admin.py
.\.venv\Scripts\python.exe scripts\init_threat_sources.py
.\.venv\Scripts\python.exe scripts\init_app_settings.py
```

## Lancement

```powershell
.\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8001
```

Puis ouvrir :

```text
http://127.0.0.1:8001/login
```

Diagnostic des ports :

```powershell
.\.venv\Scripts\python.exe scripts\check_server_environment.py
```

## Validation finale

```powershell
.\.venv\Scripts\python.exe scripts\cleanup_demo_alert.py
.\.venv\Scripts\python.exe scripts\check_final_e2e.py
.\.venv\Scripts\python.exe scripts\check_project_complete.py
```

Le verdict attendu du check global est :

```text
THREATWATCH FINAL CHECK: OK
```

## Securite

- Les secrets restent dans `.env`.
- `.env.example` ne contient que des placeholders.
- `.gitignore` exclut `.env`, `.venv`, `venv`, `__pycache__` et `*.pyc`.
- Les cookies de session sont signes, `SameSite=Lax`, `HttpOnly` via
  `SessionMiddleware`, et `Secure` pilotable par `SESSION_HTTPS_ONLY`.
- Les formulaires POST utilisent un token CSRF stocke en session.

## Structure

```text
app/
  core/        configuration, securite, CSRF, dependances
  db/          SQLAlchemy engine/session/Base
  models/      modeles persistants
  routers/     routes FastAPI
  services/    logique metier
  templates/   vues Jinja2
  static/      CSS/JS
scripts/       checks, initialisation, diagnostics
docs/          notes de validation
```
