# Validation finale ThreatWatch

## Etat PFE

Toutes les phases fonctionnelles sont integrees :

- collecte DGSSI ;
- enrichissement CVE/NVD ;
- inventaire des actifs ;
- correlation operationnelle ;
- alertes SOC priorisees ;
- traitements analystes ;
- notifications ;
- sources de veille ;
- utilisateurs et permissions ;
- parametres non sensibles ;
- pipeline SOC controle ;
- dashboard final.

## Regles de securite validees

- Session signee par `SESSION_SECRET_KEY`.
- Cookie `HttpOnly` via `SessionMiddleware`.
- `SameSite=Lax`.
- `Secure` pilotable par `SESSION_HTTPS_ONLY`.
- CSRF centralise sur les formulaires POST avec token en session.
- `.env` ignore par Git et non versionne.
- `.env.example` limite aux placeholders.

## Commandes finales

```powershell
.\.venv\Scripts\python.exe scripts\cleanup_demo_alert.py
.\.venv\Scripts\python.exe scripts\check_server_environment.py
.\.venv\Scripts\python.exe scripts\check_final_e2e.py
.\.venv\Scripts\python.exe scripts\check_project_complete.py
```

## Verdict attendu

```text
THREATWATCH FINAL E2E: OK
THREATWATCH FINAL CHECK: OK
```

## Lancement local

```powershell
.\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8001
```
