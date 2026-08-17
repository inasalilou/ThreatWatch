# Phase 2 - Collecte DGSSI

## Objectif

Cette phase ajoute la collecte des bulletins de securite DGSSI dans ThreatWatch.
Elle couvre la recuperation publique, le parsing, la normalisation,
l'insertion PostgreSQL, l'association des CVE et la tracabilite des
synchronisations.

Cette phase ne genere pas encore d'alertes et ne fait aucun enrichissement CVE
externe.

## Collecteur DGSSI

Le collecteur est implemente dans `app/services/dgssi_collector.py`.
Il utilise `httpx` pour contacter la page publique DGSSI configuree par
`DGSSI_SOURCE_URL`, puis `BeautifulSoup` pour extraire les liens de bulletins
et les pages detail.

Le collecteur separe les responsabilites :

- `fetch_html` recupere une page HTML avec timeout et gestion d'erreurs.
- `parse_bulletin_links` extrait les liens de bulletins.
- `parse_bulletin_detail` extrait les champs d'un bulletin.
- `extract_cves` detecte les identifiants CVE.
- `build_canonical_key` construit la cle stable anti-doublon.

## Normalisation

Les pages DGSSI sont converties vers `NormalizedDgssiBulletin`.
Les champs actuellement exploites sont :

- reference DGSSI ;
- titre ;
- date de publication ;
- niveau de risque ;
- niveau d'impact ;
- URL source ;
- bilan de vulnerabilite comme resume/description ;
- contenu brut ;
- liste des CVE detectees.

`bulletin_type` reste `None` car la DGSSI ne fournit pas de type explicite dans
les pages observees.

## Redirections DGSSI

Le site DGSSI peut rediriger une page HTTPS vers une URL HTTP du meme domaine.
Comme certains environnements bloquent le port 80, le collecteur suit les
redirections manuellement et transforme les redirections DGSSI HTTP en HTTPS
lorsque le domaine reste `dgssi.gov.ma`.

## Insertion PostgreSQL

Le service `app/services/synchronization_service.py` orchestre l'import :

1. creation d'une entree `SyncHistory` ;
2. recuperation de la liste DGSSI ;
3. parsing des bulletins selectionnes ;
4. verification des doublons ;
5. insertion des nouveaux `SecurityBulletin` ;
6. insertion des `BulletinCVE` associes ;
7. finalisation de l'historique.

## Detection Des Doublons

La detection applicative utilise :

- `canonical_key` ;
- `source + reference`.

La base PostgreSQL protege egalement contre les doublons avec :

- `UNIQUE(source, reference)` ;
- `UNIQUE(canonical_key)` ;
- `UNIQUE(bulletin_id, cve_id)`.

## CVE

Les CVE sont detectees par expression reguliere, normalisees en majuscules et
dedupliquees avant insertion dans `bulletin_cves`.

Aucune API externe comme NVD n'est appelee dans cette phase.

## SyncHistory

Chaque synchronisation cree une ligne dans `sync_history`.

En fin d'execution :

- `SUCCESS` si tous les bulletins traites ont ete importes ou reconnus ;
- `PARTIAL` si certains bulletins n'ont pas pu etre recuperes/parses ;
- `FAILED` si la synchronisation echoue globalement.

Les compteurs renseignes sont :

- `items_found` : bulletins detectes sur la source ;
- `items_created` : nouveaux bulletins inseres ;
- `items_updated` : toujours `0` dans cette phase.

## Gestion Des Erreurs

Les erreurs reseau, HTTP, parsing et SQLAlchemy sont journalisees sans afficher
de secrets. En cas d'erreur SQL, la transaction est annulee avec rollback et
l'historique est marque `FAILED`.

## Scripts De Test

Tester le collecteur sans insertion :

```powershell
.\.venv\Scripts\python.exe scripts\test_dgssi_connection.py --limit 3 --timeout 20
```

Synchroniser quelques bulletins :

```powershell
.\.venv\Scripts\python.exe scripts\sync_dgssi.py --limit 3
```

Verifier les donnees importees :

```powershell
.\.venv\Scripts\python.exe scripts\check_dgssi_data.py
```

## Interface Des Bulletins

La consultation des bulletins est exposee via deux routes protegees par
`require_authenticated_user` :

- `GET /bulletins` : liste paginee des bulletins ;
- `GET /bulletins/{id}` : detail d'un bulletin.

Le menu `Bulletins de securite` de la sidebar pointe maintenant vers
`/bulletins` et utilise `active_page = "bulletins"` pour reprendre le style
actif existant.

## Recherche, Filtre Et Pagination

La page `/bulletins` lit les donnees PostgreSQL avec
`app/services/bulletin_service.py`.

La recherche est effectuee cote serveur avec SQLAlchemy sur :

- la reference DGSSI ;
- le titre ;
- les identifiants CVE.

Un filtre simple par niveau de risque est propose a partir des valeurs
reellement presentes en base. Les bulletins sont tries par date de publication
decroissante, puis par date d'import et reference. La pagination est limitee a
20 bulletins par page.

## Affichage CVE

Dans la liste, seules les quantites de CVE sont affichees pour eviter un
tableau surcharge. La page detail affiche la liste complete des identifiants
CVE associes au bulletin, sans enrichissement NVD ni score CVSS.

## Protection Et 404

Les routes `/bulletins` et `/bulletins/{id}` sont accessibles uniquement apres
authentification. Un identifiant de bulletin inconnu retourne une page 404
integree au design ThreatWatch.

## Synchronisation Automatique

La synchronisation automatique est configuree par `.env` :

```env
DGSSI_SYNC_ENABLED=false
DGSSI_SYNC_INTERVAL_MINUTES=60
DGSSI_SYNC_ON_STARTUP=false
```

Le scheduler est implemente dans `app/services/scheduler_service.py` avec
APScheduler. Il est branche sur le cycle de vie FastAPI et demarre uniquement
si `DGSSI_SYNC_ENABLED=true`.

Parametres :

- `DGSSI_SYNC_ENABLED` active ou desactive la tache automatique ;
- `DGSSI_SYNC_INTERVAL_MINUTES` definit l'intervalle entre deux executions ;
- `DGSSI_SYNC_ON_STARTUP` lance une execution au demarrage si active.

Le job utilise `max_instances=1` et `coalesce=True`. Le service
`sync_dgssi_bulletins` contient aussi un verrou applicatif afin d'eviter une
execution concurrente entre un lancement manuel et un lancement planifie dans
le meme processus.

Les exceptions du scheduler sont journalisees et ne doivent pas interrompre
FastAPI.

## Interface Des Synchronisations

La consultation de l'historique est exposee via :

- `GET /synchronizations` : accessible a tout utilisateur authentifie ;
- `POST /synchronizations/run` : reserve aux administrateurs.

La page affiche :

- l'etat de l'automatisation ;
- l'intervalle configure ;
- la prochaine execution quand le scheduler est actif ;
- le dernier statut ;
- l'historique `sync_history` avec les compteurs et erreurs.

Le bouton de synchronisation manuelle utilise le meme service backend que le
script CLI et que le scheduler.

## Commandes Phase 2 Complete

Installer les dependances :

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Verifier l'etat PostgreSQL de la phase 2 :

```powershell
.\.venv\Scripts\python.exe scripts\check_phase2_complete.py
```

Demarrer l'application :

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8001
```

Tester rapidement l'automatisation :

1. mettre `DGSSI_SYNC_ENABLED=true` dans `.env` ;
2. mettre `DGSSI_SYNC_INTERVAL_MINUTES=1` ;
3. demarrer FastAPI avec la commande ci-dessus ;
4. attendre une a deux minutes ;
5. relancer `scripts\check_phase2_complete.py`.

Les doublons restent bloques par les contraintes SQLAlchemy/PostgreSQL deja
posees et par la detection applicative `canonical_key` + `source/reference`.
