# PhishGuard

Plateforme distribuée (Python) pour signaler et qualifier des e-mails de phishing — projet de fin de semestre.

## Démarrage rapide

```bash
git clone <repo>
cd PhishGuard
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # définir JWT_SECRET (≥ 32 car.)
python setup_users.py
```

Lancer les 4 services (depuis la racine, `PYTHONPATH=.:proto`) :

```bash
python auth_service/main.py        # :8001
python audit_service/main.py       # :8003
python analysis_service/main.py    # gRPC :50051
python api_gateway/main.py         # :8000
```

Windows : `start_all.bat` · Interface : **http://localhost:8000/app/index.html**

| Compte | Mot de passe | Rôle |
|--------|--------------|------|
| admin@phishguard.com | Admin1234! | admin |
| analyst@phishguard.com | Analyst1234! | analyst |
| user@phishguard.com | User1234! | user |

## Architecture

GitHub affiche le diagramme Mermaid ci-dessous directement dans ce README. Version statique : [`docs/architecture/schema.svg`](docs/architecture/schema.svg).

```mermaid
flowchart TB
    Client["Client Web<br/>client/index.html"]
    GW["API Gateway<br/>FastAPI :8000"]
    Auth["AuthService<br/>JWT · bcrypt :8001"]
    Ana["AnalysisService<br/>gRPC · Protobuf :50051"]
    Aud["AuditService<br/>:8003"]
    DB[("SQLite<br/>data/phishguard.db")]
    Log[("JSONL<br/>audit.jsonl")]

    Client -->|"HTTP/JSON REST"| GW
    GW -->|"verify token"| Auth
    GW -->|"Analyze"| Ana
    GW -->|"log event"| Aud
    GW -->|"reports"| DB
    Auth -->|"users"| DB
    Aud -->|"append"| Log
```

![Schéma d'architecture PhishGuard](docs/architecture/schema.svg)

## Livrables

| Livrable | Emplacement |
|----------|-------------|
| Code source | racine du dépôt |
| README | `README.md` |
| **Schéma d'architecture** | **`docs/architecture/`** — voir [instructions](docs/architecture/README.md) |
| Rapport (4–8 pages) | `docs/rapport.tex` → compiler en `docs/rapport.pdf` |
| Jeu de données démo | [`docs/demo/`](docs/demo/) |
| Tableau des menaces | [`docs/threats.md`](docs/threats.md) |

## Structure

```
auth_service/       JWT + rôles (SQLite)
api_gateway/        REST, orchestration
analysis_service/   scoring heuristique (gRPC)
audit_service/      logs JSONL
client/             interface web
shared/             modèles, config, DB
proto/              contrat gRPC
docs/
  architecture/     ← schéma SVG (+ PDF pour le rapport)
  demo/               ← exemples d'e-mails JSON
  threats.md          ← menaces et protections
  rapport.tex         ← rapport LaTeX
```

## Démo

1. Connexion analyste → soumettre `docs/demo/phishing_credential_harvest.json`
2. Historique + filtres → déconnexion → accès refusé sans token
3. Admin → journal d'audit

Détails : [`docs/demo/README.md`](docs/demo/README.md)
