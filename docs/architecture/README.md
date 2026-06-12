# Schéma d'architecture

## Affichage GitHub

Le diagramme est intégré dans le [**README principal**](../../README.md) :

- bloc **Mermaid** (rendu automatique sur GitHub)
- image **SVG** : `schema.svg` (même dossier)

## Fichiers

| Fichier | Usage |
|---------|--------|
| `schema.svg` | Source + affichage GitHub / édition (Inkscape, draw.io) |
| `schema.pdf` | Version pour le rapport LaTeX (export depuis SVG) |
| `schema.png` | Optionnel — slides ou captures |

Export PDF pour `docs/rapport.tex` :

```bash
inkscape docs/architecture/schema.svg --export-filename=docs/architecture/schema.pdf
```

## Contenu du schéma

- **Client** (navigateur → `client/index.html`)
- **API Gateway** (:8000) — point d'entrée REST
- **AuthService** (:8001) — JWT, bcrypt, rôles
- **AnalysisService** (:50051) — gRPC / Protobuf
- **AuditService** (:8003) — logs JSONL
- **Stockage** : SQLite (`data/phishguard.db`) + `audit_service/data/audit.jsonl`
- Flèches avec protocoles : HTTP/JSON, gRPC
