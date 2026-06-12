# Tableau des menaces et protections

| Menace | Description | Composant | Protection |
|--------|-------------|-----------|------------|
| Usurpation d'identité | Token JWT volé ou forgé | Gateway, endpoints protégés | Vérification JWT via AuthService à chaque requête ; expiration 60 min |
| Falsification des données | Payload modifié ou champs injectés | Gateway → Analysis | Validation Pydantic ; body ≤ 10 000 car. ; max 50 URLs ; gRPC ≤ 1 Mo |
| Répudiation | Nier un login ou une soumission | AuditService | Événements `login_success`, `login_failed`, `register_success`, `report_submitted` en JSONL avec horodatage, user_id, IP |
| Divulgation d'informations | Stack traces ou secrets dans les réponses | Tous | Messages d'erreur génériques côté client ; détails dans les logs structlog serveur |
| Déni de service | Flood de requêtes | Gateway | Rate limit 30 req/min/IP ; plafonds taille payload |
| Élévation de privilèges | Accès admin sans rôle | Gateway `/api/admin/*` | Contrôle rôle à chaque appel ; analyste ≠ admin |
| Injection | Contenu malveillant dans body/URLs | Analysis, SQLite | Pydantic en entrée ; requêtes SQL paramétrées ; pas d'`eval` |
| Rejeu de token | Réutilisation d'un token intercepté | Auth | Claim `exp` ; refresh token séparé (type `refresh`) |
| Désérialisation unsafe | Objet Python malveillant | Analysis (gRPC) | Protobuf uniquement — pas de pickle ni YAML unsafe |
| Surface RPC excessive | Méthodes RPC non voulues | Analysis | Un seul RPC `Analyze` |
| Fuite de credentials | Secrets dans le dépôt | Git | bcrypt ; `.env` ignoré ; `.env.example` sans secrets |
| Brute force login | Deviner un mot de passe | Auth / Gateway | Rate limit ; message « Identifiants invalides » |
