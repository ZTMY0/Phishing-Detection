# Jeu de données de démonstration

Exemples d'e-mails au format JSON, prêts à coller dans l'interface PhishGuard (onglet **Nouveau signalement**).

## Format

```json
{
  "declared_sender": "expediteur@domaine.example",
  "subject": "Objet du message",
  "body": "Corps textuel…",
  "urls": ["https://…"],
  "has_attachments": false
}
```

## Fichiers

| Fichier | Scénario | Risque attendu |
|---------|----------|----------------|
| `phishing_credential_harvest.json` | Faux renouvellement Microsoft 365 + raccourcisseur | Élevé |
| `phishing_urgent_account.json` | Usurpation PayPal, homoglyphes, URL en IP | Élevé |
| `phishing_fake_invoice.json` | Fausse facture Facebook Ads + pièce jointe | Élevé |
| `phishing_empty_lure.json` | Corps quasi vide, domaine `.top` suspect | Moyen / Élevé |
| `legitimate_newsletter.json` | Newsletter GitHub légitime | Faible |

## Scénario de soutenance (5 min)

1. Connexion `analyst@phishguard.com` / `Analyst1234!`
2. Soumettre `phishing_credential_harvest.json` → score + justifications
3. Historique → filtrer par risque **Élevé**
4. Déconnexion → requête sans token → **401**
5. Connexion `admin@phishguard.com` → journal d'audit
