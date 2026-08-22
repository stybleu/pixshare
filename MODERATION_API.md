# API de modération privée (v2)

La modération reste extérieure à PixShare. Toute nouvelle image est enregistrée avec `status=pending` et reste privée tant qu'une décision n'a pas été reçue. Les fichiers non-image restent publiés normalement.

## Configuration du serveur

```text
MODERATION_API_KEY=<clé aléatoire longue>
MODERATION_PENDING_IMAGES=1
```

La même clé doit être configurée sur le serveur PixShare et sur le bot. Ne jamais la publier dans GitHub.

## Authentification

Toutes les routes privées acceptent :

```text
X-Moderation-Key: <clé>
```

`Authorization: Bearer <clé>` reste également accepté.

## Routes

- `GET /api/admin/moderation/health` : vérifie que l'API privée et la clé fonctionnent.
- `GET /api/admin/moderation/images` : liste les images `pending` à analyser.
- `GET /api/admin/moderation/images/<id>/content` : transmet les octets au bot sans exposition publique.
- `POST /api/admin/moderation/images/<id>/decision` : nouvelle route recommandée.
- `POST /api/admin/moderation/images/<id>/approve` : ancienne route conservée.
- `DELETE /api/admin/moderation/images/<id>` : ancienne route conservée.

## Décision unifiée

### Approuver

```json
{
  "decision": "approve",
  "detector": "nudenet-3.4.2",
  "score": 0.12
}
```

### Revue manuelle

```json
{
  "decision": "review",
  "detector": "nudenet-3.4.2",
  "score": 0.72,
  "label": "FEMALE_BREAST_EXPOSED"
}
```

L'image reste privée (`status=pending`) mais est retirée de la file automatique afin d'éviter qu'elle soit retraitée en boucle.

### Refuser

```json
{
  "decision": "reject",
  "reason": "non_respect_cgu",
  "detector": "nudenet-3.4.2",
  "score": 0.96,
  "label": "FEMALE_GENITALIA_EXPOSED"
}
```

## Politique du bot v2

Deux seuils sont utilisés :

- score < `REVIEW_THRESHOLD` : approbation automatique ;
- `REVIEW_THRESHOLD` <= score < `BLOCK_THRESHOLD` : revue manuelle, fichier toujours privé ;
- score >= `BLOCK_THRESHOLD` : refus automatique.

Valeurs par défaut : `REVIEW_THRESHOLD=0.60`, `BLOCK_THRESHOLD=0.85`.

Le bot v2 ajoute également des retries HTTP avec backoff, un contrôle du MIME et de la taille, un endpoint de santé, une empreinte SHA-256 courte dans les logs et l'analyse NudeNet via un fichier temporaire local.

Une détection NudeNet n'est pas une qualification juridique. Les seuils doivent être adaptés aux CGU et aux faux positifs observés.
