# API de modération privée

Les nouvelles images sont enregistrées avec le statut `pending`. Elles ne sont pas disponibles via les routes publiques tant que le bot ne les a pas approuvées. Les fichiers non-image restent publiés normalement.

## Configuration

Dans Render, ajoute :

```text
MODERATION_API_KEY=<clé aléatoire longue>
MODERATION_PENDING_IMAGES=1
```

La clé doit être identique dans le site et dans le bot. Ne la publie jamais sur GitHub.

## Authentification

Toutes les routes utilisent :

```text
X-Moderation-Key: <clé>
```

## Routes du bot

- `GET /api/admin/moderation/images` : liste uniquement les images `pending`.
- `GET /api/admin/moderation/images/<id>/content` : transmet les octets de l'image au bot, sans route publique.
- `POST /api/admin/moderation/images/<id>/approve` : rend l'image publique.
- `DELETE /api/admin/moderation/images/<id>` : supprime l'image.

### Approbation

```json
{
  "detector": "nudenet-3.4.2",
  "score": 0.12
}
```

### Suppression

```json
{
  "reason": "contenu_illicite",
  "detector": "nudenet-3.4.2",
  "score": 0.98
}
```

Une détection de nudité n'est pas une qualification juridique. Les seuils automatiques doivent rester prudents et être adaptés à tes CGU.
