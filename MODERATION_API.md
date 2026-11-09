# API de modération privée (v2)

Toute nouvelle image est enregistrée avec `status=pending` et reste privée tant qu'une décision n'a pas été prise. Les fichiers non-image restent publiés normalement.

L'analyse NudeNet est désormais intégrée au site (voir `INSTALL_MODERATION.md`). Cette API privée reste disponible pour un outil externe facultatif : elle n'est utilisée par aucun composant du dépôt.

## Configuration du serveur

```text
MODERATION_API_KEY=<clé aléatoire longue>
MODERATION_PENDING_IMAGES=1
```

La même clé doit être configurée sur le serveur PixShare et sur l'outil externe. Ne jamais la publier dans GitHub.

## Authentification

Toutes les routes privées acceptent :

```text
X-Moderation-Key: <clé>
```

`Authorization: Bearer <clé>` reste également accepté.

## Routes

- `GET /api/admin/moderation/health` : vérifie que l'API privée et la clé fonctionnent.
- `GET /api/admin/moderation/images` : liste les images `pending` à analyser.
- `GET /api/admin/moderation/images/<id>/content` : transmet les octets à l'outil externe sans exposition publique.
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

## Politique de décision

Deux seuils sont utilisés (identiques pour NudeNet intégré et pour un outil externe) :

- score < revue : approbation automatique ;
- revue <= score < blocage : revue manuelle, fichier toujours privé ;
- score >= blocage : refus automatique.

Valeurs par défaut : `NSFW_REVIEW_THRESHOLD=0.60`, `NSFW_BLOCK_THRESHOLD=0.85`.

Une détection NudeNet n'est pas une qualification juridique. Les seuils doivent être adaptés aux CGU et aux faux positifs observés.
