# API publique PixShare

Cette version ajoute une API publique simple avec clé API et quota d'uploads.

## Endpoints

### GET /api/v1/health
Vérifie que l'API répond.

### GET /api/v1/me
Retourne les informations de la clé API et les quotas restants.

### POST /api/v1/upload
Headers :
- `X-API-Key: votre_cle`

Form-data :
- `file` : fichier à envoyer
- `lifetime` : durée d'expiration en minutes
- `permanent` : `true` ou `false`

Notes :
- `permanent=true` ne fonctionne que si la clé l'autorise
- la durée doit appartenir à `allowed_lifetimes`

### GET /api/v1/file/<file_id>
Retourne les métadonnées d'un fichier appartenant à la clé API.

### DELETE /api/v1/file/<file_id>
Supprime un fichier appartenant à la clé API.

## Authentification

Deux formats acceptés :

- `X-API-Key: ps_demo_public_v1`
- `Authorization: Bearer ps_demo_public_v1`

## Fichier des clés

Les clés sont stockées dans `pixshare/data/api_keys.json`.

Exemple :

```json
{
  "ps_demo_public_v1": {
    "name": "demo",
    "is_active": true,
    "max_uploads_total": 100,
    "uploads_used": 0,
    "max_uploads_per_day": 10,
    "daily_uploads_used": 0,
    "daily_reset_date": "2026-03-19",
    "max_file_size_mb": 10,
    "allow_permanent": false,
    "default_lifetime_minutes": 10,
    "allowed_lifetimes": [5, 10, 20, 30, 60],
    "notes": "Clé de démonstration à remplacer avant mise en production."
  }
}
```

## Exemples cURL

### Vérifier l'API

```bash
curl https://votre-domaine/api/v1/health
```

### Voir le quota

```bash
curl -H "X-API-Key: ps_demo_public_v1" https://votre-domaine/api/v1/me
```

### Upload

```bash
curl -X POST \
  -H "X-API-Key: ps_demo_public_v1" \
  -F "file=@image.jpg" \
  -F "lifetime=10" \
  https://votre-domaine/api/v1/upload
```

### Infos fichier

```bash
curl -H "X-API-Key: ps_demo_public_v1" https://votre-domaine/api/v1/file/FILE_ID
```

### Suppression

```bash
curl -X DELETE -H "X-API-Key: ps_demo_public_v1" https://votre-domaine/api/v1/file/FILE_ID
```

## Remarques importantes

- Change la clé de démonstration avant de mettre en ligne
- Ne publie pas ton fichier `api_keys.json` dans un dépôt public
- La clé possède une limite totale et une limite par jour
- Le quota n'est consommé qu'après un upload réussi
