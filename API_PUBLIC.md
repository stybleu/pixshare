# PixShare API — Documentation Pro

API d’upload et de gestion de fichiers pour applications web, mobiles, scripts, bots et automatisations.

---

## Présentation

PixShare API permet de :

- envoyer un fichier par requête HTTP
- récupérer ses métadonnées
- obtenir un lien direct et un lien de suppression
- consulter les quotas associés à une clé API
- supprimer un fichier via l’API

L’API est conçue pour une intégration simple, avec authentification par clé API et réponses JSON structurées.

---

## URL de base

Remplacez `https://votre-domaine` par votre domaine de production.

```text
https://votre-domaine
```

---

## Authentification

Deux méthodes sont acceptées.

### Méthode recommandée

```http
Authorization: Bearer VOTRE_CLE_API
```

### Méthode alternative

```http
X-API-Key: VOTRE_CLE_API
```

### Exemple cURL

```bash
curl -H "Authorization: Bearer VOTRE_CLE_API" https://votre-domaine/api/account
```

---

## Format général des réponses

### Réponse de succès

```json
{
  "success": true,
  "status": 200,
  "data": {}
}
```

### Réponse d’erreur

```json
{
  "success": false,
  "status": 401,
  "error": {
    "code": "invalid_api_key",
    "message": "Clé API invalide"
  }
}
```

---

## Endpoints

## 1) Vérifier son compte API

```http
GET /api/account
```

Retourne les informations de la clé API, les quotas disponibles et la configuration d’upload associée.

### Exemple cURL

```bash
curl -X GET https://votre-domaine/api/account -H "Authorization: Bearer VOTRE_CLE_API"
```

### Exemple de réponse

```json
{
  "success": true,
  "status": 200,
  "data": {
    "key": {
      "name": "api-client",
      "is_active": true
    },
    "quota": {
      "total": {
        "used": 0,
        "max": 100,
        "remaining": 100
      },
      "daily": {
        "used": 0,
        "max": 10,
        "remaining": 10
      }
    },
    "limits": {
      "max_file_size_mb": 10,
      "allow_permanent": false
    },
    "upload_config": {
      "default_lifetime_minutes": 10,
      "allowed_lifetimes": [5, 10, 20, 30, 60],
      "resize": {
        "enabled": true,
        "mode": "ratio_only",
        "ratio": {
          "min": 0.1,
          "max": 3.0
        },
        "max_dimension": 6000
      }
    }
  }
}
```

---

## 2) Upload d’un fichier

```http
POST /api/upload
```

Permet d’envoyer un fichier à PixShare.

### Paramètres `form-data`

- `file` : fichier à envoyer
- `expiration` : durée d’expiration en minutes

### Remarques

- le champ attendu est `expiration`
- la valeur doit appartenir aux durées autorisées par la clé API
- la taille maximale du fichier dépend de la configuration de la clé API

### Exemple cURL

```bash
curl -X POST https://votre-domaine/api/upload -H "Authorization: Bearer VOTRE_CLE_API" -F "file=@image.jpg" -F "expiration=10"
```

### Exemple cURL Android / Termux

```bash
curl -X POST https://votre-domaine/api/upload -H "Authorization: Bearer VOTRE_CLE_API" -F "file=@/storage/emulated/0/Download/image.jpg" -F "expiration=10"
```

### Exemple de réponse

```json
{
  "success": true,
  "status": 200,
  "data": {
    "id": "abc123",
    "title": "image.jpg",
    "filename": "x8fK2mPq9a.jpg",
    "original_filename": "image.jpg",
    "url_viewer": "https://votre-domaine/file/abc123",
    "url": "https://votre-domaine/api/raw/x8fK2mPq9a.jpg",
    "display_url": "https://votre-domaine/api/raw/x8fK2mPq9a.jpg",
    "delete_url": "https://votre-domaine/api/delete/token",
    "mime": "image/jpeg",
    "extension": "jpg",
    "size": 123456,
    "uploaded_at": "2026-03-20T10:00:00Z",
    "expiration": "2026-03-20T10:10:00Z",
    "is_permanent": false,
    "uploader_api_key_name": "demo",
    "width": 1920,
    "height": 1080,
    "resize": {
      "enabled": true,
      "mode": "ratio_only",
      "ratio": {
        "min": 0.1,
        "max": 3.0,
        "max_for_this_image": 2.5
      },
      "max_dimension": 6000
    },
    "limits": {
      "remaining_total": 99,
      "remaining_today": 9,
      "used_total": 1,
      "used_today": 1,
      "max_total": 100,
      "max_per_day": 10
    }
  }
}
```

---

## 3) Lire un fichier

```http
GET /api/file/<id>
```

Retourne les métadonnées d’un fichier associé à la clé API.

### Exemple cURL

```bash
curl -X GET https://votre-domaine/api/file/ID -H "Authorization: Bearer VOTRE_CLE_API"
```

### Exemple de réponse

```json
{
  "success": true,
  "status": 200,
  "data": {
    "id": "abc123",
    "title": "image.jpg",
    "filename": "x8fK2mPq9a.jpg",
    "original_filename": "image.jpg",
    "url_viewer": "https://votre-domaine/file/abc123",
    "url": "https://votre-domaine/api/raw/x8fK2mPq9a.jpg",
    "display_url": "https://votre-domaine/api/raw/x8fK2mPq9a.jpg",
    "delete_url": "https://votre-domaine/api/delete/token",
    "mime": "image/jpeg",
    "extension": "jpg",
    "size": 123456,
    "uploaded_at": "2026-03-20T10:00:00Z",
    "expiration": "2026-03-20T10:10:00Z",
    "is_permanent": false,
    "uploader_api_key_name": "demo",
    "width": 1920,
    "height": 1080,
    "resize": {
      "enabled": true,
      "mode": "ratio_only",
      "ratio": {
        "min": 0.1,
        "max": 3.0,
        "max_for_this_image": 2.5
      },
      "max_dimension": 6000
    }
  }
}
```

---

## 4) Supprimer un fichier par clé API

```http
DELETE /api/file/<id>
```

Supprime un fichier associé à la même clé API que celle utilisée lors de l’upload.

### Exemple cURL

```bash
curl -X DELETE https://votre-domaine/api/file/ID -H "Authorization: Bearer VOTRE_CLE_API"
```

### Exemple de réponse

```json
{
  "success": true,
  "status": 200,
  "data": {
    "id": "abc123",
    "deleted": true
  }
}
```

---

## 5) Suppression par lien public

```http
GET /api/delete/<token>
```

ou

```http
DELETE /api/delete/<token>
```

selon l’implémentation active du service.

### Remarque

Le lien de suppression publique est disponible uniquement si un `delete_token` est associé au fichier.

### Exemple de réponse

```json
{
  "success": true,
  "status": 200,
  "data": {
    "id": "abc123",
    "deleted": true
  }
}
```

---

## Redimensionnement d’image

Lorsque le fichier est une image, une version redimensionnée peut être obtenue via le paramètre `ratio` sur l’URL brute.

### Exemple

```http
GET /api/raw/filename.png?ratio=0.5
```

### Règles

- disponible uniquement pour les images
- le mode actuel est `ratio_only`
- le ratio doit rester dans les limites autorisées
- la dimension maximale finale dépend de `max_dimension`

---

## Codes d’erreur

| HTTP | Code | Description |
|------|------|-------------|
| 400 | `bad_request` | Requête invalide ou incomplète |
| 401 | `invalid_api_key` | Clé API absente ou invalide |
| 403 | `forbidden` | Accès refusé |
| 404 | `not_found` | Ressource introuvable |
| 413 | `file_too_large` | Fichier trop volumineux |
| 415 | `unsupported_file_type` | Type de fichier non supporté |
| 429 | `limit_reached` | Limite d’utilisation atteinte |
| 500 | `server_error` | Erreur interne du serveur |

---

## Signification des principaux champs

| Champ | Type | Description |
|------|------|-------------|
| `success` | bool | Indique si la requête a réussi |
| `status` | int | Code HTTP renvoyé par l’API |
| `data.id` | string | Identifiant unique du fichier |
| `data.title` | string | Nom affichable du fichier |
| `data.filename` | string | Nom réellement stocké |
| `data.original_filename` | string | Nom d’origine envoyé par le client |
| `data.url` | string | URL brute du fichier |
| `data.display_url` | string | URL affichable du fichier |
| `data.url_viewer` | string | Page de visualisation du fichier |
| `data.delete_url` | string | URL publique de suppression |
| `data.mime` | string | Type MIME du fichier |
| `data.extension` | string | Extension du fichier |
| `data.size` | int | Taille en octets |
| `data.uploaded_at` | string | Date d’envoi au format ISO 8601 UTC |
| `data.expiration` | string/null | Date d’expiration ou `null` |
| `data.is_permanent` | bool | Indique si le fichier est permanent |
| `data.width` | int/null | Largeur de l’image en pixels |
| `data.height` | int/null | Hauteur de l’image en pixels |
| `data.resize` | object/null | Informations de redimensionnement |

---

## Limites et quotas

Chaque clé API peut définir :

- une limite totale d’uploads
- une limite quotidienne
- une taille maximale par fichier
- une liste de durées d’expiration autorisées
- l’autorisation ou non du mode permanent

Le quota est consommé uniquement après un upload réussi.

---

## Envoi simplifié (façon imgbb)

Un seul appel, une seule réponse. Pratique pour les scripts et les outils déjà écrits pour imgbb : il suffit de changer l'adresse.

```text
POST /api/1/upload
```

### Paramètres

Envoyés en `multipart/form-data`, `application/x-www-form-urlencoded` ou JSON.

| Paramètre | Obligatoire | Description |
|-----------|-------------|-------------|
| `key` | oui | Clé API. Acceptée dans l'URL (`?key=`) ou dans le corps ; les en-têtes `Authorization: Bearer` et `X-API-Key` marchent aussi et sont préférables (une URL peut finir dans des journaux). |
| `image` | oui | Un fichier, du base64 (avec ou sans `data:image/png;base64,`) ou un lien `http(s)` vers une image. Répétable : jusqu'à 10 par requête, dont 3 liens au maximum. |
| `name` | non | Nom du fichier (envoi d'un seul fichier). |
| `expiration` | non | Durée de vie en **secondes**, entre 60 et 15552000. Elle est ramenée dans les bornes autorisées par la clé ; `0` = permanent si la clé le permet. |

### Exemples cURL

```bash
# Un fichier
curl -X POST "https://votre-domaine/api/1/upload?key=VOTRE_CLE_API" \
  -F image=@photo.jpg -F expiration=3600

# Un lien
curl -X POST "https://votre-domaine/api/1/upload" \
  -H "Authorization: Bearer VOTRE_CLE_API" \
  -d image=https://exemple.org/chat.png

# Du base64
curl -X POST "https://votre-domaine/api/1/upload" \
  -H "Authorization: Bearer VOTRE_CLE_API" \
  --data-urlencode "image=$(base64 -w0 photo.jpg)"
```

### Exemple de réponse

```json
{
  "success": true,
  "status": 200,
  "data": {
    "id": "aB3dE5fG",
    "title": "photo",
    "url_viewer": "https://votre-domaine/file/aB3dE5fG",
    "url": "https://votre-domaine/api/raw/x9y8z7.jpg",
    "display_url": "https://votre-domaine/api/raw/x9y8z7.jpg",
    "width": 1920,
    "height": 1080,
    "size": 245760,
    "time": "1767225600",
    "expiration": "3600",
    "image": {
      "filename": "x9y8z7.jpg",
      "name": "photo",
      "mime": "image/jpeg",
      "extension": "jpg",
      "url": "https://votre-domaine/api/raw/x9y8z7.jpg"
    },
    "delete_url": "https://votre-domaine/api/delete/TOKEN",
    "expires_at": "2026-01-01T01:00:00Z",
    "status": "pending",
    "moderation_status": "pending",
    "limits": { "remaining_total": 99, "remaining_today": 9 }
  }
}
```

Une image reste `pending` tant que la modération automatique n'a pas rendu sa décision (quelques secondes) : son lien `url` répond 404 jusqu'à l'approbation. Interroge `GET /api/file/{id}` pour suivre `moderation_status`.

### Plusieurs fichiers

Avec plusieurs `image`, la réponse contient `count`, `files` (même format que ci-dessus), `errors` (un élément par fichier refusé, avec son `index`, son `code` et son `message`) et `limits`. Chaque fichier accepté consomme un envoi du quota. Si aucun fichier n'est accepté, la réponse est une erreur `upload_failed` avec le détail.

### Règles

- Le contenu des images est vérifié : un fichier `.png` qui n'est pas une image est refusé (`invalid_image`).
- Le base64 et les liens ne servent qu'aux images. Les vidéos autorisées (`mp4`, `webm`, `avi`, `mov`) s'envoient comme fichier.
- Un envoi en base64 reste limité par la taille maximale de la clé ; pour les gros fichiers, préfère le fichier.
- Les liens vers des adresses locales ou privées sont refusés.

---

## Liste des fichiers

```text
GET /api/files
```

Retourne les fichiers non expirés de la clé, du plus récent au plus ancien. Clé par en-tête uniquement.

| Paramètre | Description |
|-----------|-------------|
| `page` | Numéro de page (1 par défaut) |
| `per_page` | Fichiers par page (20 par défaut, 100 maximum) |
| `status` | `all` (défaut), `active` ou `pending` |
| `q` | Filtre sur le nom du fichier |

```bash
curl -H "Authorization: Bearer VOTRE_CLE_API" "https://votre-domaine/api/files?per_page=10&status=active"
```

```json
{
  "success": true,
  "status": 200,
  "data": {
    "files": [ { "id": "aB3dE5fG", "title": "photo.jpg", "status": "active" } ],
    "pagination": { "page": 1, "per_page": 10, "total": 1, "total_pages": 1, "has_next": false }
  }
}
```

---

## Limite de débit

Chaque clé est limitée à **60 requêtes par minute** (fenêtre glissante), toutes routes authentifiées confondues. L'hébergeur peut changer cette valeur avec la variable `API_RATE_LIMIT_PER_MINUTE` (`0` = illimité) ; une clé peut aussi avoir sa propre valeur `rate_limit_per_minute` dans `api_keys.json`.

Les réponses portent `X-RateLimit-Limit`, `X-RateLimit-Remaining` et `X-RateLimit-Reset` (secondes). Au-delà de la limite, l'API répond `429` avec le code `rate_limit_exceeded` et l'en-tête `Retry-After` (secondes à attendre).

Les essais répétés avec une clé invalide sont aussi freinés par adresse IP (30 par minute) : code `too_many_invalid_keys`.

Les compteurs sont propres à chaque processus du serveur et repartent de zéro au redémarrage. Ils s'ajoutent aux quotas d'envoi, qui ne changent pas.

### Codes d'erreur ajoutés

| HTTP | Code | Description |
|------|------|-------------|
| 400 | `missing_image` | Aucune image reçue |
| 400 | `invalid_image` | Fichier illisible, base64 invalide ou contenu qui n'est pas une image |
| 400 | `invalid_expiration` | `expiration` hors de 60 à 15552000 secondes |
| 400 | `url_import_failed` | Lien impossible à télécharger ou refusé |
| 400 | `too_many_files` / `too_many_urls` | Plus de 10 fichiers ou plus de 3 liens par requête |
| 400 | `invalid_status` | Valeur de `status` inconnue (liste des fichiers) |
| 429 | `rate_limit_exceeded` | Trop de requêtes par minute |
| 429 | `too_many_invalid_keys` | Trop d'essais avec une clé invalide |

---

## Public visé

PixShare API est conçue pour :

- développeurs web
- applications mobiles
- scripts et automatisations
- bots
- outils internes
- intégrations légères nécessitant un service simple d’upload et de gestion de fichiers

---

## Bonnes pratiques

- utilisez `Authorization: Bearer` de préférence
- vérifiez les quotas avec `/api/account`
- contrôlez le type MIME reçu côté client si votre application affiche les fichiers
- gérez les réponses d’erreur de manière explicite
- évitez de supposer qu’un fichier est une image uniquement sur son extension

---

## Contact / intégration

Pour une utilisation avancée ou en production, une clé API standard peut être demandée depuis la page API du service.
