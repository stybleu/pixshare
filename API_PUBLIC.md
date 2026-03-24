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
