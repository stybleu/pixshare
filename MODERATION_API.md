# API de modération externe

Cette API permet à un bot local de lister les images actives et d'en supprimer une après analyse.

## Configuration Render

Ajoute une variable d'environnement :

```text
MODERATION_API_KEY=<clé aléatoire longue>
```

Génération conseillée :

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Ne stocke jamais cette clé dans GitHub.

## Authentification

Utilise un des deux en-têtes suivants :

```text
X-Moderation-Key: <clé>
```

ou :

```text
Authorization: Bearer <clé>
```

## Lister les images

```http
GET /api/admin/moderation/images?limit=100
```

La réponse contient notamment `id`, `raw_url` et `delete_url`.

Pour la pagination, rappelle la route avec `after=<next_after>` lorsque `next_after` n'est pas vide.

## Supprimer une image

```http
DELETE /api/admin/moderation/images/<file_id>
Content-Type: application/json
X-Moderation-Key: <clé>

{
  "reason": "contenu_illicite",
  "detector": "nudenet-local",
  "score": 0.99
}
```

Valeurs de raison recommandées : `contenu_illicite`, `non_respect_cgu` ou `spam_abus`.

La suppression passe par le service interne PixShare : le fichier est retiré, son statut est changé, les votes sont nettoyés et la miniature est programmée pour suppression.
