# Plugin Python PixShare

Le plugin réduit l'utilisation normale de l'API à trois méthodes :

- `upload()` : envoyer un fichier
- `info()` : lire les informations d'un fichier
- `delete()` : supprimer un fichier

## Installation

Le projet PixShare contient maintenant le dossier `pixshare_plugin`.
Copie ce dossier dans ton projet Python, puis installe `requests` :

```bash
pip install requests
```

## Utilisation minimale

```python
from pixshare_plugin import PixShare

pix = PixShare("MA_CLE_API")

fichier = pix.upload("photo.jpg")
print(fichier.id)
print(fichier.url)
```

## Expiration

```python
fichier = pix.upload("photo.jpg", expiration=60)
```

`60` signifie 60 minutes. Pour une clé autorisant les fichiers permanents :

```python
fichier = pix.upload("photo.jpg", expiration="permanent")
```

## Informations

```python
fichier = pix.info("ID_DU_FICHIER")
print(fichier.url)
print(fichier.status)
print(fichier.expires_at)
```

## Suppression

```python
pix.delete("ID_DU_FICHIER")
```

## Gestion des erreurs

```python
from pixshare_plugin import PixShare, PixShareError

pix = PixShare("MA_CLE_API")

try:
    fichier = pix.upload("photo.jpg")
    print(fichier.url)
except PixShareError as e:
    print("Erreur :", e)
    print("Code API :", e.code)
```

## Serveur local

Pour tester un PixShare lancé localement :

```python
pix = PixShare(
    "MA_CLE_API",
    base_url="http://127.0.0.1:5000"
)
```

Le serveur PixShare conserve ses routes historiques pour ne pas casser les anciens clients, mais un nouveau programme Python n'a besoin que de :

```text
POST   /api/upload
GET    /api/file/<id>
DELETE /api/file/<id>
```
