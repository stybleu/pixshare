"""Chiffrement de l'espace entreprise : photos ET données (machines, interventions, commentaires).

AES-256-GCM (chiffrement authentifié : un fichier modifié ou abîmé est détecté et refusé).
La clé vient de la variable d'environnement PRO_ENCRYPTION_KEY (64 caractères hexadécimaux,
ou 44 caractères base64). Sans elle, une clé est dérivée de SECRET_KEY : ça fonctionne, mais
changer SECRET_KEY rendrait alors les photos illisibles. La clé n'est JAMAIS écrite sur le disque :
le disque et les sauvegardes ne contiennent que des données chiffrées.
"""
from __future__ import annotations

import base64
import binascii
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"PXP1"          # en-tête : format version 1
NONCE = 12


class DecryptError(ValueError):
    """Données illisibles : mauvaise clé, ou fichier modifié/abîmé."""


def _key() -> bytes:
    raw = (os.environ.get("PRO_ENCRYPTION_KEY") or "").strip()
    if raw:
        for decode in (bytes.fromhex, base64.b64decode, base64.urlsafe_b64decode):
            try:
                key = decode(raw)
            except (ValueError, binascii.Error):
                continue
            if len(key) == 32:
                return key
        raise RuntimeError("PRO_ENCRYPTION_KEY doit faire 32 octets (64 caractères hexadécimaux).")
    from flask import current_app
    secret = str(current_app.config.get("SECRET_KEY") or "")
    if not secret:
        raise RuntimeError("Ni PRO_ENCRYPTION_KEY ni SECRET_KEY : chiffrement impossible.")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"pixshare-pro",
                info=b"espace entreprise v1").derive(secret.encode())


def uses_dedicated_key() -> bool:
    return bool((os.environ.get("PRO_ENCRYPTION_KEY") or "").strip())


def encrypt(data: bytes, context: str) -> bytes:
    """`context` lie le contenu à son usage (ex. « photo:<id> ») : impossible d'échanger deux fichiers."""
    nonce = os.urandom(NONCE)
    return MAGIC + nonce + AESGCM(_key()).encrypt(nonce, data, context.encode())


def decrypt(blob: bytes, context: str) -> bytes:
    if not blob or not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + NONCE + 16:
        raise DecryptError("format inconnu")
    nonce = blob[len(MAGIC):len(MAGIC) + NONCE]
    try:
        return AESGCM(_key()).decrypt(nonce, blob[len(MAGIC) + NONCE:], context.encode())
    except Exception as exc:  # InvalidTag
        raise DecryptError("clé incorrecte ou données modifiées") from exc


def encrypt_json(value, context: str) -> str:
    return base64.b64encode(encrypt(json.dumps(value, ensure_ascii=False).encode(), context)).decode()


def decrypt_json(text: str, context: str):
    return json.loads(decrypt(base64.b64decode(text), context))
