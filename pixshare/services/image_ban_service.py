"""Images interdites : une image refusée (NudeNet, ou l'admin pour non-respect des CGU / contenu
illicite) est refusée pour toujours si quelqu'un la renvoie, sans repasser par NudeNet.

On garde seulement deux empreintes, jamais l'image :
- SHA-256 du fichier : même fichier au bit près -> refus immédiat ;
- empreinte visuelle (dHash 64 bits) : même image redimensionnée, recompressée ou capturée
  -> mise « à vérifier » (une ressemblance peut, rarement, toucher une image différente).
Fichier banned_images.json (disque persistant).
"""
from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone

from PIL import Image, ImageOps

from pixshare.services.json_services import _json_lock, load_json, save_json

_log = logging.getLogger(__name__)
BANNED_FILE = "banned_images.json"
BAN_REASONS = {"auto:non_respect_cgu", "non_respect_cgu", "contenu_illicite"}
REASON_LABELS = {
    "auto:non_respect_cgu": "Supprimée par NudeNet",
    "non_respect_cgu": "Non-respect des CGU (admin)",
    "contenu_illicite": "Contenu illicite (admin)",
}


class BannedImageError(ValueError):
    """L'image envoyée a déjà été refusée."""


def similarity_threshold() -> int:
    try:
        return max(0, min(16, int(os.environ.get("BANNED_SIMILARITY", "6"))))
    except ValueError:
        return 6


def file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def visual_hash(path: str) -> str | None:
    """dHash 64 bits (texte hexadécimal). None si l'image est illisible ou trop uniforme pour être fiable."""
    try:
        with Image.open(path) as im:
            im.seek(0)
            small = ImageOps.exif_transpose(im).convert("L").resize((9, 8), Image.LANCZOS)
        pixels = list(small.tobytes())  # 72 valeurs de gris (9 x 8)
    except Exception:
        return None
    bits = 0
    for row in range(8):
        for col in range(8):
            left, right = pixels[row * 9 + col], pixels[row * 9 + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    ones = bin(bits).count("1")
    if ones < 8 or ones > 56:  # image presque uniforme : trop de ressemblances possibles
        return None
    return f"{bits:016x}"


def _load() -> dict:
    data = load_json(BANNED_FILE, {})
    if not isinstance(data, dict):
        data = {}
    data.setdefault("sha256", {})
    data.setdefault("visual", {})
    return data


def ban_file(path: str, reason: str, label: str = "", file_id: str = "") -> bool:
    """Ajoute l'image aux images interdites (à appeler avant d'effacer le fichier)."""
    if reason not in BAN_REASONS or not path or not os.path.isfile(path):
        return False
    try:
        sha = file_sha256(path)
        vis = visual_hash(path)
        entry = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "reason": reason,
                 "label": (label or "")[:80], "file_id": file_id, "sha256": sha, "visual": vis or ""}
        with _json_lock:
            data = _load()
            data["sha256"][sha] = entry
            if vis:
                data["visual"][vis] = sha
            save_json(BANNED_FILE, data)
        _forget_admin_ok(sha, vis or "")
        return True
    except Exception:
        _log.exception("Empreinte d'image interdite non enregistrée")
        return False


def ban_record(meta: dict, file_id: str, thumb_path: str = "", reason: str = "non_respect_cgu") -> bool:
    """Interdit une image dont l'original n'existe plus (expirée, supprimée) : empreinte exacte si elle
    avait été gardée, et empreinte visuelle calculée sur sa miniature."""
    sha = str(meta.get("content_sha256") or "")
    vis = visual_hash(thumb_path) if thumb_path and os.path.isfile(thumb_path) else None
    if not sha and not vis:
        return False
    key = sha or f"visuel-{vis}"
    entry = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "reason": reason,
             "label": str(meta.get("moderation_label") or "")[:80], "file_id": file_id, "sha256": key,
             "visual": vis or "", "source": "miniature" if not sha else "empreinte gardée"}
    with _json_lock:
        data = _load()
        data["sha256"][key] = entry
        if vis:
            data["visual"][vis] = key
        save_json(BANNED_FILE, data)
    _forget_admin_ok(sha, vis or "")
    return True


def _forget_admin_ok(sha: str, vis: str) -> None:
    """Une image interdite ne peut plus être « validée par l'admin » : l'interdiction gagne."""
    try:
        from pixshare.services.admin_ok_service import forget
        forget(sha, vis)
    except Exception:
        _log.exception("Mémoire des photos validées non mise à jour")


def banned_ids() -> set[str]:
    """Identifiants des fichiers dont l'image est interdite (pour l'affichage dans l'admin)."""
    return {str(e.get("file_id")) for e in _load()["sha256"].values() if isinstance(e, dict) and e.get("file_id")}


def check_file(path: str) -> tuple[str, dict] | None:
    """("exact", infos) si le fichier est déjà interdit, ("similar", infos) si l'image y ressemble fortement."""
    try:
        data = _load()
        if not data["sha256"]:
            return None
        sha = file_sha256(path)
        if sha in data["sha256"]:
            return "exact", data["sha256"][sha]
        threshold = similarity_threshold()
        vis = visual_hash(path) if threshold else None
        if vis:
            value = int(vis, 16)
            best = None
            for other, banned_sha in data["visual"].items():
                distance = bin(value ^ int(other, 16)).count("1")
                if distance <= threshold and (best is None or distance < best[0]):
                    best = (distance, banned_sha)
            if best:
                info = dict(data["sha256"].get(best[1]) or {})
                info["distance"] = best[0]
                return "similar", info
    except Exception:
        _log.exception("Vérification des images interdites impossible")
    return None


def list_banned() -> list[dict]:
    items = list(_load()["sha256"].values())
    items.sort(key=lambda e: e.get("at", ""), reverse=True)
    for e in items:
        e["reason_label"] = REASON_LABELS.get(e.get("reason"), e.get("reason"))
    return items


def unban(sha: str) -> bool:
    with _json_lock:
        data = _load()
        entry = data["sha256"].pop(sha, None)
        if not entry:
            return False
        data["visual"] = {k: v for k, v in data["visual"].items() if v != sha}
        save_json(BANNED_FILE, data)
        return True
