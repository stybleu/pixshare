"""Photos validées par l'admin après une fausse alerte de NudeNet : le site s'en souvient.

Quand l'admin dit « cette photo est bonne », on garde deux empreintes (jamais l'image) :
- l'empreinte exacte du fichier (SHA-256) : le même fichier revient -> publié sans nouvelle analyse ;
- l'empreinte visuelle (la même que pour les images interdites) : une copie redimensionnée,
  recompressée ou renvoyée par une messagerie -> si NudeNet hésite (« à vérifier »), elle est publiée
  sans déranger l'admin ; si NudeNet est sûr de lui (suppression), l'admin décide quand même.
Une image interdite ensuite par l'admin est retirée de cette liste : l'interdiction gagne toujours.
Fichier admin_ok_images.json (disque persistant), au plus MAX_ENTRIES images.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from pixshare.services.json_services import _json_lock, load_json, save_json

_log = logging.getLogger(__name__)
OK_FILE = "admin_ok_images.json"
MAX_ENTRIES = 5000
SIMILARITY = 5          # bits de différence tolérés entre deux empreintes visuelles (sur 64)


def _load() -> dict:
    data = load_json(OK_FILE, {})
    if not isinstance(data, dict):
        data = {}
    data.setdefault("sha256", {})
    data.setdefault("visual", {})
    return data


def remember(path: str, meta: dict, file_id: str) -> bool:
    """À appeler quand l'admin approuve une image bloquée à tort par NudeNet."""
    from pixshare.services.image_ban_service import file_sha256, visual_hash
    try:
        sha = file_sha256(path)
        vis = visual_hash(path) or ""
        entry = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "sha256": sha, "visual": vis,
                 "file_id": file_id, "name": str(meta.get("original_name") or "")[:120],
                 "label": str(meta.get("moderation_label") or "")[:80],
                 "score": meta.get("moderation_score"), "member": bool(meta.get("account_id"))}
        with _json_lock:
            data = _load()
            data["sha256"][sha] = entry
            if vis:
                data["visual"][vis] = sha
            if len(data["sha256"]) > MAX_ENTRIES:     # les plus anciennes s'en vont
                for old in sorted(data["sha256"], key=lambda k: data["sha256"][k].get("at", ""))[:len(data["sha256"]) - MAX_ENTRIES]:
                    data["sha256"].pop(old, None)
                data["visual"] = {k: v for k, v in data["visual"].items() if v in data["sha256"]}
            save_json(OK_FILE, data)
        return True
    except Exception:
        _log.exception("Photo validée par l'admin non mémorisée")
        return False


NOT_NUDENET = ("analyse_impossible", "signalement")


def remember_approved(meta: dict, file_id: str) -> bool:
    """Après « Approuver » (admin ou lien du mail) : mémorise la photo si c'était une fausse alerte de NudeNet."""
    import os
    from flask import current_app
    if str(meta.get("moderation_label") or "") in NOT_NUDENET:
        return False
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], os.path.basename(str(meta.get("server_name") or "")))
    return os.path.isfile(path) and remember(path, meta, file_id)


def check(path: str, sha: str = "") -> tuple[str, dict] | None:
    """("exact", infos) si l'admin a validé ce fichier ; ("similar", infos) pour une copie très proche."""
    try:
        data = _load()
        if not data["sha256"]:
            return None
        if not sha:
            from pixshare.services.image_ban_service import file_sha256
            sha = file_sha256(path)
        if sha in data["sha256"]:
            return "exact", data["sha256"][sha]
        from pixshare.services.image_ban_service import visual_hash
        vis = visual_hash(path)
        if vis:
            value, best = int(vis, 16), None
            for other, ok_sha in data["visual"].items():
                distance = bin(value ^ int(other, 16)).count("1")
                if distance <= SIMILARITY and (best is None or distance < best[0]):
                    best = (distance, ok_sha)
            if best:
                return "similar", dict(data["sha256"].get(best[1]) or {}, distance=best[0])
    except Exception:
        _log.exception("Vérification des photos validées impossible")
    return None


def forget(sha: str = "", visual: str = "") -> bool:
    """Retire une photo de la liste (bouton de l'admin, ou image interdite ensuite)."""
    with _json_lock:
        data = _load()
        keys = {sha} if sha in data["sha256"] else set()
        if visual:
            keys |= {v for k, v in data["visual"].items() if k == visual}
        if not keys:
            return False
        for k in keys:
            data["sha256"].pop(k, None)
        data["visual"] = {k: v for k, v in data["visual"].items() if v not in keys}
        save_json(OK_FILE, data)
        return True


def list_ok() -> list[dict]:
    items = [e for e in _load()["sha256"].values() if isinstance(e, dict)]
    return sorted(items, key=lambda e: e.get("at", ""), reverse=True)


def count() -> int:
    return len(_load()["sha256"])
