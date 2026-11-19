"""Images déjà acceptées par le filtre : un renvoi du MÊME fichier est publié sans nouvelle analyse.

Garde-fous :
* empreinte exacte (SHA-256) uniquement : une image retouchée, même d'un pixel, est réanalysée ;
* chaque acceptation est liée aux réglages du filtre (seuils, parties surveillées, découpage, version
  de NudeNet) : si l'admin les change, les anciennes acceptations ne comptent plus ;
* visiteurs et membres sont séparés (le filtre est plus tolérant pour les membres) ;
* une image supprimée par l'admin ou signalée est oubliée.

Place sur le disque : une ligne d'environ 150 octets par image dans la base SQLite. Au maximum
MAX_ENTRIES lignes (environ 3 Mo) ; une acceptation pas resservie depuis KEEP_DAYS jours est effacée.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

from pixshare.services.json_services import _get_data_dir, _json_lock, load_json, save_json, use_sqlite

APPROVED_FILE = "approved_hashes.json"   # secours sans SQLite (PIXSHARE_STORAGE=json)
MAX_ENTRIES = 20000
JSON_MAX_ENTRIES = 2000
KEEP_DAYS = 180
_log = logging.getLogger(__name__)


def fingerprint(detector: str, review: float, block: float, tiling: bool, classes) -> str:
    raw = json.dumps([detector, round(float(review), 4), round(float(block), 4), bool(tiling),
                      sorted(classes or [])], sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _profile(member: bool) -> str:
    return "membre:" if member else "visiteur:"


def _key(sha: str, member: bool) -> str:
    return _profile(member) + sha


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _store():
    from pixshare.services import sqlite_store
    return sqlite_store, _get_data_dir()


# ---- secours JSON (petit plafond : le fichier est réécrit en entier à chaque fois)

def _jload() -> dict:
    data = load_json(APPROVED_FILE, {})
    return data if isinstance(data, dict) and isinstance(data.get("entries"), dict) else {"entries": {}}


def known(sha: str, member: bool, fp: str) -> dict | None:
    """L'acceptation enregistrée pour ce fichier, si elle vaut encore avec les réglages actuels."""
    if not sha:
        return None
    key = _key(sha, member)
    if use_sqlite():
        store, data_dir = _store()
        entry = store.approved_get(data_dir, key)
        if entry and entry["fp"] == fp:
            store.approved_touch(data_dir, key, _now())  # resservie : gardée plus longtemps
            return entry
        return None
    entry = _jload()["entries"].get(key)
    return entry if isinstance(entry, dict) and entry.get("fp") == fp else None


def remember(sha: str, member: bool, fp: str, score) -> None:
    if not sha:
        return
    key, score = _key(sha, member), float(score or 0.0)
    if use_sqlite():
        store, data_dir = _store()
        store.approved_put(data_dir, key, fp, score, _now(), _profile(member), MAX_ENTRIES)
        return
    with _json_lock:
        data = _jload()
        entries = data["entries"]
        entries[key] = {"fp": fp, "score": score, "at": _now()}
        for k in [k for k, v in entries.items() if k.startswith(_profile(member)) and v.get("fp") != fp]:
            entries.pop(k, None)
        for k, _v in sorted(entries.items(), key=lambda kv: kv[1].get("at", ""))[:max(0, len(entries) - JSON_MAX_ENTRIES)]:
            entries.pop(k, None)
        save_json(APPROVED_FILE, data)


def forget(sha: str) -> bool:
    """L'image a été supprimée par l'admin, signalée ou mise en revue : plus jamais publiée d'office."""
    if not sha:
        return False
    keys = [_key(sha, False), _key(sha, True)]
    if use_sqlite():
        store, data_dir = _store()
        return store.approved_delete(data_dir, keys) > 0
    with _json_lock:
        data = _jload()
        removed = [data["entries"].pop(k, None) for k in keys]
        if any(removed):
            save_json(APPROVED_FILE, data)
            return True
    return False


def purge_old() -> int:
    """Efface les acceptations pas resservies depuis KEEP_DAYS jours (appelé avec le ménage du site)."""
    limit = (datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)).isoformat(timespec="seconds")
    if use_sqlite():
        store, data_dir = _store()
        return store.approved_purge(data_dir, limit)
    with _json_lock:
        data = _jload()
        old = [k for k, v in data["entries"].items() if str(v.get("at", "")) < limit]
        for k in old:
            data["entries"].pop(k, None)
        if old:
            save_json(APPROVED_FILE, data)
        return len(old)


def clear() -> int:
    if use_sqlite():
        store, data_dir = _store()
        return store.approved_purge(data_dir)
    with _json_lock:
        n = len(_jload()["entries"])
        save_json(APPROVED_FILE, {"entries": {}})
        return n


def count() -> int:
    if use_sqlite():
        store, data_dir = _store()
        return store.approved_count(data_dir)
    return len(_jload()["entries"])
