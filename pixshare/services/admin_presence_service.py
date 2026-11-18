"""Présence de l'admin (interne, jamais montrée au public).

L'admin est « présent » s'il a utilisé l'admin il y a moins de N minutes (réglage), et ne s'est pas
déconnecté depuis. Une page admin ouverte envoie un petit signal chaque minute. Absent : le filtre
NudeNet prend les décisions seul et supprime les images douteuses au lieu de les mettre de côté.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from pixshare.services.json_services import load_json, save_json

PRESENCE_FILE = "admin_presence.json"
_WRITE_EVERY_SEC = 30          # pas plus d'une écriture par worker toutes les 30 s
_lock = threading.Lock()
_last_write = 0.0
_log = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _load() -> dict:
    data = load_json(PRESENCE_FILE, {})
    return data if isinstance(data, dict) else {}


def _settings() -> dict:
    from pixshare.services.settings_service import load_settings
    s = load_settings()
    return {"mode": bool(s.get("admin_absent_mode", True)),
            "minutes": int(s.get("admin_absent_after_minutes") or 15),
            "members": bool(s.get("admin_absent_members", True))}


def touch(force: bool = False) -> int:
    """L'admin est là. Renvoie le nombre d'images supprimées par le filtre pendant son absence (puis remet à 0)."""
    global _last_write
    with _lock:
        if not force and time.monotonic() - _last_write < _WRITE_EVERY_SEC:
            return 0
        _last_write = time.monotonic()
    data = _load()
    deleted = int(data.get("deleted_while_away") or 0)
    data.update({"last_seen": _now().isoformat(timespec="seconds"), "logged_out": False, "deleted_while_away": 0})
    save_json(PRESENCE_FILE, data)
    return deleted


def logged_out() -> None:
    global _last_write
    data = _load()
    data.update({"logged_out": True, "logged_out_at": _now().isoformat(timespec="seconds")})
    save_json(PRESENCE_FILE, data)
    with _lock:
        _last_write = 0.0


def is_present() -> bool:
    """Vrai si l'admin décide lui-même (mode absent coupé, ou admin actif récemment)."""
    try:
        cfg = _settings()
        if not cfg["mode"]:
            return True
        data = _load()
        if data.get("logged_out"):
            return False
        seen = datetime.fromisoformat(str(data.get("last_seen") or ""))
        return _now() - seen < timedelta(minutes=cfg["minutes"])
    except (TypeError, ValueError):
        return False
    except Exception:
        _log.exception("Présence admin illisible : l'admin est considéré présent (rien n'est supprimé)")
        return True


def filter_decides(member: bool) -> bool:
    """Le filtre doit-il trancher seul pour cette image ?"""
    if is_present():
        return False
    return (not member) or _settings()["members"]


def count_deletion() -> None:
    data = _load()
    data["deleted_while_away"] = int(data.get("deleted_while_away") or 0) + 1
    save_json(PRESENCE_FILE, data)


def status() -> dict:
    cfg = _settings()
    data = _load()
    return {**cfg, "last_seen": data.get("last_seen") or "", "pending_count": int(data.get("deleted_while_away") or 0)}
