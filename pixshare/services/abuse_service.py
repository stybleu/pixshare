"""Blocage automatique des récidivistes : trop d'images rejetées par NudeNet -> IP bloquée un moment.

Réglages (variables d'environnement Render) :
- AUTO_BLOCK_REJECTIONS : nombre d'images rejetées qui déclenche le blocage (3 par défaut, 0 = désactivé) ;
- AUTO_BLOCK_HOURS : durée du blocage et de la fenêtre de comptage, en heures (24 par défaut).
Le blocage est temporaire : une IP mobile change souvent de personne.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

from pixshare.services.json_services import _json_lock, block_ip, load_json, save_json

_log = logging.getLogger(__name__)
OFFENSES_FILE = "auto_block_offenses.json"


def _env_number(name: str, default: float) -> float:
    try:
        return max(0.0, float(os.environ.get(name, default)))
    except ValueError:
        return default


def auto_block_settings() -> dict:
    return {
        "rejections": int(_env_number("AUTO_BLOCK_REJECTIONS", 3)),
        "hours": _env_number("AUTO_BLOCK_HOURS", 24) or 24,
    }


def record_rejection(ip: str) -> bool:
    """Note une image rejetée pour cette IP. Retourne True si l'IP vient d'être bloquée."""
    ip = (ip or "").strip()
    cfg = auto_block_settings()
    if not ip or cfg["rejections"] <= 0:
        return False
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=cfg["hours"])
    with _json_lock:
        data = load_json(OFFENSES_FILE, {})
        if not isinstance(data, dict):
            data = {}
        recent = []
        for stamp in data.get(ip, []) + [now.isoformat(timespec="seconds")]:
            try:
                if datetime.fromisoformat(stamp) > since:
                    recent.append(stamp)
            except (TypeError, ValueError):
                continue
        # on oublie les IP sans rejet récent (fichier toujours petit)
        data = {k: v for k, v in data.items() if k != ip and any(_after(s, since) for s in v)}
        blocked = False
        if len(recent) >= cfg["rejections"]:
            hours = cfg["hours"]
            blocked = block_ip(ip, f"Auto : {len(recent)} images rejetées par NudeNet", hours)
            if blocked:
                _log.warning("IP bloquée automatiquement pour %s h après %d images rejetées.", hours, len(recent))
        else:
            data[ip] = recent
        save_json(OFFENSES_FILE, data)
    return blocked


def _after(stamp, since) -> bool:
    try:
        return datetime.fromisoformat(stamp) > since
    except (TypeError, ValueError):
        return False
