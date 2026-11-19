"""Statistiques de NudeNet : combien d'images publiées, mises de côté, supprimées,
et ce que l'admin a décidé pour les images « à vérifier » (fausses alertes ou non).

Fichier nsfw_stats.json : remis à zéro à chaque déploiement (pas de disque persistant).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from pixshare.services.json_services import _json_lock, load_json, save_json

_log = logging.getLogger(__name__)
STATS_FILE = "nsfw_stats.json"
KEYS = ("auto_approved", "auto_review", "auto_rejected", "review_approved", "review_deleted", "absent_deleted", "hash_approved")


def bump(key: str) -> None:
    """Ajoute 1 au compteur. Ne gêne jamais la modération."""
    if key not in KEYS:
        return
    try:
        with _json_lock:
            data = load_json(STATS_FILE, {})
            if not isinstance(data, dict):
                data = {}
            data.setdefault("since", datetime.now(timezone.utc).isoformat(timespec="seconds"))
            data[key] = int(data.get(key, 0) or 0) + 1
            save_json(STATS_FILE, data)
    except Exception:
        _log.exception("Statistiques NudeNet non enregistrées")


def load_stats() -> dict:
    data = load_json(STATS_FILE, {})
    if not isinstance(data, dict):
        data = {}
    stats = {key: int(data.get(key, 0) or 0) for key in KEYS}
    stats["since"] = str(data.get("since") or "")
    stats["analysed"] = stats["auto_approved"] + stats["auto_review"] + stats["auto_rejected"]
    decided = stats["review_approved"] + stats["review_deleted"]
    stats["review_decided"] = decided
    stats["false_alarm_pct"] = round(100 * stats["review_approved"] / decided) if decided else None
    advice = ""
    if decided >= 10:
        if stats["false_alarm_pct"] >= 80:
            advice = "Presque toutes les images « à vérifier » étaient inoffensives : tu peux monter le seuil de revue (ex. 0,70)."
        elif stats["false_alarm_pct"] <= 20:
            advice = "Presque toutes les images « à vérifier » étaient à supprimer : tu peux baisser le seuil de suppression automatique (ex. 0,80)."
        else:
            advice = "Les seuils semblent bien réglés."
    stats["advice"] = advice
    return stats


def reset_stats() -> None:
    save_json(STATS_FILE, {"since": datetime.now(timezone.utc).isoformat(timespec="seconds")})
