"""Limite d'envois par adresse IP sur le site public.

Fenêtre glissante gardée en mémoire : « au plus N envois par période, pour une
même IP ». Au-delà, le site répond « 429 – trop d'envois » avec le délai d'attente.

Réglages (variables d'environnement, lues au démarrage) :
  UPLOAD_RATE_LIMIT       nombre d'envois autorisés par période (défaut 30, 0 = pas de limite)
  UPLOAD_RATE_WINDOW_SEC  durée de la période en secondes (défaut 3600 = 1 heure)

À savoir :
- Les compteurs sont propres à chaque processus et repartent de zéro au redémarrage
  du serveur (pas de base de données ni de disque nécessaire).
- Avec plusieurs workers gunicorn, chacun compte de son côté (la limite réelle est
  alors multipliée par le nombre de workers ; par défaut il n'y en a qu'un).
- La fiabilité dépend de get_client_ip() : tant que TRUSTED_PROXY_COUNT n'est pas
  défini sur Render, une IP peut être falsifiée avec un en-tête X-Forwarded-For.
- L'administrateur connecté n'est jamais limité.
"""
from __future__ import annotations

import math
import threading
import time
from collections import deque
from dataclasses import dataclass

from flask import current_app

DEFAULT_LIMIT = 30
DEFAULT_WINDOW_SEC = 3600
_MAX_BUCKETS = 20000

_lock = threading.Lock()


@dataclass(frozen=True)
class RateInfo:
    allowed: bool
    limit: int        # 0 = pas de limite
    window: int       # durée de la période, en secondes
    remaining: int    # envois encore possibles dans la période
    retry_after: int  # secondes à attendre avant de réessayer (0 si autorisé)


def _now() -> float:
    return time.monotonic()


def _as_int(value, default: int) -> int:
    try:
        if value is None or str(value).strip() == "":
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def upload_limit_settings() -> tuple[int, int]:
    """(nombre d'envois, durée en secondes). Un nombre <= 0 désactive la limite."""
    limit = _as_int(current_app.config.get("UPLOAD_RATE_LIMIT"), DEFAULT_LIMIT)
    window = _as_int(current_app.config.get("UPLOAD_RATE_WINDOW_SEC"), DEFAULT_WINDOW_SEC)
    return max(0, limit), max(1, window)


def _buckets() -> dict:
    # Rangés dans l'application : chaque app (et chaque test) a ses propres compteurs.
    return current_app.extensions.setdefault("pixshare_upload_rate", {})


def _prune(buckets: dict, now: float, window: int) -> None:
    for name in [n for n, q in buckets.items() if not q or now - q[-1] >= window]:
        del buckets[name]
    if len(buckets) >= _MAX_BUCKETS:
        buckets.clear()


def check_upload_rate(ip: str, exempt: bool = False) -> RateInfo:
    """Compte un envoi pour `ip` et dit s'il est autorisé.

    `exempt` (administrateur) et une IP inconnue ne sont jamais limités : sans IP,
    tous les visiteurs partageraient le même compteur.
    """
    limit, window = upload_limit_settings()
    if exempt or limit <= 0 or not ip:
        return RateInfo(True, 0, window, 0, 0)

    now = _now()
    with _lock:
        buckets = _buckets()
        queue = buckets.get(ip)
        if queue is None:
            if len(buckets) >= _MAX_BUCKETS:
                _prune(buckets, now, window)
            queue = buckets[ip] = deque()

        while queue and now - queue[0] >= window:
            queue.popleft()

        if len(queue) >= limit:
            wait = max(1, int(math.ceil(window - (now - queue[0]))))
            return RateInfo(False, limit, window, 0, wait)

        queue.append(now)
        return RateInfo(True, limit, window, limit - len(queue), 0)


def format_wait(seconds: int) -> str:
    if seconds < 60:
        return "quelques secondes"
    minutes = int(math.ceil(seconds / 60))
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes > 1 else ''}"
    hours = int(math.ceil(minutes / 60))
    return f"{hours} heure{'s' if hours > 1 else ''}"


def format_window(seconds: int) -> str:
    if seconds % 3600 == 0:
        hours = seconds // 3600
        return "heure" if hours == 1 else f"{hours} heures"
    if seconds % 60 == 0:
        minutes = seconds // 60
        return "minute" if minutes == 1 else f"{minutes} minutes"
    return f"{seconds} secondes"


def limit_message(info: RateInfo) -> str:
    return (
        f"Trop d'envois depuis ton adresse (maximum {info.limit} par {format_window(info.window)}). "
        f"Réessaie dans {format_wait(info.retry_after)}."
    )
