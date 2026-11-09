"""Limite de débit en mémoire (fenêtre glissante d'une minute).

Sert à freiner les abus de l'API : trop de requêtes par minute pour une clé, ou
trop d'essais avec une clé invalide depuis une même IP. Les compteurs sont propres
à chaque processus du serveur et repartent de zéro au redémarrage ; les quotas
d'envoi (totaux et journaliers), eux, restent dans api_keys.json.
"""
from __future__ import annotations

import hashlib
import threading
import time
from collections import deque
from dataclasses import dataclass

from flask import current_app, g

WINDOW_SECONDS = 60
DEFAULT_LIMIT_PER_MINUTE = 60
FAILED_AUTH_LIMIT_PER_MINUTE = 30
_MAX_BUCKETS = 20000

_lock = threading.Lock()
_hits: dict[str, deque] = {}


@dataclass(frozen=True)
class RateInfo:
    allowed: bool
    limit: int        # 0 = pas de limite
    remaining: int
    retry_after: int  # secondes à attendre avant de réessayer (0 si autorisé)
    reset: int        # secondes avant que la fenêtre soit libre


def _now() -> float:
    return time.monotonic()


def reset() -> None:
    with _lock:
        _hits.clear()


def _prune(now: float, window: int) -> None:
    for name in [n for n, q in _hits.items() if not q or now - q[-1] >= window]:
        del _hits[name]
    if len(_hits) >= _MAX_BUCKETS:
        _hits.clear()


def hit(bucket: str, limit: int, window: int = WINDOW_SECONDS) -> RateInfo:
    """Compte une requête dans `bucket`. `limit` <= 0 : aucune limite."""
    if limit <= 0:
        return RateInfo(True, 0, 0, 0, 0)

    now = _now()
    with _lock:
        queue = _hits.get(bucket)
        if queue is None:
            if len(_hits) >= _MAX_BUCKETS:
                _prune(now, window)
            queue = _hits[bucket] = deque()

        while queue and now - queue[0] >= window:
            queue.popleft()

        wait = max(1, int(window - (now - queue[0]) + 0.999)) if queue else window
        if len(queue) >= limit:
            return RateInfo(False, limit, 0, wait, wait)

        queue.append(now)
        return RateInfo(True, limit, limit - len(queue), 0, wait)


def key_bucket(key_value: str) -> str:
    return "key:" + hashlib.sha256(key_value.encode("utf-8")).hexdigest()[:16]


def limit_for_key(key_data: dict | None) -> int:
    """Limite par minute : valeur propre à la clé, sinon réglage global (60 par défaut)."""
    for raw in ((key_data or {}).get("rate_limit_per_minute"), current_app.config.get("API_RATE_LIMIT_PER_MINUTE")):
        try:
            if raw is not None and str(raw).strip() != "":
                return max(0, int(raw))
        except (TypeError, ValueError):
            continue
    return DEFAULT_LIMIT_PER_MINUTE


def apply_headers(response):
    """En-têtes X-RateLimit-* (et Retry-After quand la limite est atteinte)."""
    info = g.get("rate_limit")
    if info is not None and info.limit:
        response.headers["X-RateLimit-Limit"] = str(info.limit)
        response.headers["X-RateLimit-Remaining"] = str(info.remaining)
        response.headers["X-RateLimit-Reset"] = str(info.reset)
        if not info.allowed:
            response.headers["Retry-After"] = str(info.retry_after)
    return response
