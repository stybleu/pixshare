"""Visiteurs « en direct » pour l'admin : qui est sur le site depuis les 5 dernières minutes.

Aucune localisation ni profil : seulement l'IP (pour pouvoir bloquer un abus) et la page consultée.
Les robots (Google, aperçus, IA, scripts…) ont leur propre liste, dans un second petit fichier temporaire.
Rien n'est écrit sur le disque persistant :
un petit fichier dans le dossier temporaire du serveur (partagé entre les workers), vidé au fil
de l'eau (5 minutes) et effacé à chaque redémarrage.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile
import threading
import time

from flask import request

from pixshare.services.visitor_stats_service import _today, _visitor_key

WINDOW_SECONDS = 300
MAX_VISITORS = 300
_LIVE_FILE = os.path.join(tempfile.gettempdir(), "pixshare_live.json")
_lock = threading.Lock()

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None


def mask_ip(ip: str) -> str:
    """86.218.162.249 -> 86.218.x.x ; 2a01:cb00:1234::1 -> 2a01:cb00:x:x"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "?"
    if addr.version == 4:
        parts = str(addr).split(".")
        return f"{parts[0]}.{parts[1]}.x.x"
    groups = addr.exploded.split(":")
    return f"{groups[0].lstrip('0') or '0'}:{groups[1].lstrip('0') or '0'}:x:x"


def _bots_file() -> str:
    return _LIVE_FILE[:-5] + "_bots.json" if _LIVE_FILE.endswith(".json") else _LIVE_FILE + ".bots"


def _read(path: str | None = None) -> dict:
    try:
        with open(path or _LIVE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(data: dict, path: str | None = None) -> None:
    path = path or _LIVE_FILE
    tmp = path + f".{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)


def _locked(fn, path: str | None = None):
    with _lock:
        handle = open((path or _LIVE_FILE) + ".lock", "a+") if fcntl else None
        try:
            if handle:
                fcntl.flock(handle, fcntl.LOCK_EX)
            return fn()
        finally:
            if handle:
                fcntl.flock(handle, fcntl.LOCK_UN)
                handle.close()


def _prune(data: dict, now: float) -> dict:
    fresh = {k: v for k, v in data.items() if now - float(v.get("last", 0)) <= WINDOW_SECONDS}
    if len(fresh) > MAX_VISITORS:
        keep = sorted(fresh.items(), key=lambda kv: kv[1].get("last", 0), reverse=True)[:MAX_VISITORS]
        fresh = dict(keep)
    return fresh


def record(ip: str) -> None:
    """Note la page que ce visiteur est en train de voir (appelé pour chaque page comptée)."""
    h = request.headers
    ua = h.get("User-Agent", "")
    now = time.time()
    key = _visitor_key(ip or "?", ua, _today())
    def update():
        data = _prune(_read(), now)
        entry = data.get(key) or {"first": now, "pages": 0}
        entry.update({
            "ip": ip or "", "masked": mask_ip(ip or ""), "last": now, "path": request.path[:120],
        })
        for old in ("city", "region", "country", "lat", "lon", "device"):
            entry.pop(old, None)
        entry["pages"] = int(entry.get("pages", 0)) + 1
        data[key] = entry
        _write(data)

    _locked(update)


def snapshot(path: str | None = None) -> list[dict]:
    """Visiteurs actifs, du plus récent au plus ancien, avec durées lisibles."""
    now = time.time()
    data = _locked(lambda: _prune(_read(path), now), path)
    rows = []
    for key, entry in sorted(data.items(), key=lambda kv: kv[1].get("last", 0), reverse=True):
        row = dict(entry)
        row["id"] = key
        row["seen_ago"] = int(now - float(entry.get("last", now)))
        row["on_site"] = int(now - float(entry.get("first", now)))
        rows.append(row)
    return rows


# ------------------------------------------------------------------ robots

LEGIT_CATEGORIES = {"search_bot", "preview_bot"}  # moteurs de recherche et aperçus de liens : jamais bloqués d'un clic
_BOT_TOKEN = re.compile(r"[A-Za-z0-9_\-]*(?:bot|crawl|spider)[A-Za-z0-9_\-]*", re.I)
_GENERIC_ROBOTS = (
    ("uptimerobot", "UptimeRobot"), ("pingdom", "Pingdom"), ("uptime", "Surveillance"), ("monitor", "Surveillance"),
    ("lighthouse", "Lighthouse"), ("headless", "Navigateur sans écran"), ("curl", "curl"), ("wget", "wget"),
    ("python", "Python"), ("go-http", "Go"), ("okhttp", "okhttp"), ("java/", "Java"), ("httpclient", "Client HTTP"),
    ("slurp", "Yahoo"), ("scan", "Scanner"), ("preview", "Aperçu de lien"), ("fetch", "Client HTTP"),
)
_pending: dict[str, int] = {}      # requêtes d'un même robot reçues à moins d'une seconde : comptées au prochain passage
_last_write: dict[str, float] = {}


def robot_family(user_agent: str) -> tuple[str, str]:
    """(nom lisible, catégorie) d'un robot d'après son User-Agent."""
    ua = (user_agent or "").strip()
    if not ua:
        return "Sans identifiant", "unknown_bot"
    from pixshare.services.usage_tracking_service import KNOWN_USER_AGENTS
    low = ua.lower()
    for needle, (name, category) in KNOWN_USER_AGENTS.items():
        if needle in low:
            return name, category
    match = _BOT_TOKEN.search(ua)
    if match:
        return match.group(0)[:30], "unknown_bot"
    for needle, name in _GENERIC_ROBOTS:
        if needle in low:
            return name, "unknown_bot"
    return "Autre robot", "unknown_bot"


def is_robot_request() -> bool:
    from pixshare.services.visitor_stats_service import is_bot
    if request.method not in ("GET", "HEAD") or request.path.startswith(("/admin", "/static", "/healthz")):
        return False
    return is_bot(request.headers.get("User-Agent", ""))


def record_bot(ip: str) -> None:
    """Note qu'un robot vient de passer : son nom, la dernière page demandée et le nombre de requêtes."""
    ua = request.headers.get("User-Agent", "")
    now = time.time()
    key = _visitor_key(ip or "?", ua, _today())
    if now - _last_write.get(key, 0.0) < 1.0:  # un robot qui moissonne : on n'écrit pas à chaque requête
        _pending[key] = _pending.get(key, 0) + 1
        return
    if len(_last_write) > 2000:
        _last_write.clear()
    _last_write[key] = now
    extra = _pending.pop(key, 0)
    name, category = robot_family(ua)
    page = request.path[:120]
    path = _bots_file()

    def update():
        data = _prune(_read(path), now)
        entry = data.get(key) or {"first": now, "hits": 0}
        entry.update({"ip": ip or "", "masked": mask_ip(ip or ""), "last": now, "path": page,
                      "name": name, "category": category, "ua": ua[:100]})
        entry["hits"] = int(entry.get("hits", 0)) + 1 + extra
        data[key] = entry
        _write(data, path)

    _locked(update, path)


def snapshot_bots() -> list[dict]:
    rows = snapshot(_bots_file())
    for row in rows:
        row["legit"] = row.get("category") in LEGIT_CATEGORIES
    return rows


def robot_families(rows: list[dict]) -> list[dict]:
    """Robots par famille (Google, GPTBot…) sur les 5 dernières minutes : nombre de requêtes."""
    totals: dict[str, int] = {}
    for row in rows:
        name = str(row.get("name") or "Autre robot")
        totals[name] = totals.get(name, 0) + int(row.get("hits") or 0)
    return [{"name": n, "count": c} for n, c in sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:8]]
