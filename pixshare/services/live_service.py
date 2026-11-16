"""Visiteurs « en direct » pour l'admin : qui est sur le site depuis les 5 dernières minutes.

Position approximative fournie par Cloudflare (option « Add visitor location headers ») :
ville, pays, latitude/longitude déduites de l'IP. Rien n'est écrit sur le disque persistant :
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


def _device(ua: str) -> str:
    ua = ua or ""
    kind = "Tablette" if re.search(r"iPad|Tablet", ua) else "Mobile" if re.search(r"Mobi|Android|iPhone", ua) else "Ordinateur"
    for name, pattern in (("Edge", r"Edg/"), ("Opera", r"OPR/"), ("Samsung", r"SamsungBrowser"),
                          ("Firefox", r"Firefox/"), ("Chrome", r"Chrome/"), ("Safari", r"Safari/")):
        if re.search(pattern, ua):
            return f"{kind} · {name}"
    return kind


def _float(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if -180.0 <= number <= 180.0 else None


def _read() -> dict:
    try:
        with open(_LIVE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(data: dict) -> None:
    tmp = _LIVE_FILE + f".{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, _LIVE_FILE)


def _locked(fn):
    with _lock:
        handle = open(_LIVE_FILE + ".lock", "a+") if fcntl else None
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
    city = (h.get("cf-ipcity") or "").strip()[:60]
    region = (h.get("cf-region") or "").strip()[:60]
    country = (h.get("cf-ipcountry") or "").strip().upper()[:2]
    lat, lon = _float(h.get("cf-iplatitude")), _float(h.get("cf-iplongitude"))

    def update():
        data = _prune(_read(), now)
        entry = data.get(key) or {"first": now, "pages": 0}
        entry.update({
            "ip": ip or "", "masked": mask_ip(ip or ""), "last": now, "path": request.path[:120],
            "device": _device(ua), "city": city, "region": region, "country": country,
            "lat": lat, "lon": lon,
        })
        entry["pages"] = int(entry.get("pages", 0)) + 1
        data[key] = entry
        _write(data)

    _locked(update)


def snapshot() -> list[dict]:
    """Visiteurs actifs, du plus récent au plus ancien, avec durées lisibles."""
    now = time.time()
    data = _locked(lambda: _prune(_read(), now))
    rows = []
    for key, entry in sorted(data.items(), key=lambda kv: kv[1].get("last", 0), reverse=True):
        row = dict(entry)
        row["id"] = key
        row["seen_ago"] = int(now - float(entry.get("last", now)))
        row["on_site"] = int(now - float(entry.get("first", now)))
        rows.append(row)
    return rows
