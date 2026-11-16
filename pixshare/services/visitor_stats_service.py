"""Compteur de visites pour l'admin : visiteurs uniques par jour, pages vues, envois.

Aucune adresse IP n'est stockée : un visiteur est reconnu le temps d'une journée grâce à une
empreinte (IP + navigateur + date + clé secrète) qui change chaque jour et ne peut pas être inversée.
Les robots (Google, aperçus WhatsApp…), l'admin connecté et les pages techniques ne sont pas comptés.
Fichier visitor_stats.json (sur le disque persistant s'il y en a un) ; 90 jours gardés.
"""
from __future__ import annotations

import hashlib
import logging
import re
from datetime import date, datetime, timedelta, timezone

from flask import current_app, request

from pixshare.services.json_services import _json_lock, load_json, save_json

try:
    from zoneinfo import ZoneInfo
    _TZ = ZoneInfo("Europe/Paris")
except Exception:  # pragma: no cover
    _TZ = timezone.utc

_log = logging.getLogger(__name__)
STATS_FILE = "visitor_stats.json"
KEEP_DAYS = 90
_BOT = re.compile(
    r"bot|crawl|spider|slurp|preview|facebookexternalhit|whatsapp|telegram|discord|curl|wget|python|"
    r"httpclient|java/|go-http|okhttp|headless|lighthouse|monitor|uptime|render|pingdom|scan|fetch",
    re.I,
)
_SKIP_PREFIXES = ("/admin", "/static", "/healthz", "/robots.txt", "/sitemap.xml", "/report", "/delete", "/moderation")


def _today() -> date:
    return datetime.now(_TZ).date()


def is_bot(user_agent: str) -> bool:
    return not user_agent or bool(_BOT.search(user_agent))


def _visitor_key(ip: str, user_agent: str, day: date) -> str:
    secret = str(current_app.config.get("SECRET_KEY") or "")
    raw = f"{secret}|{day.isoformat()}|{ip}|{user_agent[:200]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _load() -> dict:
    data = load_json(STATS_FILE, {})
    if not isinstance(data, dict) or not isinstance(data.get("days"), dict):
        data = {"days": {}}
    return data


def _day_entry(data: dict, day: date) -> dict:
    entry = data["days"].setdefault(day.isoformat(), {"visitors": 0, "views": 0, "uploads": 0})
    for key in ("visitors", "views", "uploads"):
        entry.setdefault(key, 0)
    return entry


def _prune(data: dict, today: date) -> None:
    oldest = (today - timedelta(days=KEEP_DAYS)).isoformat()
    for day in list(data["days"]):
        if day < oldest:
            del data["days"][day]
        elif day != today.isoformat():
            data["days"][day].pop("keys", None)  # les empreintes ne servent que le jour même


def should_count(response) -> bool:
    if request.method != "GET" or response.status_code != 200 or response.mimetype != "text/html":
        return False
    if request.path.startswith(_SKIP_PREFIXES):
        return False
    purpose = (request.headers.get("Sec-Purpose") or request.headers.get("Purpose") or "").lower()
    if "prefetch" in purpose:
        return False
    return not is_bot(request.headers.get("User-Agent", ""))


def record_page_view(ip: str) -> None:
    """Compte une page vue (et un visiteur s'il n'est pas encore venu aujourd'hui)."""
    try:
        today = _today()
        key = _visitor_key(ip or "?", request.headers.get("User-Agent", ""), today)
        with _json_lock:
            data = _load()
            entry = _day_entry(data, today)
            entry["views"] += 1
            keys = entry.setdefault("keys", [])
            if key not in keys:
                keys.append(key)
                entry["visitors"] += 1
            _prune(data, today)
            save_json(STATS_FILE, data)
    except Exception:
        _log.exception("Compteur de visites non mis à jour")


def record_upload() -> None:
    try:
        today = _today()
        with _json_lock:
            data = _load()
            _day_entry(data, today)["uploads"] += 1
            save_json(STATS_FILE, data)
    except Exception:
        _log.exception("Compteur d'envois non mis à jour")


def summary(days: int = 30) -> dict:
    """Totaux et série jour par jour (du plus ancien au plus récent) pour la page admin."""
    data = _load()
    today = _today()
    series = []
    for offset in range(days - 1, -1, -1):
        day = today - timedelta(days=offset)
        entry = data["days"].get(day.isoformat()) or {}
        series.append({
            "date": day.isoformat(),
            "label": day.strftime("%d/%m"),
            "visitors": int(entry.get("visitors", 0)),
            "views": int(entry.get("views", 0)),
            "uploads": int(entry.get("uploads", 0)),
        })

    def total(last: int, key: str) -> int:
        return sum(item[key] for item in series[-last:])

    peak = max(series, key=lambda item: item["visitors"]) if series else None
    first_day = min(data["days"]) if data["days"] else ""
    return {
        "series": series,
        "max_visitors": max([item["visitors"] for item in series] + [1]),
        "today": series[-1] if series else {},
        "yesterday": series[-2] if len(series) > 1 else {},
        "week": {key: total(7, key) for key in ("visitors", "views", "uploads")},
        "month": {key: total(30, key) for key in ("visitors", "views", "uploads")},
        "peak": peak if peak and peak["visitors"] else None,
        "since": first_day,
    }
