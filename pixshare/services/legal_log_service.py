"""Registre légal : obligation de conservation des hébergeurs (LCEN, article 6, V ; décret n° 2021-1362).

Pour chaque création, modification ou suppression d'un contenu, on garde UN AN :
  - l'adresse IP à l'origine de l'opération ;
  - le protocole utilisé ;
  - la nature de l'opération, la date et l'heure ;
  - l'identifiant du contenu ;
  - l'identifiant de l'auteur quand il en a fourni un (adresse e-mail du compte).

Ce registre sert UNIQUEMENT à répondre à une réquisition de la justice ou de la police.
Il est séparé du reste du site : rien ne s'en sert pour les statistiques, la modération ou autre chose.
Les lignes de plus d'un an sont effacées automatiquement. Une erreur ici ne bloque jamais un envoi.
"""
from __future__ import annotations

import csv
import io
import logging
import threading
from datetime import datetime, timedelta, timezone

_log = logging.getLogger(__name__)
RETENTION_DAYS = 365
JSON_DOC = "legal_log.json"          # secours si le site tourne sans SQLite
JSON_MAX = 50000
_purge_lock = threading.Lock()
_last_purge_day = None

# Natures d'opération enregistrées
CREATION = "création"
MODIFICATION = "modification"
SUPPRESSION = "suppression"
COMPTE_CREATION = "création de compte"
COMPTE_SUPPRESSION = "suppression de compte"
ALBUM_CREATION = "création d'album"
LIVRE_OR = "message du livre d'or"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _store():
    from .json_services import _get_data_dir, use_sqlite
    from . import sqlite_store
    return (sqlite_store if use_sqlite() else None), _get_data_dir()


def _author() -> str:
    try:
        from .account_service import current_account
        from .auth_service import is_admin
        rec = current_account()
        if rec:
            return str(rec.get("email") or rec.get("id") or "")
        return "admin" if is_admin() else ""
    except Exception:
        return ""


def _is_admin_session() -> bool:
    try:
        from .auth_service import is_admin
        return bool(is_admin())
    except Exception:
        return False


def _proto() -> str:
    try:
        from flask import request
        scheme = "HTTPS" if (request.is_secure or request.headers.get("X-Forwarded-Proto") == "https") else "HTTP"
        return f"{scheme} ({request.environ.get('SERVER_PROTOCOL', 'HTTP/1.1')})"
    except Exception:
        return ""


def record(op: str, content: str, author: str | None = None, ip: str | None = None) -> None:
    """Ajoute une ligne. Ne lève jamais d'exception (l'envoi ne doit pas échouer pour ça)."""
    try:
        # Les envois faits depuis la session admin (l'éditeur lui-même, pour tester) ne concernent aucun utilisateur :
        # ils n'entrent pas dans le registre.
        if author is None and _is_admin_session():
            return
        if ip is None:
            from .request_service import get_client_ip
            ip = get_client_ip() or ""
        at = _now().isoformat(timespec="seconds")
        who = _author() if author is None else author
        store, data_dir = _store()
        if store is not None:
            store.legal_add(data_dir, at, op, str(content or ""), ip, _proto(), who)
        else:
            from .json_services import load_json, save_json
            rows = load_json(JSON_DOC, []) or []
            rows.append({"at": at, "op": op, "content": str(content or ""), "ip": ip, "proto": _proto(), "author": who})
            save_json(JSON_DOC, rows[-JSON_MAX:])
        purge_if_due()
    except Exception:
        _log.exception("Registre légal : ligne non enregistrée")


def purge_if_due(force: bool = False) -> int:
    """Efface ce qui a plus d'un an (au plus une fois par jour et par processus)."""
    global _last_purge_day
    today = _now().date()
    if not force and _last_purge_day == today:
        return 0
    with _purge_lock:
        _last_purge_day = today
        limit = (_now() - timedelta(days=RETENTION_DAYS)).isoformat(timespec="seconds")
        store, data_dir = _store()
        if store is not None:
            return store.legal_purge(data_dir, limit)
        from .json_services import load_json, save_json
        rows = load_json(JSON_DOC, []) or []
        kept = [r for r in rows if str(r.get("at", "")) >= limit]
        if len(kept) != len(rows):
            save_json(JSON_DOC, kept)
        return len(rows) - len(kept)


def search(query: str = "", limit: int = 200) -> list[dict]:
    query = (query or "").strip()[:200]
    store, data_dir = _store()
    if store is not None:
        return store.legal_search(data_dir, query, limit)
    from .json_services import load_json
    rows = list(reversed(load_json(JSON_DOC, []) or []))
    if query:
        q = query.lower()
        rows = [r for r in rows if q in str(r.get("content", "")).lower() or q in str(r.get("ip", "")).lower()
                or q in str(r.get("author", "")).lower()]
    return rows[:limit]


def count() -> int:
    store, data_dir = _store()
    if store is not None:
        return store.legal_count(data_dir)
    from .json_services import load_json
    return len(load_json(JSON_DOC, []) or [])


def to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(["Date et heure (UTC)", "Opération", "Identifiant du contenu", "Adresse IP", "Protocole", "Auteur"])
    def cell(value) -> str:
        text = str(value or "")
        # Un prénom comme « =HYPERLINK(...) » ne doit pas devenir une formule dans Excel.
        return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text
    for r in rows:
        writer.writerow([cell(r.get(k)) for k in ("at", "op", "content", "ip", "proto", "author")])
    return "﻿" + buf.getvalue()   # le BOM permet à Excel de lire les accents
