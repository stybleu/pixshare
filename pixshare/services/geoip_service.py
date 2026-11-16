"""Géolocalisation des visiteurs sans Cloudflare : base gratuite « IP to City Lite » de DB-IP.

- Licence CC BY 4.0 : il faut citer DB-IP (lien « IP Geolocation by DB-IP » sur la page En direct
  et dans les mentions légales).
- La base (~120 Mo) est téléchargée automatiquement sur le disque, puis renouvelée chaque mois.
- Lecture en mémoire « mappée » : elle ne charge pas les 120 Mo en RAM.
Désactivable avec la variable Render GEOIP=0.
"""
from __future__ import annotations

import gzip
import ipaddress
import logging
import os
import shutil
import threading
import time
from datetime import date
from functools import lru_cache

_log = logging.getLogger(__name__)
DB_NAME = "dbip-city-lite.mmdb"
URL = "https://download.db-ip.com/free/dbip-city-lite-{month}.mmdb.gz"
MAX_AGE_DAYS = 32
ATTRIBUTION_HTML = '<a href="https://db-ip.com">IP Geolocation by DB-IP</a>'

_reader = None
_reader_mtime = None
_lock = threading.Lock()
_started = False
_status = {"state": "absent", "detail": ""}


def enabled() -> bool:
    return (os.environ.get("GEOIP") or "1").strip() not in ("0", "non", "false", "off")


def db_dir() -> str:
    from pixshare.services.json_services import _get_data_dir
    return os.path.join(_get_data_dir(), "geoip")


def db_path() -> str:
    return os.path.join(db_dir(), DB_NAME)


def _months_to_try(today: date | None = None) -> list[str]:
    today = today or date.today()
    previous = date(today.year - 1, 12, 1) if today.month == 1 else date(today.year, today.month - 1, 1)
    return [today.strftime("%Y-%m"), previous.strftime("%Y-%m")]


def _is_fresh(path: str) -> bool:
    try:
        return time.time() - os.path.getmtime(path) < MAX_AGE_DAYS * 86400
    except OSError:
        return False


def download(force: bool = False) -> bool:
    """Télécharge la base du mois (ou du mois précédent si pas encore publiée). Un seul worker à la fois."""
    import requests

    os.makedirs(db_dir(), exist_ok=True)
    path = db_path()
    if not force and _is_fresh(path):
        _status.update(state="ok", detail="")
        return True
    lock_path = path + ".lock"
    try:
        import fcntl
        lock = open(lock_path, "a+")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            lock.close()
            _status.update(state="downloading", detail="téléchargement en cours (autre processus)")
            return False
    except ImportError:  # pragma: no cover
        lock = None
    try:
        if not force and _is_fresh(path):
            return True
        _status.update(state="downloading", detail="téléchargement en cours")
        for month in _months_to_try():
            url = URL.format(month=month)
            tmp = path + ".part"
            try:
                with requests.get(url, stream=True, timeout=(10, 120)) as resp:
                    if resp.status_code != 200:
                        continue
                    resp.raw.decode_content = False
                    with gzip.GzipFile(fileobj=resp.raw) as gz, open(tmp, "wb") as out:
                        shutil.copyfileobj(gz, out, 1 << 20)
                if os.path.getsize(tmp) < 1_000_000:
                    raise ValueError("fichier trop petit")
                os.replace(tmp, path)
                _status.update(state="ok", detail=f"base DB-IP {month}")
                _log.info("Base de géolocalisation DB-IP %s installée.", month)
                return True
            except Exception as exc:
                _log.warning("Téléchargement DB-IP %s impossible : %s", month, exc)
                try:
                    os.remove(tmp)
                except OSError:
                    pass
        _status.update(state="error", detail="téléchargement impossible (nouvel essai plus tard)")
        return False
    finally:
        if lock:
            lock.close()


def _keep_updated() -> None:
    while True:
        try:
            download()
        except Exception:
            _log.exception("Mise à jour de la base de géolocalisation impossible")
        time.sleep(24 * 3600)


def start_background_update(app) -> None:
    """Lance (une fois par processus) le téléchargement puis la vérification quotidienne."""
    global _started
    if _started or not enabled() or app.config.get("TESTING"):
        return
    _started = True

    def run():
        with app.app_context():
            _keep_updated()

    threading.Thread(target=run, name="geoip-update", daemon=True).start()


def _get_reader():
    global _reader, _reader_mtime
    path = db_path()
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None
    with _lock:
        if _reader is None or mtime != _reader_mtime:
            import maxminddb
            old = _reader
            _reader = maxminddb.open_database(path, mode=maxminddb.MODE_MMAP)
            _reader_mtime = mtime
            _lookup.cache_clear()
            if old is not None:
                try:
                    old.close()
                except Exception:
                    pass
            _status.update(state="ok")
        return _reader


def _name(node) -> str:
    names = (node or {}).get("names") or {}
    return str(names.get("fr") or names.get("en") or "")


@lru_cache(maxsize=4096)
def _lookup(ip: str):
    reader = _get_reader()
    if reader is None:
        return None
    record = reader.get(ip) or {}
    location = record.get("location") or {}
    subdivisions = record.get("subdivisions") or [{}]
    return {
        "city": _name(record.get("city"))[:60],
        "region": _name(subdivisions[0])[:60],
        "country": str((record.get("country") or {}).get("iso_code") or "")[:2].upper(),
        "lat": location.get("latitude"),
        "lon": location.get("longitude"),
    }


def locate(ip: str) -> dict | None:
    """Ville, région, pays, latitude, longitude d'une IP publique ; None si inconnu ou base absente."""
    if not enabled() or not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_reserved:
            return None
        return _lookup(str(addr))
    except Exception:
        return None


def status() -> dict:
    path = db_path()
    info = dict(_status)
    if os.path.isfile(path):
        info["size_mb"] = round(os.path.getsize(path) / (1024 * 1024))
        info["updated"] = time.strftime("%d/%m/%Y", time.localtime(os.path.getmtime(path)))
        if info["state"] == "absent":
            info["state"] = "ok"
    info["enabled"] = enabled()
    return info
