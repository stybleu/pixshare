"""Sauvegarde de secours sur Cloudflare R2 (stockage compatible S3).

Chaque nuit (au premier passage après 3 h, heure de Paris) :
- une copie propre de la base SQLite, compressée, rangée dans « base/ » (les 7 dernières sont gardées) ;
- les fichiers des visiteurs (originaux seulement), rangés dans « fichiers/ » : seuls les nouveaux ou
  les remplacés partent ; ceux qui n'existent plus sur le site (expirés, supprimés, retirés par la
  modération) sont effacés de la sauvegarde aussi.

Les clés viennent uniquement des variables d'environnement de Render (jamais du code ni de l'admin) :
R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET.

Aucune bibliothèque en plus : les requêtes sont signées ici (signature AWS v4, exigée par R2).
"""
from __future__ import annotations

import gzip
import hashlib
import hmac
import logging
import os
import shutil
import sqlite3
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

from flask import current_app

from .time_service import parse_dt, utcnow

_log = logging.getLogger(__name__)
STATE_DOC = "backup_state.json"
DB_PREFIX = "base/"
FILES_PREFIX = "fichiers/"
KEEP_DB_COPIES = 7
NIGHT_HOUR = 3            # heure de Paris à partir de laquelle la sauvegarde de la nuit se lance
_thread_lock = threading.Lock()


class BackupError(Exception):
    pass


# ------------------------------------------------------------------ réglages

def r2_config() -> dict | None:
    cfg = {k: (os.environ.get(v) or "").strip() for k, v in (
        ("account", "R2_ACCOUNT_ID"), ("key", "R2_ACCESS_KEY_ID"),
        ("secret", "R2_SECRET_ACCESS_KEY"), ("bucket", "R2_BUCKET"))}
    return cfg if all(cfg.values()) else None


def is_configured() -> bool:
    return r2_config() is not None


# ------------------------------------------------------------------ signature AWS v4

def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _quote(value: str, safe: str = "-_.~") -> str:
    return urllib.parse.quote(value, safe=safe)


def sign(method: str, host: str, path: str, query: dict, headers: dict, payload_hash: str,
         access_key: str, secret_key: str, region: str, amz_date: str, service: str = "s3") -> str:
    """En-tête Authorization (AWS Signature Version 4). ``headers`` : en-têtes à signer (sans host)."""
    all_headers = {k.lower(): str(v).strip() for k, v in headers.items()}
    all_headers["host"] = host
    signed = ";".join(sorted(all_headers))
    canonical_headers = "".join(f"{k}:{all_headers[k]}\n" for k in sorted(all_headers))
    canonical_query = "&".join(f"{_quote(k)}={_quote(str(v))}" for k, v in sorted(query.items()))
    canonical = "\n".join([method, _quote(path, safe="/-_.~"), canonical_query, canonical_headers, signed, payload_hash])
    day = amz_date[:8]
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = _hmac(_hmac(_hmac(_hmac(("AWS4" + secret_key).encode(), day), region), service), "aws4_request")
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    return f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}"


EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class R2Client:
    """Le strict nécessaire : envoyer, lire, lister, effacer."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.host = f"{cfg['account']}.r2.cloudflarestorage.com"

    def _request(self, method: str, key: str = "", query: dict | None = None, body=None,
                 payload_hash: str = EMPTY_SHA256, length: int | None = None):
        query = query or {}
        path = f"/{self.cfg['bucket']}/{key}" if key else f"/{self.cfg['bucket']}"
        amz_date = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        headers = {"x-amz-content-sha256": payload_hash, "x-amz-date": amz_date}
        auth = sign(method, self.host, path, query, headers, payload_hash,
                    self.cfg["key"], self.cfg["secret"], "auto", amz_date)
        url = f"https://{self.host}{_quote(path, safe='/-_.~')}"
        if query:
            url += "?" + "&".join(f"{_quote(k)}={_quote(str(v))}" for k, v in sorted(query.items()))
        req = urllib.request.Request(url, data=body, method=method, headers={**headers, "Authorization": auth})
        if body is not None:
            req.add_header("Content-Type", "application/octet-stream")
        if length is not None:
            req.add_header("Content-Length", str(length))
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.read() if method == "GET" else b""
        except urllib.error.HTTPError as exc:
            if method == "DELETE" and exc.code == 404:
                return b""
            detail = exc.read()[:300].decode("utf-8", "replace")
            raise BackupError(f"R2 a répondu {exc.code} ({method}) : {detail}") from None
        except urllib.error.URLError as exc:
            raise BackupError(f"R2 injoignable : {exc.reason}") from None

    def put_file(self, key: str, path: str) -> None:
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                sha.update(chunk)
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            self._request("PUT", key, body=f, payload_hash=sha.hexdigest(), length=size)

    def get_to_file(self, key: str, path: str) -> None:
        data = self._request("GET", key)
        with open(path, "wb") as f:
            f.write(data)

    def delete(self, key: str) -> None:
        self._request("DELETE", key)

    def list(self, prefix: str) -> dict[str, dict]:
        """{clé: {"size": …, "etag": …}} pour tout ce qui commence par ``prefix``."""
        out, token = {}, None
        while True:
            query = {"list-type": "2", "prefix": prefix}
            if token:
                query["continuation-token"] = token
            root = ET.fromstring(self._request("GET", "", query=query))
            ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
            for item in root.findall(f"{ns}Contents"):
                out[item.findtext(f"{ns}Key")] = {
                    "size": int(item.findtext(f"{ns}Size") or 0),
                    "etag": (item.findtext(f"{ns}ETag") or "").strip('"'),
                }
            if (root.findtext(f"{ns}IsTruncated") or "").lower() != "true":
                return out
            token = root.findtext(f"{ns}NextContinuationToken")


def get_client() -> R2Client:
    cfg = r2_config()
    if not cfg:
        raise BackupError("Sauvegarde non configurée (variables R2_* manquantes sur Render).")
    return R2Client(cfg)


# ------------------------------------------------------------------ état (dans la base)

def load_state() -> dict:
    """État de la sauvegarde. Un « en cours » de plus de 2 heures vient d'un redémarrage : il est ignoré."""
    from .json_services import load_json
    state = load_json(STATE_DOC, {})
    state = state if isinstance(state, dict) else {}
    for key in ("running_since", "restoring_since"):
        try:
            if state.get(key) and utcnow() - parse_dt(state[key]) > timedelta(hours=2):
                state[key] = ""
        except Exception:
            state[key] = ""
    return state


def _save_state(**changes) -> dict:
    from .json_services import load_json, save_json
    state = load_json(STATE_DOC, {})
    state = state if isinstance(state, dict) else {}
    state.update(changes)
    save_json(STATE_DOC, state)
    return state


# ------------------------------------------------------------------ sauvegarde

def _md5(path: str) -> str:
    h = hashlib.md5(usedforsecurity=False)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _live_files() -> dict[str, str]:
    """{nom: chemin} des fichiers encore en ligne (en attente de vérification comprise)."""
    from .json_services import load_db
    folder = current_app.config["UPLOAD_FOLDER"]
    out = {}
    for meta in load_db().values():
        if not isinstance(meta, dict) or (meta.get("status") or "active").lower() not in ("active", "pending"):
            continue
        name = os.path.basename(str(meta.get("server_name") or ""))
        path = os.path.join(folder, name)
        if name and os.path.isfile(path):
            out[name] = path
    return out


def _backup_database(client: R2Client) -> int:
    from . import sqlite_store
    from .json_services import _get_data_dir, use_sqlite
    if not use_sqlite():
        raise BackupError("La sauvegarde de la base demande le stockage SQLite.")
    tmpdir = tempfile.mkdtemp(prefix="pixshare-sauvegarde-")
    try:
        raw = os.path.join(tmpdir, "pixshare.db")
        sqlite_store.backup_to(_get_data_dir(), raw)
        packed = raw + ".gz"
        with open(raw, "rb") as src, gzip.open(packed, "wb", compresslevel=6) as dst:
            shutil.copyfileobj(src, dst)
        key = f"{DB_PREFIX}pixshare-{utcnow().strftime('%Y-%m-%d-%H%M')}.db.gz"
        client.put_file(key, packed)
        size = os.path.getsize(packed)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    copies = sorted(client.list(DB_PREFIX))
    for old in copies[:-KEEP_DB_COPIES]:
        client.delete(old)
    return size


def run_backup(client: R2Client | None = None) -> dict:
    """Sauvegarde complète (base + fichiers). Renvoie un petit résumé ; lève BackupError en cas d'échec."""
    client = client or get_client()
    started = utcnow()
    db_size = _backup_database(client)
    remote = client.list(FILES_PREFIX)
    state = load_state()
    md5_cache = state.get("md5") if isinstance(state.get("md5"), dict) else {}
    new_cache, sent, sent_bytes = {}, 0, 0
    live = _live_files()
    for name, path in live.items():
        st = os.stat(path)
        sig = f"{st.st_size}:{int(st.st_mtime)}"
        cached = md5_cache.get(name) or {}
        digest = cached.get("md5") if cached.get("sig") == sig else _md5(path)
        new_cache[name] = {"sig": sig, "md5": digest}
        have = remote.get(FILES_PREFIX + name)
        if have and have["etag"] == digest:
            continue
        client.put_file(FILES_PREFIX + name, path)
        sent += 1
        sent_bytes += st.st_size
    removed = 0
    for key in remote:
        if key[len(FILES_PREFIX):] not in live:
            client.delete(key)
            removed += 1
    summary = {"at": utcnow().isoformat(timespec="seconds"), "files": len(live), "sent": sent,
               "sent_mb": round(sent_bytes / 1048576, 1), "removed": removed,
               "db_kb": round(db_size / 1024), "seconds": int((utcnow() - started).total_seconds())}
    _save_state(md5=new_cache, last_success=summary["at"], last_summary=summary, last_error="", last_error_at="")
    return summary


def _run_logged(app, manual: bool = False) -> None:
    if not _thread_lock.acquire(blocking=False):
        return
    lock_file = None
    try:
        with app.app_context():
            from .json_services import _get_data_dir
            try:
                import fcntl
                lock_file = open(os.path.join(_get_data_dir(), ".sauvegarde.lock"), "w")
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)  # un seul worker à la fois
            except OSError:
                return
            except ImportError:  # pragma: no cover - Windows
                pass
            _save_state(running_since=utcnow().isoformat(timespec="seconds"))
            try:
                run_backup()
            except Exception as exc:
                _log.exception("Sauvegarde R2 échouée")
                _save_state(last_error=str(exc)[:300], last_error_at=utcnow().isoformat(timespec="seconds"))
            finally:
                _save_state(running_since="", last_attempt=utcnow().isoformat(timespec="seconds"))
    finally:
        if lock_file:
            lock_file.close()
        _thread_lock.release()


def start_backup(app, manual: bool = False) -> bool:
    """Lance la sauvegarde dans un fil à part (elle ne bloque jamais une page)."""
    if not is_configured() or _thread_lock.locked():
        return False
    threading.Thread(target=_run_logged, args=(app, manual), daemon=True, name="sauvegarde-r2").start()
    return True


def _last_night_start(now: datetime) -> datetime:
    """Le dernier « 3 h du matin, heure de Paris » passé (heure d'été comprise)."""
    try:
        from zoneinfo import ZoneInfo
        paris = ZoneInfo("Europe/Paris")
    except Exception:  # pragma: no cover
        paris = timezone(timedelta(hours=1))
    local = now.astimezone(paris)
    start = local.replace(hour=NIGHT_HOUR, minute=0, second=0, microsecond=0)
    if local < start:
        start = (local - timedelta(days=1)).replace(hour=NIGHT_HOUR, minute=0, second=0, microsecond=0)
    return start


def backup_due(now: datetime | None = None) -> bool:
    """Une sauvegarde automatique par nuit : due si la dernière tentative date d'avant le dernier 3 h (Paris)."""
    if not is_configured():
        return False
    now = now or utcnow()
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    last = load_state().get("last_attempt") or ""
    if not last:
        return True  # jamais sauvegardé : tout de suite
    try:
        last_dt = parse_dt(last)
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=timezone.utc)
    except Exception:
        return True
    return last_dt < _last_night_start(now)


_last_check: float | None = None


def should_check(every_seconds: int = 600) -> bool:
    """Vrai au plus une fois toutes les 10 minutes par processus (et seulement si R2 est configuré)."""
    global _last_check
    import time
    if not is_configured() or (_last_check is not None and time.monotonic() - _last_check < every_seconds):
        return False
    _last_check = time.monotonic()
    return True


def maybe_nightly_backup(app) -> None:
    try:
        with app.app_context():
            due = backup_due()
        if due:
            start_backup(app)
    except Exception:  # pragma: no cover
        _log.exception("Vérification de la sauvegarde impossible")


# ------------------------------------------------------------------ restauration

def list_db_copies(client: R2Client | None = None) -> list[str]:
    client = client or get_client()
    return sorted(client.list(DB_PREFIX), reverse=True)


def restore(client: R2Client | None = None, db_key: str | None = None) -> dict:
    """Remet la base (la copie choisie, ou la plus récente) puis les fichiers absents du disque.

    Avant d'écraser quoi que ce soit, la base actuelle est copiée à côté (pixshare-avant-restauration.db).
    """
    from . import sqlite_store
    from .file_service import create_medium, create_thumbnail, is_image_extension
    from .json_services import _get_data_dir, load_db

    client = client or get_client()
    copies = list_db_copies(client)
    if not copies:
        raise BackupError("Aucune copie de la base dans R2.")
    key = db_key if db_key in copies else copies[0]
    data_dir = _get_data_dir()
    tmpdir = tempfile.mkdtemp(prefix="pixshare-restauration-")
    try:
        packed = os.path.join(tmpdir, "copie.db.gz")
        client.get_to_file(key, packed)
        raw = os.path.join(tmpdir, "copie.db")
        with gzip.open(packed, "rb") as src, open(raw, "wb") as dst:
            shutil.copyfileobj(src, dst)
        check = sqlite3.connect(raw)
        try:
            if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise BackupError("La copie téléchargée est abîmée : rien n'a été changé.")
            for table in ("documents", "files"):
                check.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608 - noms écrits ici
        except sqlite3.DatabaseError as exc:
            raise BackupError(f"La copie téléchargée n'est pas une base PixShare : {exc}") from None
        sqlite_store.backup_to(data_dir, os.path.join(data_dir, "pixshare-avant-restauration.db"))
        live = sqlite_store._connect(sqlite_store.db_path(data_dir))
        try:
            check.backup(live)  # remplace le contenu de la base en une fois
        finally:
            check.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    folder = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(folder, exist_ok=True)
    wanted = {os.path.basename(str(m.get("server_name") or "")): fid for fid, m in load_db().items()
              if isinstance(m, dict) and (m.get("status") or "active").lower() in ("active", "pending")}
    fetched = 0
    for remote_key in client.list(FILES_PREFIX):
        name = os.path.basename(remote_key)
        if not name or name not in wanted or os.path.isfile(os.path.join(folder, name)):
            continue
        dest = os.path.join(folder, name)
        client.get_to_file(remote_key, dest + ".part")
        os.replace(dest + ".part", dest)
        fetched += 1
        if is_image_extension(os.path.splitext(name)[1].lower()):
            try:
                create_thumbnail(dest, wanted[name])
                create_medium(dest, wanted[name])
            except Exception:
                pass
    _save_state(md5={}, last_restore=utcnow().isoformat(timespec="seconds"), last_restore_key=key)
    return {"db": key, "files": fetched}


def _restore_logged(app, db_key: str | None) -> None:
    try:
        with app.app_context():
            _save_state(restoring_since=utcnow().isoformat(timespec="seconds"), restore_error="")
            try:
                result = restore(db_key=db_key)
                _save_state(last_restore_result=result)
            except Exception as exc:
                _log.exception("Restauration R2 échouée")
                _save_state(restore_error=str(exc)[:300])
            finally:  # la copie restaurée date d'une sauvegarde en cours : on remet l'état à plat
                _save_state(restoring_since="", running_since="")
    finally:
        _thread_lock.release()


def start_restore(app, db_key: str | None = None) -> bool:
    """Restauration dans un fil à part (peut durer quelques minutes). Jamais en même temps qu'une sauvegarde."""
    if not is_configured() or not _thread_lock.acquire(blocking=False):
        return False
    threading.Thread(target=_restore_logged, args=(app, db_key), daemon=True, name="restauration-r2").start()
    return True
