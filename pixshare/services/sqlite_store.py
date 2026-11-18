"""Stockage SQLite de PixShare (fichier pixshare.db sur le disque persistant).

Sécurité :
- Aucune donnée venant d'un visiteur n'est jamais collée dans le texte d'une requête SQL :
  toutes les valeurs passent par des paramètres « ? » (le moteur les traite comme des données,
  jamais comme du code). Les noms de tables sont des constantes écrites ici, rien d'autre.
- Les données sont rangées en JSON (texte) et relues avec json.loads : pas de pickle, rien d'exécutable.
- Le fichier n'est lisible que par le serveur (droits 600) et n'est jamais servi par le site.
- Pas de serveur de base de données ni de port ouvert : seulement un fichier.

Fiabilité :
- Mode WAL : lectures et écriture en même temps sans bloquer ni abîmer le fichier.
- Chaque écriture est une transaction : elle a lieu en entier ou pas du tout (même si le serveur s'arrête).
- La liste des fichiers est rangée ligne par ligne : enregistrer un fichier n'écrase plus les
  changements faits au même moment sur un autre fichier (par un autre worker).

Migration : au premier accès, un ancien fichier JSON est importé puis renommé « .json.migre »
(gardé comme copie de secours).
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading

_log = logging.getLogger(__name__)
DB_NAME = "pixshare.db"
FILES_DOC = "files.json"  # rangé ligne par ligne dans la table `files`
_local = threading.local()
_init_lock = threading.Lock()
_ready: set[str] = set()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    name TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL
);
"""


def db_path(data_dir: str) -> str:
    return os.path.join(data_dir, DB_NAME)


def _connect(path: str) -> sqlite3.Connection:
    cache = getattr(_local, "conns", None)
    if cache is None or getattr(_local, "pid", None) != os.getpid():
        cache = _local.conns = {}  # nouveau processus (fork) : jamais de connexion héritée
        _local.pid = os.getpid()
    conn = cache.get(path)
    if conn is not None:
        return conn
    new_file = not os.path.exists(path)
    conn = sqlite3.connect(path, timeout=15, isolation_level=None)  # transactions gérées à la main
    conn.execute("PRAGMA busy_timeout = 15000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA trusted_schema = OFF")  # pas de fonctions SQL lancées depuis le schéma
    if path not in _ready:
        with _init_lock:
            conn.executescript(_SCHEMA)
            _ready.add(path)
    if new_file:
        for suffix in ("", "-wal", "-shm"):
            try:
                os.chmod(path + suffix, 0o600)
            except OSError:
                pass
    cache[path] = conn
    return conn


class _Tx:
    """Transaction d'écriture : BEGIN IMMEDIATE … COMMIT, ou ROLLBACK si une erreur survient."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def __enter__(self):
        self.conn.execute("BEGIN IMMEDIATE")
        return self.conn

    def __exit__(self, exc_type, exc, tb):
        self.conn.execute("ROLLBACK" if exc_type else "COMMIT")
        return False


def _dump(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


# ------------------------------------------------------------------ migration des anciens JSON

def _legacy_json(data_dir: str, name: str):
    """Contenu d'un ancien fichier JSON (ou None s'il n'existe pas / est illisible)."""
    path = os.path.join(data_dir, os.path.basename(name))
    if not os.path.isfile(path):
        return None, path
    try:
        with open(path, "r", encoding="utf-8") as handle:
            content = handle.read().strip()
        return (json.loads(content) if content else None), path
    except (OSError, ValueError):
        _log.error("Ancien fichier %s illisible : gardé tel quel, non importé", path)
        return None, path


def _retire(path: str) -> None:
    try:
        os.replace(path, path + ".migre")
    except OSError:
        pass


def _migrate_document(conn, data_dir: str, name: str) -> None:
    value, path = _legacy_json(data_dir, name)
    if value is None:
        return
    with _Tx(conn) as c:
        exists = c.execute("SELECT 1 FROM documents WHERE name = ?", (name,)).fetchone()
        if not exists:
            c.execute("INSERT INTO documents (name, data) VALUES (?, ?)", (name, _dump(value)))
    _retire(path)
    _log.info("%s importé dans la base SQLite", name)


def _migrate_files(conn, data_dir: str) -> None:
    value, path = _legacy_json(data_dir, FILES_DOC)
    if value is None:
        return
    if isinstance(value, dict):
        with _Tx(conn) as c:
            if not c.execute("SELECT 1 FROM files LIMIT 1").fetchone():
                c.executemany("INSERT OR IGNORE INTO files (id, data) VALUES (?, ?)",
                              [(str(k), _dump(v)) for k, v in value.items() if isinstance(v, dict)])
    _retire(path)
    _log.info("files.json importé dans la base SQLite (%s fichiers)", len(value) if isinstance(value, dict) else 0)


# ------------------------------------------------------------------ documents (réglages, comptes, stats…)

def read_document(data_dir: str, name: str, default):
    conn = _connect(db_path(data_dir))
    row = conn.execute("SELECT data FROM documents WHERE name = ?", (name,)).fetchone()
    if row is None:
        _migrate_document(conn, data_dir, name)
        row = conn.execute("SELECT data FROM documents WHERE name = ?", (name,)).fetchone()
    if row is None:
        return default
    try:
        data = json.loads(row[0])
    except ValueError:
        _log.error("Document %s illisible dans la base : valeur par défaut", name)
        return default
    if isinstance(default, list) and not isinstance(data, list):
        return default
    if isinstance(default, dict) and not isinstance(data, dict):
        return default
    return data


def write_document(data_dir: str, name: str, data) -> None:
    conn = _connect(db_path(data_dir))
    text = _dump(data)
    with _Tx(conn) as c:
        c.execute(
            "INSERT INTO documents (name, data, updated_at) VALUES (?, ?, datetime('now')) "
            "ON CONFLICT(name) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
            (name, text),
        )


def delete_document(data_dir: str, name: str) -> None:
    conn = _connect(db_path(data_dir))
    with _Tx(conn) as c:
        c.execute("DELETE FROM documents WHERE name = ?", (name,))


def document_exists(data_dir: str, name: str) -> bool:
    conn = _connect(db_path(data_dir))
    if conn.execute("SELECT 1 FROM documents WHERE name = ?", (name,)).fetchone():
        return True
    return os.path.isfile(os.path.join(data_dir, os.path.basename(name)))


# ------------------------------------------------------------------ liste des fichiers (ligne par ligne)

class FilesDict(dict):
    """dict des fichiers qui se souvient de l'état lu, pour n'écrire ensuite que ce qui a changé."""

    __slots__ = ("snapshot",)


def read_files(data_dir: str) -> FilesDict:
    conn = _connect(db_path(data_dir))
    _migrate_files(conn, data_dir)
    result = FilesDict()
    snapshot = {}
    for file_id, text in conn.execute("SELECT id, data FROM files"):
        try:
            value = json.loads(text)
        except ValueError:
            _log.error("Fiche %s illisible dans la base : ignorée", file_id)
            continue
        if isinstance(value, dict):
            result[file_id] = value
            snapshot[file_id] = text
    result.snapshot = snapshot
    return result


def write_files(data_dir: str, data: dict) -> None:
    """Enregistre la liste des fichiers.

    Si `data` vient de read_files : seules les fiches modifiées, ajoutées ou retirées depuis la lecture
    sont écrites (un autre worker peut modifier d'autres fiches en même temps sans rien perdre).
    Sinon (dict construit à la main) : la table est remplacée par `data`.
    """
    conn = _connect(db_path(data_dir))
    rows = {str(k): _dump(v) for k, v in data.items() if isinstance(v, dict)}
    snapshot = getattr(data, "snapshot", None)
    with _Tx(conn) as c:
        if snapshot is None:
            c.execute("DELETE FROM files")
            c.executemany("INSERT INTO files (id, data) VALUES (?, ?)", list(rows.items()))
            return
        changed = [(k, v) for k, v in rows.items() if snapshot.get(k) != v]
        removed = [(k,) for k in snapshot if k not in rows]
        if changed:
            c.executemany(
                "INSERT INTO files (id, data) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data",
                changed,
            )
        if removed:
            c.executemany("DELETE FROM files WHERE id = ?", removed)
    data.snapshot = rows  # un 2e enregistrement du même dict n'écrit que les nouveaux changements


# ------------------------------------------------------------------ état, sauvegarde

def status(data_dir: str) -> dict:
    path = db_path(data_dir)
    conn = _connect(path)
    try:
        check = conn.execute("PRAGMA quick_check").fetchone()[0]
    except sqlite3.DatabaseError as exc:
        check = f"erreur : {exc}"
    size = sum(os.path.getsize(path + s) for s in ("", "-wal") if os.path.exists(path + s))
    return {
        "path": path,
        "ok": check == "ok",
        "check": check,
        "size": size,
        "files": conn.execute("SELECT COUNT(*) FROM files").fetchone()[0],
        "documents": conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
        "journal": conn.execute("PRAGMA journal_mode").fetchone()[0],
    }


def backup_to(data_dir: str, target: str) -> None:
    """Copie cohérente de la base (même pendant que le site tourne), via l'outil de sauvegarde de SQLite."""
    source = _connect(db_path(data_dir))
    dest = sqlite3.connect(target)
    try:
        source.backup(dest)
    finally:
        dest.close()
