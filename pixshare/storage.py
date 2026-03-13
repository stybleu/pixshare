import json
import os
from flask import Flask


def project_root(app: Flask) -> str:
    return os.path.dirname(app.root_path)


def project_path(app: Flask, relative_path: str) -> str:
    return os.path.join(project_root(app), relative_path)


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def atomic_write_json(path: str, data) -> None:
    ensure_parent_dir(path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def read_json_file(path: str, default):
    ensure_parent_dir(path)
    if not os.path.isfile(path):
        atomic_write_json(path, default)
        return default.copy() if isinstance(default, (dict, list)) else default

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return default.copy() if isinstance(default, (dict, list)) else default

    if isinstance(default, dict) and isinstance(data, dict):
        return data
    if isinstance(default, list) and isinstance(data, list):
        return data
    return default.copy() if isinstance(default, (dict, list)) else default


def db_path(app: Flask) -> str:
    return project_path(app, app.config["DB_FILE"])


def blocked_path(app: Flask) -> str:
    return project_path(app, app.config["BLOCKED_FILE"])


def failed_logins_path(app: Flask) -> str:
    return project_path(app, app.config["FAILED_LOGINS_FILE"])


def views_path(app: Flask) -> str:
    return project_path(app, app.config["VIEWS_FILE"])


def contacts_path(app: Flask) -> str:
    return project_path(app, app.config["CONTACTS_FILE"])


def init_storage(app: Flask) -> None:
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    for path, default in [
        (db_path(app), {}),
        (blocked_path(app), []),
        (failed_logins_path(app), {}),
        (views_path(app), {}),
        (contacts_path(app), []),
    ]:
        ensure_parent_dir(path)
        if not os.path.exists(path):
            atomic_write_json(path, default)
