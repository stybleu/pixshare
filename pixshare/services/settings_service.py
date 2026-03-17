from __future__ import annotations

import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
SETTINGS_FILE = DATA_DIR / "settings.json"

DEFAULT_SETTINGS = {
    "max_upload_size_mb": 100,
    "allow_permanent_files": True,
    "default_lifetime_minutes": 10,
}


ALLOWED_LIFETIMES = {5, 10, 20, 30, 60, 120}


def ensure_settings_file() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not SETTINGS_FILE.exists():
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_SETTINGS, f, ensure_ascii=False, indent=2)


def load_settings() -> dict:
    ensure_settings_file()
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return DEFAULT_SETTINGS.copy()

    if not isinstance(data, dict):
        return DEFAULT_SETTINGS.copy()

    settings = DEFAULT_SETTINGS.copy()
    settings.update(data)
    settings["max_upload_size_mb"] = get_valid_max_upload_size_mb(settings.get("max_upload_size_mb"))
    settings["allow_permanent_files"] = bool(settings.get("allow_permanent_files", True))
    settings["default_lifetime_minutes"] = get_valid_lifetime(settings.get("default_lifetime_minutes"))
    return settings


def save_settings(settings: dict) -> dict:
    ensure_settings_file()

    clean_settings = {
        "max_upload_size_mb": get_valid_max_upload_size_mb(settings.get("max_upload_size_mb")),
        "allow_permanent_files": bool(settings.get("allow_permanent_files", True)),
        "default_lifetime_minutes": get_valid_lifetime(settings.get("default_lifetime_minutes")),
    }

    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(clean_settings, f, ensure_ascii=False, indent=2)

    return clean_settings


def get_valid_max_upload_size_mb(value) -> int:
    try:
        value = int(value)
    except (TypeError, ValueError):
        value = DEFAULT_SETTINGS["max_upload_size_mb"]
    return max(1, min(value, 500))


def get_valid_lifetime(value) -> int:
    try:
        value = int(value)
    except (TypeError, ValueError):
        return DEFAULT_SETTINGS["default_lifetime_minutes"]

    if value not in ALLOWED_LIFETIMES:
        return DEFAULT_SETTINGS["default_lifetime_minutes"]
    return value


def get_default_lifetime() -> int:
    return int(load_settings().get("default_lifetime_minutes", DEFAULT_SETTINGS["default_lifetime_minutes"]))


def get_max_upload_size_mb() -> int:
    return int(load_settings().get("max_upload_size_mb", DEFAULT_SETTINGS["max_upload_size_mb"]))


def get_max_upload_size_bytes() -> int:
    return get_max_upload_size_mb() * 1024 * 1024


def permanent_files_enabled() -> bool:
    return bool(load_settings().get("allow_permanent_files", True))
