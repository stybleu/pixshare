from __future__ import annotations

from pixshare.services.json_services import json_exists, load_json, save_json

SETTINGS_FILENAME = "settings.json"

DEFAULT_SETTINGS = {
    "upload_service_enabled": True,
    "max_upload_size_mb": 100,
    "allow_permanent_files": True,
    "default_lifetime_minutes": 10,
    "thumbnail_retention_hours": 24,
    "keep_thumbnails": True,
}

ALLOWED_LIFETIMES = {5, 10, 20, 30, 60, 120, 360, 720, 1440, 2880, 4320, 10080}


def ensure_settings_file() -> None:
    if not json_exists(SETTINGS_FILENAME):
        save_json(SETTINGS_FILENAME, DEFAULT_SETTINGS)


def load_settings() -> dict:
    ensure_settings_file()
    data = load_json(SETTINGS_FILENAME, {})

    if not isinstance(data, dict):
        return DEFAULT_SETTINGS.copy()

    settings = DEFAULT_SETTINGS.copy()
    settings.update(data)
    settings["upload_service_enabled"] = bool(settings.get("upload_service_enabled", True))
    settings["max_upload_size_mb"] = get_valid_max_upload_size_mb(settings.get("max_upload_size_mb"))
    settings["allow_permanent_files"] = bool(settings.get("allow_permanent_files", True))
    settings["default_lifetime_minutes"] = get_valid_lifetime(settings.get("default_lifetime_minutes"))
    settings["thumbnail_retention_hours"] = get_valid_thumbnail_retention_hours(settings.get("thumbnail_retention_hours"))
    settings["keep_thumbnails"] = bool(settings.get("keep_thumbnails", True))
    return settings


def save_settings(settings: dict) -> dict:
    ensure_settings_file()

    clean_settings = {
        "upload_service_enabled": bool(settings.get("upload_service_enabled", True)),
        "max_upload_size_mb": get_valid_max_upload_size_mb(settings.get("max_upload_size_mb")),
        "allow_permanent_files": bool(settings.get("allow_permanent_files", True)),
        "default_lifetime_minutes": get_valid_lifetime(settings.get("default_lifetime_minutes")),
        "thumbnail_retention_hours": get_valid_thumbnail_retention_hours(settings.get("thumbnail_retention_hours")),
        "keep_thumbnails": bool(settings.get("keep_thumbnails", True)),
    }

    save_json(SETTINGS_FILENAME, clean_settings)

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


def get_valid_thumbnail_retention_hours(value) -> int:
    try:
        value = int(value)
    except (TypeError, ValueError):
        value = DEFAULT_SETTINGS["thumbnail_retention_hours"]
    return max(0, min(value, 48))


def upload_service_enabled() -> bool:
    return bool(load_settings().get("upload_service_enabled", True))


def get_default_lifetime() -> int:
    return int(load_settings().get("default_lifetime_minutes", DEFAULT_SETTINGS["default_lifetime_minutes"]))


def get_max_upload_size_mb() -> int:
    return int(load_settings().get("max_upload_size_mb", DEFAULT_SETTINGS["max_upload_size_mb"]))


def get_max_upload_size_bytes() -> int:
    return get_max_upload_size_mb() * 1024 * 1024


def permanent_files_enabled() -> bool:
    return bool(load_settings().get("allow_permanent_files", True))


def get_thumbnail_retention_hours() -> int:
    return int(load_settings().get("thumbnail_retention_hours", DEFAULT_SETTINGS["thumbnail_retention_hours"]))


def thumbnails_enabled() -> bool:
    return bool(load_settings().get("keep_thumbnails", DEFAULT_SETTINGS["keep_thumbnails"]))
