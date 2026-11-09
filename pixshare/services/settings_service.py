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
    # Modération NudeNet. None = valeur de l'environnement (NSFW_*), tant que l'admin n'a rien enregistré.
    "nsfw_auto_moderation": None,
    "nsfw_review_threshold": None,
    "nsfw_block_threshold": None,
    "nsfw_tiling": True,
}

NSFW_MIN_THRESHOLD = 0.05
NSFW_MAX_THRESHOLD = 1.0

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
    settings.update(_clean_nsfw_settings(settings))
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

    # Les réglages NudeNet absents de `settings` (autre formulaire) gardent leur valeur actuelle.
    current = load_settings()
    nsfw_source = {key: settings.get(key, current.get(key)) for key in NSFW_KEYS}
    clean_settings.update(_clean_nsfw_settings(nsfw_source))

    save_json(SETTINGS_FILENAME, clean_settings)

    return clean_settings


NSFW_KEYS = ("nsfw_auto_moderation", "nsfw_review_threshold", "nsfw_block_threshold", "nsfw_tiling")


def get_valid_nsfw_threshold(value):
    """Seuil NudeNet entre 0,05 et 1 (arrondi à 2 décimales) ; None si absent ou invalide."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(str(value).strip().replace(",", "."))
    except (TypeError, ValueError):
        return None
    if number != number or number < NSFW_MIN_THRESHOLD or number > NSFW_MAX_THRESHOLD:
        return None
    return round(number, 2)


def _clean_nsfw_settings(source: dict) -> dict:
    enabled = source.get("nsfw_auto_moderation")
    return {
        "nsfw_auto_moderation": None if enabled is None else bool(enabled),
        "nsfw_review_threshold": get_valid_nsfw_threshold(source.get("nsfw_review_threshold")),
        "nsfw_block_threshold": get_valid_nsfw_threshold(source.get("nsfw_block_threshold")),
        "nsfw_tiling": bool(source.get("nsfw_tiling", True)),
    }


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
