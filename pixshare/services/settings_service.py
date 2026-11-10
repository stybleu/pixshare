from __future__ import annotations

from pixshare.services.json_services import json_exists, load_json, save_json
from pixshare.services.theme_service import clean_choice

SETTINGS_FILENAME = "settings.json"

DEFAULT_SETTINGS = {
    "upload_service_enabled": True,
    "max_upload_size_mb": 100,
    "allow_permanent_files": True,
    "default_lifetime_minutes": 10,
    # Durée maximale proposée aux visiteurs. None = variable MAX_LIFETIME_MIN (7 jours par défaut).
    "max_lifetime_minutes": None,
    # Lien « Soutenir PixShare » (Ko-fi...). "" = variable SUPPORT_URL, sinon pas de bouton.
    "support_url": "",
    "thumbnail_retention_hours": 24,
    "keep_thumbnails": True,
    # Modération NudeNet. None = valeur de l'environnement (NSFW_*), tant que l'admin n'a rien enregistré.
    "nsfw_auto_moderation": None,
    "nsfw_review_threshold": None,
    "nsfw_block_threshold": None,
    "nsfw_tiling": True,
    "nsfw_classes": None,
    # Thème de saison : "" = variable SEASON_THEME ou automatique (voir theme_service).
    "season_theme": "",
    # Ciel selon l'heure : None = variable SKY_THEME (activé par défaut).
    "sky_enabled": None,
}

NSFW_MIN_THRESHOLD = 0.05
NSFW_MAX_THRESHOLD = 1.0

# Parties du corps que NudeNet sait reconnaître et que l'admin peut surveiller : (nom NudeNet, libellé).
# NudeNet ne reconnaît pas les cuisses.
NSFW_CLASS_GROUPS = (
    ("Zones intimes exposées", (
        ("FEMALE_BREAST_EXPOSED", "Poitrine de femme"),
        ("FEMALE_GENITALIA_EXPOSED", "Parties génitales de femme"),
        ("MALE_GENITALIA_EXPOSED", "Parties génitales d'homme"),
        ("BUTTOCKS_EXPOSED", "Fesses"),
        ("ANUS_EXPOSED", "Anus"),
    )),
    ("Zones intimes couvertes (sous-vêtements, tissu)", (
        ("FEMALE_BREAST_COVERED", "Poitrine de femme couverte"),
        ("FEMALE_GENITALIA_COVERED", "Parties génitales de femme couvertes"),
        ("BUTTOCKS_COVERED", "Fesses couvertes"),
        ("ANUS_COVERED", "Anus couvert"),
    )),
    ("Autres zones", (
        ("MALE_BREAST_EXPOSED", "Torse d'homme nu"),
        ("BELLY_EXPOSED", "Ventre"),
        ("ARMPITS_EXPOSED", "Aisselles"),
        ("FEET_EXPOSED", "Pieds"),
    )),
)
NSFW_CLASS_NAMES = tuple(name for _group, items in NSFW_CLASS_GROUPS for name, _label in items)
NSFW_CLASS_LABELS = {name: label for _group, items in NSFW_CLASS_GROUPS for name, label in items}


def nsfw_class_label(name) -> str:
    """Nom français d'une partie détectée par NudeNet (le nom d'origine si elle est inconnue)."""
    name = str(name or "")
    return NSFW_CLASS_LABELS.get(name, name)

# Durées proposées (minutes, clé de traduction du libellé).
LIFETIME_CHOICES = (
    (5, "minutes_5"), (10, "minutes_10"), (20, "minutes_20"), (30, "minutes_30"),
    (60, "hour_1"), (120, "hours_2"), (360, "hours_6"), (720, "hours_12"),
    (1440, "day_1"), (2880, "days_2"), (4320, "days_3"), (10080, "days_7"),
    (20160, "days_14"), (43200, "days_30"), (129600, "days_90"), (525600, "year_1"),
)
ALLOWED_LIFETIMES = {minutes for minutes, _key in LIFETIME_CHOICES}
# Durées possibles pour le maximum (à partir d'1 heure).
MAX_LIFETIME_CHOICES = tuple(minutes for minutes, _key in LIFETIME_CHOICES if minutes >= 60)


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
    settings["max_lifetime_minutes"] = get_valid_max_lifetime(settings.get("max_lifetime_minutes"))
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
    clean_settings["support_url"] = clean_support_url(settings.get("support_url", current.get("support_url", "")))
    max_life = settings.get("max_lifetime_minutes", current.get("max_lifetime_minutes"))
    clean_settings["max_lifetime_minutes"] = get_valid_max_lifetime(max_life)
    clean_settings["season_theme"] = clean_choice(settings.get("season_theme", current.get("season_theme", "")))
    sky = settings.get("sky_enabled", current.get("sky_enabled"))
    clean_settings["sky_enabled"] = sky if isinstance(sky, bool) else None

    save_json(SETTINGS_FILENAME, clean_settings)

    return clean_settings


NSFW_KEYS = ("nsfw_auto_moderation", "nsfw_review_threshold", "nsfw_block_threshold", "nsfw_tiling", "nsfw_classes")


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


def get_valid_nsfw_classes(value):
    """Liste triée de parties NudeNet valides (liste ou texte « A,B »). None si vide ou invalide."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        value = value.replace(";", ",").replace(" ", ",").split(",")
    try:
        names = {str(item).strip().upper() for item in value}
    except TypeError:
        return None
    valid = sorted(names & set(NSFW_CLASS_NAMES))
    return valid or None


def _clean_nsfw_settings(source: dict) -> dict:
    enabled = source.get("nsfw_auto_moderation")
    return {
        "nsfw_auto_moderation": None if enabled is None else bool(enabled),
        "nsfw_review_threshold": get_valid_nsfw_threshold(source.get("nsfw_review_threshold")),
        "nsfw_block_threshold": get_valid_nsfw_threshold(source.get("nsfw_block_threshold")),
        "nsfw_tiling": bool(source.get("nsfw_tiling", True)),
        "nsfw_classes": get_valid_nsfw_classes(source.get("nsfw_classes")),
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


def clean_support_url(value) -> str:
    """Lien de soutien : seulement une vraie adresse web en https (sinon vide)."""
    from urllib.parse import urlparse
    value = str(value or "").strip()[:300]
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or " " in value:
        return ""
    return value


def get_support_url() -> str:
    """Réglage de l'admin, sinon variable SUPPORT_URL de Render, sinon rien."""
    import os
    return clean_support_url(load_settings().get("support_url")) or clean_support_url(os.environ.get("SUPPORT_URL"))


def get_valid_max_lifetime(value):
    """Maximum choisi dans l'admin ; None s'il n'y en a pas (ou s'il est invalide)."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value if value in MAX_LIFETIME_CHOICES else None


def get_max_lifetime() -> int:
    """Durée maximale d'hébergement en minutes : réglage de l'admin, sinon
    variable MAX_LIFETIME_MIN de Render, sinon 7 jours."""
    chosen = load_settings().get("max_lifetime_minutes")
    if chosen:
        return int(chosen)
    from flask import current_app
    try:
        env_value = int(current_app.config.get("MAX_LIFETIME_MIN", 10080))
    except (TypeError, ValueError):
        env_value = 10080
    # On se cale sur la plus grande durée proposée qui ne dépasse pas la variable.
    fitting = [m for m in MAX_LIFETIME_CHOICES if m <= env_value]
    return fitting[-1] if fitting else MAX_LIFETIME_CHOICES[0]


def get_lifetime_choices() -> list[tuple[int, str]]:
    """Durées affichées aux visiteurs : toutes celles qui ne dépassent pas le maximum."""
    limit = get_max_lifetime()
    return [(minutes, key) for minutes, key in LIFETIME_CHOICES if minutes <= limit]


def get_default_lifetime() -> int:
    """Durée présélectionnée, jamais au-dessus du maximum."""
    value = int(load_settings().get("default_lifetime_minutes", DEFAULT_SETTINGS["default_lifetime_minutes"]))
    limit = get_max_lifetime()
    if value <= limit:
        return value
    return [m for m, _k in LIFETIME_CHOICES if m <= limit][-1]


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
