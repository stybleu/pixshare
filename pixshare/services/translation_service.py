from __future__ import annotations

import json
from pathlib import Path

from flask import request, session, url_for

SUPPORTED_LANGS = ("fr", "en")
DEFAULT_LANG = "fr"
TRANSLATIONS_DIR = Path(__file__).resolve().parents[1] / "data" / "translations"
_TRANSLATIONS_CACHE: dict[str, dict[str, str]] = {}


def normalize_lang(lang: str | None) -> str:
    if not lang:
        return DEFAULT_LANG

    lang = lang.lower().strip()
    if lang.startswith("fr"):
        return "fr"
    if lang.startswith("en"):
        return "en"
    return DEFAULT_LANG


def _translation_file(lang: str) -> Path:
    lang = normalize_lang(lang)
    return TRANSLATIONS_DIR / f"{lang}.json"


def _load_translations(lang: str) -> dict[str, str]:
    lang = normalize_lang(lang)

    cached = _TRANSLATIONS_CACHE.get(lang)
    if cached is not None:
        return cached

    path = _translation_file(lang)

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        if lang != DEFAULT_LANG:
            return _load_translations(DEFAULT_LANG)
        data = {}

    if not isinstance(data, dict):
        if lang != DEFAULT_LANG:
            return _load_translations(DEFAULT_LANG)
        data = {}

    normalized_data = {str(k): str(v) for k, v in data.items()}
    _TRANSLATIONS_CACHE[lang] = normalized_data
    return normalized_data


def apply_requested_language() -> None:
    requested = request.args.get("lang")
    if requested:
        lang = normalize_lang(requested)
        if lang in SUPPORTED_LANGS:
            session["lang"] = lang


def get_current_language() -> str:
    lang = session.get("lang")
    if lang in SUPPORTED_LANGS:
        return lang

    header = request.accept_languages.best_match(SUPPORTED_LANGS)
    return normalize_lang(header)


def translate(key: str) -> str:
    lang = get_current_language()
    current_translations = _load_translations(lang)
    default_translations = _load_translations(DEFAULT_LANG)

    if key not in current_translations and key not in default_translations:
        print(f"[i18n missing key] {key}")

    return current_translations.get(key, default_translations.get(key, key))


def build_lang_url(lang: str) -> str:
    lang = normalize_lang(lang)

    if not request.endpoint:
        return request.path

    values = dict(request.view_args or {})
    for k, v in request.args.items():
        if k != "lang":
            values[k] = v
    values["lang"] = lang

    try:
        return url_for(request.endpoint, **values)
    except Exception:
        return f"{request.path}?lang={lang}"
