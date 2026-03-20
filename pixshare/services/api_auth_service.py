from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

from flask import current_app, request

from pixshare.services.json_services import load_api_keys, save_api_keys


@dataclass
class ApiAuthResult:
    ok: bool
    status_code: int
    error: str | None = None
    message: str | None = None
    key_value: str | None = None
    key_data: dict[str, Any] | None = None


def get_api_key_from_request() -> str:
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return (request.headers.get("X-API-Key") or "").strip()


def ensure_default_api_keys() -> None:
    data = load_api_keys()

    # Sécurise le type : le fichier JSON doit contenir un dict, pas une liste.
    if not isinstance(data, dict):
        data = {}

    # Si la clé de démo existe déjà, on ne fait rien.
    if "ps_demo_public_v1" in data:
        return

    data["ps_demo_public_v1"] = {
        "name": "demo",
        "is_active": True,
        "max_uploads_total": 1, 
        "uploads_used": 0,
        "max_uploads_per_day": 1,
        "daily_uploads_used": 0,
        "daily_reset_date": date.today().isoformat(),
        "max_file_size_mb": int(current_app.config.get("API_DEFAULT_MAX_FILE_SIZE_MB", 10)),
        "allow_permanent": False,
        "default_lifetime_minutes": 10,
        "allowed_lifetimes": [5, 10, 20, 30, 60],
        "notes": "Clé de démonstration à remplacer avant mise en production."
    }
    save_api_keys(data)


def _normalize_key_data(key_data: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(key_data or {})
    today = date.today().isoformat()

    normalized["name"] = str(normalized.get("name") or "api-client")
    normalized["is_active"] = bool(normalized.get("is_active", True))

    try:
        normalized["max_uploads_total"] = max(1, int(normalized.get("max_uploads_total", 100)))
    except (TypeError, ValueError):
        normalized["max_uploads_total"] = 100

    try:
        normalized["uploads_used"] = max(0, int(normalized.get("uploads_used", 0)))
    except (TypeError, ValueError):
        normalized["uploads_used"] = 0

    try:
        normalized["max_uploads_per_day"] = max(1, int(normalized.get("max_uploads_per_day", 10)))
    except (TypeError, ValueError):
        normalized["max_uploads_per_day"] = 10

    try:
        normalized["daily_uploads_used"] = max(0, int(normalized.get("daily_uploads_used", 0)))
    except (TypeError, ValueError):
        normalized["daily_uploads_used"] = 0

    reset_date = str(normalized.get("daily_reset_date") or today)
    if reset_date != today:
        normalized["daily_reset_date"] = today
        normalized["daily_uploads_used"] = 0
    else:
        normalized["daily_reset_date"] = reset_date

    try:
        normalized["max_file_size_mb"] = max(
            1,
            int(
                normalized.get(
                    "max_file_size_mb",
                    current_app.config.get("API_DEFAULT_MAX_FILE_SIZE_MB", 10)
                )
            )
        )
    except (TypeError, ValueError):
        normalized["max_file_size_mb"] = int(
            current_app.config.get("API_DEFAULT_MAX_FILE_SIZE_MB", 10)
        )

    normalized["allow_permanent"] = bool(normalized.get("allow_permanent", False))

    try:
        normalized["default_lifetime_minutes"] = max(
            1,
            int(normalized.get("default_lifetime_minutes", 10))
        )
    except (TypeError, ValueError):
        normalized["default_lifetime_minutes"] = 10

    allowed_lifetimes = normalized.get("allowed_lifetimes") or [5, 10, 20, 30, 60]
    if not isinstance(allowed_lifetimes, list):
        allowed_lifetimes = [5, 10, 20, 30, 60]

    clean_lifetimes = []
    for value in allowed_lifetimes:
        try:
            ivalue = int(value)
        except (TypeError, ValueError):
            continue
        if ivalue > 0 and ivalue not in clean_lifetimes:
            clean_lifetimes.append(ivalue)

    normalized["allowed_lifetimes"] = sorted(clean_lifetimes or [5, 10, 20, 30, 60])
    normalized["default_lifetime_minutes"] = min(
        normalized["allowed_lifetimes"],
        key=lambda x: abs(x - normalized["default_lifetime_minutes"])
    )

    normalized["notes"] = str(normalized.get("notes") or "")
    return normalized


def get_api_key_record(
    key_value: str
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]] | tuple[None, dict[str, dict[str, Any]]]:
    data = load_api_keys()

    # Sécurise le type pour éviter un crash si le JSON contient [] au lieu de {}.
    if not isinstance(data, dict):
        data = {}

    changed = False

    for key, key_data in list(data.items()):
        normalized = _normalize_key_data(key_data)
        if normalized != key_data:
            data[key] = normalized
            changed = True

    if changed:
        save_api_keys(data)

    if not key_value:
        return None, data

    return data.get(key_value), data


def authenticate_api_key() -> ApiAuthResult:
    ensure_default_api_keys()
    key_value = get_api_key_from_request()

    if not key_value:
        return ApiAuthResult(False, 401, "missing_api_key", "Clé API manquante.")

    key_data, _ = get_api_key_record(key_value)

    if not key_data:
        return ApiAuthResult(False, 401, "invalid_api_key", "Clé API invalide.")

    if not bool(key_data.get("is_active", True)):
        return ApiAuthResult(False, 403, "api_key_disabled", "Cette clé API est désactivée.")

    if int(key_data.get("uploads_used", 0)) >= int(key_data.get("max_uploads_total", 0)):
        return ApiAuthResult(False, 403, "upload_limit_reached", "La limite totale d'uploads a été atteinte.")

    if int(key_data.get("daily_uploads_used", 0)) >= int(key_data.get("max_uploads_per_day", 0)):
        return ApiAuthResult(False, 429, "daily_upload_limit_reached", "La limite quotidienne d'uploads a été atteinte.")

    return ApiAuthResult(True, 200, key_value=key_value, key_data=key_data)


def get_api_max_file_size_bytes(key_data: dict[str, Any]) -> int:
    return int(
        key_data.get(
            "max_file_size_mb",
            current_app.config.get("API_DEFAULT_MAX_FILE_SIZE_MB", 10)
        )
    ) * 1024 * 1024


def consume_upload_for_key(key_value: str) -> dict[str, Any] | None:
    data = load_api_keys()

    if not isinstance(data, dict):
        data = {}

    key_data = data.get(key_value)

    if not key_data:
        return None

    key_data = _normalize_key_data(key_data)

    key_data["uploads_used"] = int(key_data.get("uploads_used", 0)) + 1
    key_data["daily_uploads_used"] = int(key_data.get("daily_uploads_used", 0)) + 1

    data[key_value] = key_data
    save_api_keys(data)

    return key_data


def remaining_uploads_info(key_data: dict[str, Any]) -> dict[str, int]:
    total_remaining = max(
        0,
        int(key_data.get("max_uploads_total", 0)) - int(key_data.get("uploads_used", 0))
    )
    daily_remaining = max(
        0,
        int(key_data.get("max_uploads_per_day", 0)) - int(key_data.get("daily_uploads_used", 0))
    )

    return {
        "remaining_total": total_remaining,
        "remaining_today": daily_remaining,
        "used_total": int(key_data.get("uploads_used", 0)),
        "used_today": int(key_data.get("daily_uploads_used", 0)),
        "max_total": int(key_data.get("max_uploads_total", 0)),
        "max_per_day": int(key_data.get("max_uploads_per_day", 0)),
    }