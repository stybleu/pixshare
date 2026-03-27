from __future__ import annotations

import secrets
from datetime import datetime

from flask import session
from werkzeug.security import check_password_hash, generate_password_hash

from pixshare.services.json_services import load_named_dict, save_named_dict

API_USERS_FILE = "api_users.json"


def load_api_users() -> dict:
    data = load_named_dict(API_USERS_FILE)
    return data if isinstance(data, dict) else {}


def save_api_users(data: dict) -> None:
    save_named_dict(API_USERS_FILE, data)


def _normalize_user(user: dict) -> dict:
    normalized = dict(user or {})
    had_active_field = "active_api_key" in normalized

    single_key = str(normalized.get("api_key") or "").strip()
    api_keys = normalized.get("api_keys")
    if not isinstance(api_keys, list):
        api_keys = []

    clean_keys = []
    for key in api_keys:
        key = str(key or "").strip()
        if key and key not in clean_keys:
            clean_keys.append(key)

    if single_key and single_key not in clean_keys:
        clean_keys.append(single_key)

    normalized["api_keys"] = clean_keys

    active_key = str(normalized.get("active_api_key") or "").strip()
    if active_key and active_key not in clean_keys:
        active_key = ""

    if not active_key and clean_keys and not had_active_field:
        active_key = clean_keys[0]

    normalized["active_api_key"] = active_key
    normalized["api_key"] = active_key
    normalized["is_active"] = bool(normalized.get("is_active", True))
    return normalized


def _save_normalized_users(users: dict) -> dict:
    changed = False
    out = {}
    for user_id, user in users.items():
        if not isinstance(user, dict):
            continue
        normalized = _normalize_user(user)
        out[user_id] = normalized
        if normalized != user:
            changed = True

    if changed or out != users:
        save_api_users(out)
    return out


def create_api_user(pseudo: str, password: str):
    pseudo = (pseudo or "").strip()
    password = (password or "").strip()

    if len(pseudo) < 3:
        return None, "Le pseudo doit contenir au moins 3 caractères."

    if len(password) < 6:
        return None, "Le mot de passe doit contenir au moins 6 caractères."

    users = _save_normalized_users(load_api_users())

    for existing in users.values():
        if not isinstance(existing, dict):
            continue
        if str(existing.get("pseudo", "")).strip().lower() == pseudo.lower():
            return None, "Pseudo déjà utilisé."

    user_id = secrets.token_urlsafe(8).replace("-", "").replace("_", "")

    user = {
        "id": user_id,
        "pseudo": pseudo,
        "password_hash": generate_password_hash(password),
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "api_key": "",
        "api_keys": [],
        "active_api_key": "",
        "is_active": True,
    }

    users[user_id] = _normalize_user(user)
    save_api_users(users)
    return users[user_id], None


def find_user_by_pseudo(pseudo: str):
    pseudo = (pseudo or "").strip().lower()
    if not pseudo:
        return None

    users = _save_normalized_users(load_api_users())
    for user in users.values():
        if not isinstance(user, dict):
            continue
        if str(user.get("pseudo", "")).strip().lower() == pseudo:
            return user
    return None


def verify_password(user: dict, password: str) -> bool:
    password_hash = str((user or {}).get("password_hash") or "")
    if not password_hash:
        return False
    return check_password_hash(password_hash, password or "")


def login_api_user(user: dict) -> None:
    session["api_user_id"] = user["id"]


def current_api_user():
    user_id = session.get("api_user_id")
    if not user_id:
        return None

    users = _save_normalized_users(load_api_users())
    user = users.get(user_id)
    if not isinstance(user, dict):
        session.pop("api_user_id", None)
        return None

    if not bool(user.get("is_active", True)):
        session.pop("api_user_id", None)
        return None

    return user


def logout_api_user() -> None:
    session.pop("api_user_id", None)


def attach_api_key_to_user(user_id: str, api_key: str, make_active: bool = True) -> bool:
    api_key = str(api_key or "").strip()
    if not api_key:
        return False

    users = _save_normalized_users(load_api_users())
    user = users.get(user_id)
    if not isinstance(user, dict):
        return False

    keys = list(user.get("api_keys", []))
    if api_key not in keys:
        keys.append(api_key)

    user["api_keys"] = keys
    if make_active or not user.get("active_api_key"):
        user["active_api_key"] = api_key
    user["api_key"] = user.get("active_api_key", "")

    users[user_id] = _normalize_user(user)
    save_api_users(users)
    return True


def set_active_api_key_for_user(user_id: str, api_key: str) -> bool:
    api_key = str(api_key or "").strip()
    users = _save_normalized_users(load_api_users())
    user = users.get(user_id)
    if not isinstance(user, dict):
        return False

    if api_key not in user.get("api_keys", []):
        return False

    user["active_api_key"] = api_key
    user["api_key"] = api_key
    users[user_id] = _normalize_user(user)
    save_api_users(users)
    return True


def clear_active_api_key_for_user(user_id: str) -> bool:
    users = _save_normalized_users(load_api_users())
    user = users.get(user_id)
    if not isinstance(user, dict):
        return False

    user["active_api_key"] = ""
    user["api_key"] = ""
    users[user_id] = _normalize_user(user)
    save_api_users(users)
    return True


def remove_api_key_from_user(user_id: str, api_key: str) -> bool:
    api_key = str(api_key or "").strip()
    users = _save_normalized_users(load_api_users())
    user = users.get(user_id)
    if not isinstance(user, dict):
        return False

    keys = [k for k in user.get("api_keys", []) if k != api_key]
    user["api_keys"] = keys

    if user.get("active_api_key") == api_key:
        user["active_api_key"] = keys[0] if keys else ""
    user["api_key"] = user.get("active_api_key", "")

    users[user_id] = _normalize_user(user)
    save_api_users(users)
    return True


def get_user_api_keys(user: dict) -> list[str]:
    user = _normalize_user(user or {})
    return list(user.get("api_keys", []))


def get_active_api_key(user: dict) -> str:
    user = _normalize_user(user or {})
    return str(user.get("active_api_key") or "")
