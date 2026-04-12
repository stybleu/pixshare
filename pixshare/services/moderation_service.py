from __future__ import annotations

from datetime import timedelta
import secrets

from pixshare.services.json_services import load_moderation_notices, save_moderation_notices
from pixshare.services.time_service import parse_dt, utcnow


def _cleanup_notices(items: list[dict]) -> list[dict]:
    now = utcnow()
    cleaned = []
    for item in items:
        if not isinstance(item, dict):
            continue
        created_at = (item.get("created_at") or "").strip()
        if created_at:
            try:
                created_dt = parse_dt(created_at)
            except Exception:
                created_dt = now
        else:
            created_dt = now

        shown = bool(item.get("shown", False))
        max_age = timedelta(days=90 if shown else 30)
        if created_dt + max_age < now:
            continue

        cleaned.append(item)
    return cleaned


def build_notice_message(reason: str) -> str:
    reason = (reason or "admin_delete").strip().lower()

    if reason == "non_respect_cgu":
        return "Une de vos images a été supprimée par la modération pour non-respect des conditions d’utilisation de PixShare."
    if reason == "contenu_illicite":
        return "Une de vos images a été supprimée par la modération car elle contrevenait aux règles du service ou à la législation applicable."
    if reason == "spam_abus":
        return "Un de vos fichiers a été supprimé par la modération pour usage abusif du service."
    return "Un de vos fichiers a été supprimé par l’administration de PixShare."


def create_moderation_notice(meta: dict, file_id: str, reason: str = "non_respect_cgu", message: str | None = None) -> bool:
    guest_token = (meta.get("guest_token") or "").strip()
    if not guest_token or guest_token.startswith("api:"):
        return False

    notices = _cleanup_notices(load_moderation_notices())
    notices.append({
        "id": secrets.token_urlsafe(12).replace("-", "").replace("_", ""),
        "guest_token": guest_token,
        "ip": (meta.get("ip") or "").strip(),
        "file_id": file_id,
        "reason": (reason or "non_respect_cgu").strip(),
        "message": (message or build_notice_message(reason)).strip(),
        "level": "warning",
        "created_at": utcnow().isoformat(timespec="seconds"),
        "shown": False,
        "shown_at": "",
    })
    save_moderation_notices(notices)
    return True


def pop_pending_notice(guest_token: str) -> dict | None:
    guest_token = (guest_token or "").strip()
    if not guest_token:
        return None

    notices = _cleanup_notices(load_moderation_notices())
    changed = False
    selected = None

    for item in notices:
        if bool(item.get("shown", False)):
            continue
        if (item.get("guest_token") or "").strip() != guest_token:
            continue

        item["shown"] = True
        item["shown_at"] = utcnow().isoformat(timespec="seconds")
        selected = item
        changed = True
        break

    if changed:
        save_moderation_notices(notices)

    return selected
