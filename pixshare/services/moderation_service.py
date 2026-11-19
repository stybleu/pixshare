from __future__ import annotations

from datetime import datetime, timedelta, timezone
import secrets

from pixshare.services.json_services import load_moderation_notices, save_db, save_moderation_notices
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
    if reason == "filtre_absent":
        return "Une de vos images a été retirée par le filtre automatique de PixShare, car elle semblait ne pas respecter les conditions d’utilisation."
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


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def start_lifetime_now(meta: dict) -> None:
    """Le délai de l'image ne compte qu'à partir de sa publication : le temps passé en vérification
    (analyse automatique ou revue par l'admin) est rajouté à la date d'expiration."""
    from datetime import timedelta

    from pixshare.services.time_service import parse_dt, utcnow

    if meta.get("permanent") or not meta.get("expires_at") or meta.get("lifetime_started_at"):
        return
    try:
        start = parse_dt(meta.get("moderation_requested_at") or meta.get("uploaded_at") or "")
        expires = parse_dt(meta["expires_at"])
    except Exception:
        return
    now = utcnow()
    paused = now - start
    if start.year < 2000 or paused.total_seconds() <= 0:
        return
    meta["expires_at"] = (expires + paused).isoformat(timespec="seconds")
    meta["lifetime_started_at"] = now.isoformat(timespec="seconds")
    meta["paused_seconds"] = int(paused.total_seconds())


def _forget_approved(meta: dict, path: str = "") -> None:
    """Image signalée, mise en revue ou supprimée par l'admin : elle ne sera plus publiée d'office."""
    try:
        from pixshare.services.approved_hash_service import forget
        sha = str(meta.get("content_sha256") or "")
        if not sha and path:
            from pixshare.services.image_ban_service import file_sha256
            sha = file_sha256(path)
        forget(sha)
    except Exception:
        pass


def approve_image(database: dict, file_id: str, meta: dict, detector: str, score: float | None) -> None:
    """Publie une image en attente (utilisé par l'API de modération et par NudeNet intégré)."""
    start_lifetime_now(meta)
    meta["status"] = "active"
    meta["moderated_at"] = _utc_now_iso()
    meta["moderation_decision"] = "approved"
    meta["moderation_detector"] = detector
    meta["moderation_score"] = score
    database[file_id] = meta
    save_db(database)


def mark_image_for_review(database: dict, file_id: str, meta: dict, detector: str, score: float | None, label: str) -> None:
    """L'image reste privée (status=pending) mais sort de la file automatique : revue manuelle."""
    _forget_approved(meta)
    meta["status"] = "pending"
    meta["moderated_at"] = _utc_now_iso()
    meta["moderation_decision"] = "manual_review"
    meta["moderation_detector"] = detector
    meta["moderation_score"] = score
    meta["moderation_label"] = label[:80]
    database[file_id] = meta
    save_db(database)
    try:  # alerte mail pour l'admin : ne doit jamais gêner la modération
        from pixshare.services.mail_service import notify_review
        notify_review()
    except Exception:
        pass
