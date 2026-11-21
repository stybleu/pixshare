import os
import secrets
import time
from datetime import datetime, timedelta

from flask import current_app, g, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from PIL import Image, ImageOps

try:
    from pillow_heif import register_heif_opener
    register_heif_opener()
    HEIF_ENABLED = True
except Exception:
    HEIF_ENABLED = False

from pixshare.storage import thumbnail_dir
from .auth_service import is_admin
from .json_services import load_db, save_db, load_views, save_views
from .time_service import parse_dt, utcnow
from .image_quality_service import (
    HEIF_AVAILABLE,
    can_enhance_extension,
    enhance_image_bytes,
    get_output_extension,
    parse_strength,
)
from .image_metadata_service import strip_uploaded_image
from .settings_service import nsfw_class_label
from .settings_service import get_thumbnail_retention_hours, permanent_files_enabled, thumbnails_enabled
from .usage_tracking_service import build_usage_summary


class FileTooLargeError(ValueError):
    """Le fichier reçu dépasse la taille maximale autorisée."""


IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".tif", ".tiff", ".heic", ".heif",
    ".bmp", ".jfif", ".jpe", ".apng",
}
VIDEO_EXTENSIONS = {".mp4", ".webm", ".avi", ".mov"}
PREVIEW_IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".avif",
    ".jfif", ".jpe", ".apng",
}


def is_image_filename(filename) -> bool:
    """Vrai si le nom de fichier est une image affichable sur la page d'aperçu."""
    if not filename:
        return False
    name = str(filename).lower()
    return any(name.endswith(ext) for ext in PREVIEW_IMAGE_EXTENSIONS)


def is_video_filename(filename) -> bool:
    """Vrai si le nom de fichier est une vidéo lisible sur la page publique."""
    if not filename:
        return False
    return os.path.splitext(str(filename).lower())[1] in VIDEO_EXTENSIONS


def requires_image_moderation(extension_or_filename: str) -> bool:
    """Return True when a newly uploaded file must wait for image moderation."""
    value = (extension_or_filename or "").lower()
    extension = value if value.startswith(".") else os.path.splitext(value)[1].lower()
    if extension not in IMAGE_EXTENSIONS:
        return False
    # L'image n'attend que si NudeNet va vraiment l'analyser. Sinon (NudeNet
    # désactivé dans l'admin, ou pas installé), personne ne la validerait et
    # elle resterait bloquée pour toujours.
    from .nsfw_service import auto_moderation_enabled, nudenet_installed
    return auto_moderation_enabled() and nudenet_installed()


def initial_upload_status(extension_or_filename: str) -> str:
    return "pending" if requires_image_moderation(extension_or_filename) else "active"


def human_size(n: int) -> str:
    units = ["o", "Ko", "Mo", "Go", "To"]
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    return f"{f:.2f} {units[i]}" if i > 0 else f"{int(f)} {units[i]}"


def safe_ext(filename: str) -> str:
    _, ext = os.path.splitext(filename)
    ext = (ext or "").lower()
    if len(ext) > 12:
        return ""
    return ext


def is_image_extension(ext: str) -> bool:
    ext = (ext or "").lower()
    if ext in {".heic", ".heif"} and not HEIF_ENABLED:
        return False
    return ext in IMAGE_EXTENSIONS


def allowed_file(filename: str) -> bool:
    ext = safe_ext(filename)
    return bool(ext) and ext[1:] in current_app.config["ALLOWED_EXTENSIONS"]


def generate_file_id() -> str:
    return secrets.token_urlsafe(8).replace("-", "").replace("_", "")


def get_guest_token() -> str:
    cookie_name = current_app.config.get("GUEST_COOKIE_NAME", "guest_token")
    tok = (request.cookies.get(cookie_name) or "").strip()

    if tok:
        session["guest_token"] = tok
        return tok

    tok = (session.get("guest_token") or "").strip()
    if not tok:
        tok = secrets.token_urlsafe(16)

    session["guest_token"] = tok
    g.guest_cookie_token = tok
    return tok


def get_existing_guest_token() -> str:
    cookie_name = current_app.config.get("GUEST_COOKIE_NAME", "guest_token")
    tok = (request.cookies.get(cookie_name) or session.get("guest_token") or "").strip()
    return tok


def attach_guest_cookie(response):
    tok = getattr(g, "guest_cookie_token", "")
    if not tok:
        return response

    response.set_cookie(
        current_app.config.get("GUEST_COOKIE_NAME", "guest_token"),
        tok,
        max_age=int(current_app.config.get("GUEST_COOKIE_MAX_AGE", 60 * 60 * 24 * 30)),
        httponly=True,
        secure=not bool(current_app.debug),
        samesite="Lax",
    )
    return response


def _account_id() -> str:
    try:
        from .account_service import current_account_id
        return current_account_id()
    except Exception:
        return ""


def _is_member() -> bool:
    """Amélioration des photos : réservée aux comptes (et à l'admin)."""
    try:
        from .account_service import is_member
        return is_member()
    except Exception:
        return False


def is_owner(meta: dict) -> bool:
    """Le visiteur a-t-il envoyé ce fichier ? Même navigateur, ou même compte (sur n'importe quel appareil)."""
    if not isinstance(meta, dict):
        return False
    owner = (meta.get("guest_token") or "").strip()
    if owner and owner == (get_existing_guest_token() or ""):
        return True
    account = (meta.get("account_id") or "").strip()
    return bool(account and account == _account_id())


def claim_device_files(account_id: str) -> int:
    """À la connexion : les fichiers envoyés depuis ce navigateur sans compte rejoignent le compte."""
    token = get_existing_guest_token()
    if not token or not account_id:
        return 0
    db = load_db()
    claimed = 0
    for meta in db.values():
        if (isinstance(meta, dict) and meta.get("guest_token") == token and not meta.get("account_id")
                and (meta.get("status") or "active").lower() in ("active", "pending")):
            meta["account_id"] = account_id
            claimed += 1
    if claimed:
        save_db(db)
    return claimed


def get_or_create_visitor_token() -> tuple[str, bool]:
    token = (request.cookies.get(current_app.config["VISITOR_COOKIE_NAME"]) or "").strip()
    if token:
        return token, False
    return secrets.token_urlsafe(24), True


def register_unique_view(file_id: str, visitor_token: str) -> bool:
    data = load_views()
    file_views = data.get(file_id, [])
    if not isinstance(file_views, list):
        file_views = []
    if visitor_token in file_views:
        return False
    file_views.append(visitor_token)
    data[file_id] = file_views
    save_views(data)
    return True


def get_thumbnail_abs_path(file_id: str) -> str:
    return os.path.join(thumbnail_dir(current_app), f"{file_id}.jpg")


def create_thumbnail(source_path: str, file_id: str) -> str:
    if not thumbnails_enabled():
        return ""

    thumb_abs = get_thumbnail_abs_path(file_id)
    os.makedirs(os.path.dirname(thumb_abs), exist_ok=True)

    with Image.open(source_path) as img:
        if img.mode not in {"RGB", "L"}:
            img = img.convert("RGB")
        elif img.mode == "L":
            img = img.convert("RGB")

        img.thumbnail((800, 800), Image.LANCZOS)
        img.save(thumb_abs, "JPEG", quality=82, optimize=True)

    return os.path.join(current_app.config["THUMBNAIL_FOLDER"], f"{file_id}.jpg")


def delete_thumbnail_file(thumb_path: str) -> bool:
    rel = (thumb_path or "").strip()
    if not rel:
        return False

    abs_path = os.path.join(os.path.dirname(current_app.root_path), rel)
    if not os.path.isfile(abs_path):
        return False

    try:
        os.remove(abs_path)
        return True
    except Exception:
        return False


def schedule_thumbnail_cleanup(meta: dict, when: datetime | None = None) -> dict:
    if not thumbnails_enabled():
        if meta.get("thumb_path"):
            delete_thumbnail_file(meta.get("thumb_path", ""))
        meta["thumb_path"] = ""
        meta["thumb_delete_at"] = ""
        return meta

    retention_hours = get_thumbnail_retention_hours()

    if not meta.get("thumb_path"):
        meta["thumb_delete_at"] = ""
        return meta

    if retention_hours <= 0:
        delete_thumbnail_file(meta.get("thumb_path", ""))
        meta["thumb_path"] = ""
        meta["thumb_delete_at"] = ""
        return meta

    base_dt = when or utcnow()
    meta["thumb_delete_at"] = (base_dt + timedelta(hours=retention_hours)).isoformat(timespec="seconds")
    return meta


def get_expected_thumb_delete_at(meta: dict) -> str:
    thumb_path = (meta.get("thumb_path") or "").strip()
    if not thumb_path:
        return ""

    thumb_delete_at = (meta.get("thumb_delete_at") or "").strip()
    if thumb_delete_at:
        return thumb_delete_at

    if not thumbnails_enabled() or get_thumbnail_retention_hours() <= 0:
        return ""

    status = (meta.get("status") or "active").lower()

    if status == "active":
        if meta.get("permanent") or not meta.get("expires_at"):
            return ""
        try:
            base_dt = parse_dt(meta.get("expires_at", ""))
        except Exception:
            return ""
        return (base_dt + timedelta(hours=get_thumbnail_retention_hours())).isoformat(timespec="seconds")

    deleted_at = (meta.get("deleted_at") or "").strip()
    if deleted_at:
        try:
            base_dt = parse_dt(deleted_at)
        except Exception:
            return ""
        return (base_dt + timedelta(hours=get_thumbnail_retention_hours())).isoformat(timespec="seconds")

    return ""


def purge_expired_thumbnails(db: dict | None = None) -> tuple[dict, bool]:
    db = db if db is not None else load_db()
    now = utcnow()
    changed = False
    to_remove = []

    for file_id, meta in db.items():
        thumb_delete_at = (meta.get("thumb_delete_at") or "").strip()
        if thumb_delete_at:
            delete_at = parse_dt(thumb_delete_at)
            if delete_at <= now:
                if delete_thumbnail_file(meta.get("thumb_path", "")):
                    changed = True
                meta["thumb_path"] = ""
                meta["thumb_delete_at"] = ""
                db[file_id] = meta
                changed = True

        status = (meta.get("status") or "active").lower()
        if status == "active":
            # Évite un appel disque par fichier actif à chaque requête.
            continue

        public_path = os.path.join(
            current_app.config["UPLOAD_FOLDER"],
            os.path.basename(meta.get("server_name", ""))
        )
        if not os.path.isfile(public_path) and not meta.get("thumb_path"):
            to_remove.append(file_id)

    for file_id in to_remove:
        db.pop(file_id, None)
        changed = True

    return db, changed


def cleanup_expired() -> int:
    db = load_db()
    now = utcnow()
    removed_public_files = 0
    changed = False

    for file_id, meta in list(db.items()):
        status = (meta.get("status") or "active").lower()
        if status not in {"active", "pending"}:
            continue
        if meta.get("permanent") or not meta.get("expires_at"):
            # Les fichiers permanents n'existent plus : les anciens expirent dans 7 jours.
            meta["permanent"] = False
            meta["expires_at"] = (now + timedelta(days=7)).isoformat(timespec="seconds")
            db[file_id] = meta
            changed = True
            continue

        if status == "pending":
            # En vérification : le délai est en pause (il démarre à la publication).
            # Une image jamais vérifiée finit quand même par être effacée au bout de 30 jours.
            waiting_since = parse_dt(meta.get("moderation_requested_at") or meta.get("uploaded_at") or "")
            if waiting_since.year < 2000 or now - waiting_since < timedelta(days=PENDING_MAX_DAYS):
                continue
        else:
            exp = parse_dt(meta.get("expires_at", ""))
            if exp > now:
                continue

        server_name = os.path.basename(meta.get("server_name", ""))
        path = os.path.join(current_app.config["UPLOAD_FOLDER"], server_name)

        try:
            if server_name and os.path.isfile(path):
                os.remove(path)
                removed_public_files += 1
        except Exception:
            pass

        remove_medium(file_id)
        meta["status"] = "expired"
        meta["deleted_at"] = now.isoformat(timespec="seconds")
        meta["delete_reason"] = "expired"
        schedule_thumbnail_cleanup(meta, now)
        db[file_id] = meta
        changed = True

    db, thumbs_changed = purge_expired_thumbnails(db)
    changed = changed or thumbs_changed

    if changed:
        save_db(db)

    return removed_public_files


_last_cleanup = 0.0


PENDING_MAX_DAYS = 30


def cleanup_expired_soon(interval: float = 60.0) -> int:
    """Nettoyage des fichiers expirés au plus une fois par minute (par worker) au lieu d'à chaque image."""
    global _last_cleanup
    now = time.monotonic()
    if now - _last_cleanup < interval:
        return 0
    _last_cleanup = now
    return cleanup_expired()


def is_expired(meta: dict) -> bool:
    if meta.get("permanent") or not meta.get("expires_at"):
        return False
    try:
        return parse_dt(meta.get("expires_at", "")) <= utcnow()
    except Exception:
        return False


# Version « moyenne » (WebP, 1280 px max) affichée sur la page de l'image, comme ImgBB.
MEDIUM_MAX = 1280
MEDIUM_EXTENSIONS = {".jpg", ".jpeg", ".jfif", ".jpe", ".png", ".webp", ".bmp", ".tif", ".tiff", ".heic", ".heif"}


def medium_path(file_id: str) -> str:
    return os.path.join(current_app.config["UPLOAD_FOLDER"], f"{os.path.basename(file_id)}_m.webp")


def remove_medium(file_id: str) -> None:
    try:
        os.remove(medium_path(file_id))
    except OSError:
        pass


def create_medium(src: str, file_id: str) -> str:
    """Crée la version moyenne si elle est vraiment plus légère. Ne casse jamais un envoi."""
    if os.path.splitext(src)[1].lower() not in MEDIUM_EXTENSIONS:
        return ""
    out = medium_path(file_id)
    try:
        size = os.path.getsize(src)
        with Image.open(src) as im:
            w, h = im.size
            if getattr(im, "is_animated", False) or w * h > 40_000_000:
                return ""
            if max(w, h) <= MEDIUM_MAX and size <= 400_000:
                return ""
            if im.format == "JPEG":
                im.draft("RGB", (MEDIUM_MAX, MEDIUM_MAX))
            pic = ImageOps.exif_transpose(im)
            alpha = pic.mode in ("RGBA", "LA", "PA") or (pic.mode == "P" and "transparency" in pic.info)
            pic = pic.convert("RGBA" if alpha else "RGB")
            pic.thumbnail((MEDIUM_MAX, MEDIUM_MAX), Image.LANCZOS)
            pic.save(out, "WEBP", quality=82, method=4)
        if os.path.getsize(out) >= size:
            remove_medium(file_id)
            return ""
        return out
    except Exception:
        remove_medium(file_id)
        return ""


def file_meta(file_id: str, db: dict | None = None):
    """``db`` : base déjà chargée (et déjà nettoyée) par l'appelant. Sans cela,
    chaque appel relisait tout le fichier JSON et relançait le nettoyage, ce qui
    rendait les listes admin quadratiques."""
    if db is None:
        cleanup_expired()
        db = load_db()

    if not file_id:
        return None

    meta = db.get(file_id)
    if not meta:
        return None

    server_name = os.path.basename(meta.get("server_name", ""))
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], server_name) if server_name else ""
    status = (meta.get("status") or "active").lower()
    public_exists = bool(server_name and os.path.isfile(path))
    ext = os.path.splitext(server_name)[1].lower()

    thumb_rel = (meta.get("thumb_path") or "").strip()
    thumb_exists = False
    if thumb_rel:
        thumb_abs = os.path.join(os.path.dirname(current_app.root_path), thumb_rel)
        thumb_exists = os.path.isfile(thumb_abs)

    if not public_exists and not thumb_exists:
        return None

    is_public = status == "active"
    previewable = is_public and public_exists and ext in IMAGE_EXTENSIONS.union(VIDEO_EXTENSIONS)
    permanent = bool(meta.get("permanent")) or (not meta.get("expires_at"))
    remaining_h = ""

    if status == "active":
        if permanent:
            remaining_h = "∞"
        else:
            exp = parse_dt(meta.get("expires_at", ""))
            remaining_s = max(0, int((exp - utcnow()).total_seconds()))
            remaining_min = remaining_s // 60
            remaining_sec = remaining_s % 60
            remaining_h = f"{remaining_min:02d}:{remaining_sec:02d}"

    size_h = human_size(os.stat(path).st_size) if public_exists else "—"
    from zoneinfo import ZoneInfo
    paris = ZoneInfo("Europe/Paris")
    if public_exists:  # heure de Paris, au format français (le serveur est en UTC)
        mtime_h = datetime.fromtimestamp(os.stat(path).st_mtime, paris).strftime("%d/%m/%Y à %H:%M")
    else:
        mtime_h = meta.get("deleted_at") or meta.get("uploaded_at", "")
        try:
            mtime_h = parse_dt(mtime_h).astimezone(paris).strftime("%d/%m/%Y à %H:%M")
        except Exception:
            pass

    return {
        "id": file_id,
        "original": meta.get("original_name", "unknown"),
        "server": server_name,
        "uploaded_at": meta.get("uploaded_at", ""),
        "expires_at": meta.get("expires_at", ""),
        "remaining_h": remaining_h,
        "permanent": permanent,
        "ip": meta.get("ip", ""),
        "size_h": size_h,
        "mtime_h": mtime_h,
        "download_url": url_for("public.download", file_id=file_id, _external=True) if is_public and public_exists else "",
        "public_url": url_for("public.public_file", file_id=file_id, _external=True) if is_public and public_exists else "",
        "raw_url": url_for("public.view_file", file_id=file_id, _external=True) if is_public and public_exists else "",
        "previewable": previewable,
        "is_image": previewable and ext in IMAGE_EXTENSIONS,
        "views": int(meta.get("views", 0) or 0),
        "view_limit_enabled": bool(meta.get("view_limit_enabled", False)),
        "max_views": int(meta.get("max_views", 0) or 0),
        "views_remaining": (max(0, int(meta.get("max_views", 0) or 0) - int(meta.get("views", 0) or 0)) if meta.get("view_limit_enabled") else None),
        "status": status,
        "moderation_decision": str(meta.get("moderation_decision") or ""),
        "moderation_score": meta.get("moderation_score"),
        "moderation_label": str(meta.get("moderation_label") or ""),
        "moderation_label_fr": nsfw_class_label(meta.get("moderation_label")),
        "reports_count": len(meta.get("reports") or []),
        "reports_summary": _reports_summary(meta),
        "protected": bool(meta.get("password_hash")),
        "review_url": (
            url_for("admin.admin_review_preview", file_id=file_id)
            if status == "pending" and public_exists and ext in IMAGE_EXTENSIONS
            else ""
        ),
        "deleted_at": meta.get("deleted_at", ""),
        "delete_reason": meta.get("delete_reason", ""),
        "status_before_delete": meta.get("status_before_delete", ""),
        "late_check": meta.get("late_check", ""),
        "late_check_label": meta.get("late_check_label", ""),
        "late_check_score": meta.get("late_check_score"),
        "thumb_url": url_for("admin.admin_thumbnail", file_id=file_id, _external=False) if thumb_exists else "",
        "has_public_file": public_exists,
        "account_id": meta.get("account_id", ""),
        "owner_preview_url": (
            url_for("account.owner_preview", file_id=file_id, v=meta.get("replace_count") or None)
            if status in ("active", "pending") and public_exists and ext in IMAGE_EXTENSIONS
            else ""
        ),
        "replaced_at": meta.get("replaced_at", ""),
        "has_thumb": thumb_exists,
        "thumb_delete_at": get_expected_thumb_delete_at(meta),
        "usage": build_usage_summary(file_id),
    }


def list_all_files(include_thumbnails: bool = True):
    cleanup_expired()
    db = load_db()
    items = []

    for file_id in db.keys():
        fm = file_meta(file_id, db=db)
        if not fm:
            continue
        if not include_thumbnails:
            fm["thumb_url"] = ""
        items.append(fm)

    items.sort(key=lambda x: (x.get("uploaded_at", ""), x.get("mtime_h", "")), reverse=True)
    return items


def list_all_thumbnails():
    cleanup_expired()
    items = []

    for item in list_all_files(include_thumbnails=True):
        if item.get("has_thumb") and item.get("thumb_url"):
            items.append(item)

    items.sort(key=lambda x: (x.get("uploaded_at", ""), x.get("mtime_h", "")), reverse=True)
    return items


def list_guest_files():
    """Fichiers du visiteur : ceux de ce navigateur, plus ceux de son compte (tous appareils)."""
    cleanup_expired()
    db = load_db()
    guest_token = get_guest_token()
    account_id = _account_id()
    items = []

    for file_id, meta in db.items():
        if meta.get("guest_token") != guest_token and not (account_id and meta.get("account_id") == account_id):
            continue

        fm = file_meta(file_id, db=db)
        if fm and fm.get("status") in {"active", "pending"}:
            items.append(fm)

    items.sort(key=lambda x: x.get("mtime_h", ""), reverse=True)
    return items


def list_removed_files():
    """Fichiers retirés par la modération ces derniers jours : on garde une trace dans « Mes fichiers »,
    pour que la personne sache pourquoi (et, pour un membre, puisse la remplacer en gardant le lien)."""
    from .moderation_service import REMOVED_VISIBLE_DAYS, is_moderation_removal, removal_cause
    db = load_db()
    guest_token = get_guest_token()
    account_id = _account_id()
    now = utcnow()
    items = []
    for file_id, meta in db.items():
        if not isinstance(meta, dict) or not is_moderation_removal(meta):
            continue
        if meta.get("guest_token") != guest_token and not (account_id and meta.get("account_id") == account_id):
            continue
        try:
            if now - parse_dt(meta.get("deleted_at") or "") > timedelta(days=REMOVED_VISIBLE_DAYS):
                continue
        except Exception:
            continue
        items.append({"id": file_id, "original_name": meta.get("original_name") or "fichier",
                      "cause": removal_cause(meta), "deleted_at": meta.get("deleted_at") or "",
                      "replaceable": can_replace_removed(meta, account_id)})
    return sorted(items, key=lambda m: m["deleted_at"], reverse=True)


def can_replace_removed(meta: dict, account_id: str | None) -> bool:
    """Un membre peut remplacer une image retirée par la modération (même lien), tant qu'elle n'a pas expiré."""
    from .moderation_service import REMOVED_VISIBLE_DAYS, is_moderation_removal
    if not account_id or meta.get("account_id") != account_id or not is_moderation_removal(meta):
        return False
    now = utcnow()
    try:
        if now - parse_dt(meta.get("deleted_at") or "") > timedelta(days=REMOVED_VISIBLE_DAYS):
            return False
        if meta.get("expires_at") and parse_dt(meta["expires_at"]) <= now:
            return False
    except Exception:
        return False
    return True


def can_keep_uploads() -> bool:
    if not permanent_files_enabled():
        return False

    return current_app.config["PERMANENT_UPLOADS_ENABLED"] and (
        not current_app.config["PERMANENT_UPLOADS_ADMIN_ONLY"] or is_admin()
    )


def _convert_heic_to_jpeg(dest: str, server_name: str, ext: str, original_name: str):
    """Photo iPhone (HEIC/HEIF) -> JPEG : lisible dans tous les navigateurs, et nettoyable (GPS, appareil).

    En cas d'échec, le fichier d'origine est gardé tel quel.
    """
    if ext not in {".heic", ".heif"} or not HEIF_AVAILABLE:
        return server_name, dest, ext, original_name
    new_server = os.path.splitext(server_name)[0] + ".jpg"
    new_dest = os.path.join(os.path.dirname(dest), new_server)
    if os.path.exists(new_dest):
        return server_name, dest, ext, original_name
    try:
        with Image.open(dest) as im:
            icc = im.info.get("icc_profile")
            picture = ImageOps.exif_transpose(im).convert("RGB")
        options = {"quality": 92, "optimize": True}
        if icc:
            options["icc_profile"] = icc
        picture.save(new_dest, "JPEG", **options)
        os.remove(dest)
        return new_server, new_dest, ".jpg", os.path.splitext(original_name)[0] + ".jpg"
    except Exception:
        try:
            os.remove(new_dest)
        except OSError:
            pass
        return server_name, dest, ext, original_name


def _reports_summary(meta: dict) -> str:
    from .report_service import reasons_summary
    return reasons_summary(meta)


def _check_banned(dest: str, client_ip: str = ""):
    """Image déjà refusée ? Identique : on l'efface et on refuse l'envoi. Ressemblante : revue manuelle."""
    if not is_image_extension(os.path.splitext(dest)[1].lower()):
        return None
    from .image_ban_service import BannedImageError, check_file
    result = check_file(dest)
    if result and result[0] == "exact":
        try:
            os.remove(dest)
        except OSError:
            pass
        if not is_admin():
            try:  # renvoyer une image interdite compte comme une image rejetée (récidive)
                from .abuse_service import record_rejection
                record_rejection(client_ip)
            except Exception:
                pass
        raise BannedImageError("image déjà refusée")
    return result


def _prepare_file_destination(original_name: str) -> tuple[str, str, str, str]:
    ext = safe_ext(original_name)

    file_id = generate_file_id()
    server_name = f"{file_id}{ext}"
    dest = os.path.join(current_app.config["UPLOAD_FOLDER"], server_name)

    while os.path.exists(dest):
        file_id = generate_file_id()
        server_name = f"{file_id}{ext}"
        dest = os.path.join(current_app.config["UPLOAD_FOLDER"], server_name)

    return file_id, server_name, dest, ext


def _resolve_web_lifetime(keep_requested: bool) -> tuple[int | None, bool]:
    allow_keep = can_keep_uploads()
    if keep_requested and allow_keep:
        return None, True

    try:
        lifetime = int(request.form.get("lifetime", current_app.config["DEFAULT_LIFETIME_MIN"]))
    except ValueError:
        lifetime = current_app.config["DEFAULT_LIFETIME_MIN"]

    from .settings_service import get_max_lifetime
    lifetime = max(1, min(lifetime, get_max_lifetime()))
    return lifetime, False




def _normalize_view_limit(view_limit_enabled: bool = False, max_views: int | None = None) -> tuple[bool, int | None]:
    if not view_limit_enabled:
        return False, None

    try:
        clean_max_views = int(max_views or 20)
    except (TypeError, ValueError):
        clean_max_views = 20

    clean_max_views = max(1, min(clean_max_views, 100))
    return True, clean_max_views


def _register_saved_public_file(
    *,
    banned=None,
    file_id: str,
    server_name: str,
    original_name: str,
    client_ip: str,
    guest_token: str,
    lifetime: int | None,
    permanent: bool,
    thumb_path: str = "",
    view_limit_enabled: bool = False,
    max_views: int | None = None,
    password: str = "",
) -> tuple[str, int | None, bool]:
    uploaded_at = utcnow()
    expires_at = None if permanent else uploaded_at + timedelta(minutes=int(lifetime))

    db = load_db()
    db[file_id] = {
        "original_name": original_name,
        "server_name": server_name,
        "uploaded_at": uploaded_at.isoformat(timespec="seconds"),
        "expires_at": (expires_at.isoformat(timespec="seconds") if expires_at else ""),
        "permanent": bool(permanent),
        "ip": client_ip,
        "by_admin": bool(is_admin()),
        "guest_token": guest_token,
        "account_id": _account_id(),
        "views": 0,
        "status": initial_upload_status(server_name),
        "moderation_requested_at": uploaded_at.isoformat(timespec="seconds") if requires_image_moderation(server_name) else "",
        "moderated_at": "",
        "moderation_decision": "pending" if requires_image_moderation(server_name) else "not_required",
        "moderation_detector": "",
        "moderation_score": None,
        "deleted_at": "",
        "delete_reason": "",
        "thumb_path": thumb_path,
        "thumb_delete_at": "",
    }
    enabled, clean_max_views = _normalize_view_limit(view_limit_enabled, max_views)
    if enabled:
        db[file_id]["view_limit_enabled"] = True
        db[file_id]["max_views"] = clean_max_views
    if password:
        # Seule une empreinte du mot de passe est gardée : il ne peut pas être relu.
        db[file_id]["password_hash"] = generate_password_hash(password)

    if thumb_path:
        db[file_id]["thumb_delete_at"] = get_expected_thumb_delete_at(db[file_id])
    if banned and banned[0] == "similar" and db[file_id]["status"] == "pending":
        # ressemble fortement à une image déjà refusée : NudeNet n'est pas sollicité, l'admin décide
        from .moderation_service import mark_image_for_review
        mark_image_for_review(db, file_id, db[file_id], "empreinte", None, "deja_refusee")
    save_db(db)
    try:  # statistiques de l'admin (envois par jour)
        from .visitor_stats_service import record_upload
        record_upload()
    except Exception:
        pass

    return file_id, lifetime, permanent


def save_saved_local_file(
    local_path: str,
    original_name: str,
    client_ip: str,
    guest_token: str,
    keep_requested: bool = False,
    view_limit_enabled: bool = False,
    max_views: int | None = None,
    password: str = "",
) -> tuple[str, int | None, bool]:
    file_id, server_name, dest, ext = _prepare_file_destination(original_name)
    lifetime, permanent = _resolve_web_lifetime(keep_requested)

    try:
        os.replace(local_path, dest)
        server_name, dest, ext, original_name = _convert_heic_to_jpeg(dest, server_name, ext, original_name)
        strip_uploaded_image(dest)
        banned = _check_banned(dest, client_ip)

        thumb_path = ""
        if is_image_extension(ext):
            try:
                thumb_path = create_thumbnail(dest, file_id)
            except Exception:
                thumb_path = ""
            create_medium(dest, file_id)

        return _register_saved_public_file(
            file_id=file_id,
            server_name=server_name,
            original_name=original_name,
            client_ip=client_ip,
            guest_token=guest_token,
            lifetime=lifetime,
            permanent=permanent,
            thumb_path=thumb_path,
            view_limit_enabled=view_limit_enabled,
            max_views=max_views,
            password=password,
            banned=banned,
        )
    except Exception:
        if os.path.exists(local_path):
            try:
                os.remove(local_path)
            except OSError:
                pass
        if os.path.exists(dest):
            try:
                os.remove(dest)
            except OSError:
                pass
        raise


def save_uploaded_file(
    file_storage,
    original_name: str,
    client_ip: str,
    guest_token: str,
    keep_requested: bool = False,
    view_limit_enabled: bool = False,
    max_views: int | None = None,
    max_size_bytes: int | None = None,
    password: str = "",
) -> tuple[str, int | None, bool]:
    file_id, server_name, dest, ext = _prepare_file_destination(original_name)

    enhance_requested = request.form.get("enhance_quality") in {"1", "on", "true", "yes"} and _is_member()
    enhance_strength = parse_strength(request.form.get("enhance_strength"))

    if enhance_requested and enhance_strength > 0 and can_enhance_extension(ext):
        original_bytes = file_storage.read()
        try:
            file_bytes = enhance_image_bytes(original_bytes, ext, enhance_strength)
        except Exception:
            file_bytes = original_bytes

        # Photo HEIC améliorée = JPEG : on change l'extension pour que tout l'ouvre.
        new_ext = get_output_extension(ext)
        if file_bytes is not original_bytes and new_ext != ext:
            new_server_name = f"{file_id}{new_ext}"
            new_dest = os.path.join(current_app.config["UPLOAD_FOLDER"], new_server_name)
            if os.path.exists(new_dest):
                file_bytes = original_bytes
            else:
                server_name, dest, ext = new_server_name, new_dest, new_ext
                original_name = os.path.splitext(original_name)[0] + new_ext

        with open(dest, "wb") as f:
            f.write(file_bytes)
    else:
        file_storage.save(dest)

    # Content-Length peut être absent (transfert « chunked ») ou mensonger :
    # on vérifie donc la taille réellement écrite sur le disque.
    if max_size_bytes and os.path.getsize(dest) > int(max_size_bytes):
        try:
            os.remove(dest)
        except OSError:
            pass
        raise FileTooLargeError("Fichier trop volumineux.")

    # Photos iPhone -> JPEG, puis retire GPS, appareil, date… (sans toucher aux pixels).
    server_name, dest, ext, original_name = _convert_heic_to_jpeg(dest, server_name, ext, original_name)
    strip_uploaded_image(dest)
    banned = _check_banned(dest, client_ip)

    thumb_path = ""
    if is_image_extension(ext):
        try:
            thumb_path = create_thumbnail(dest, file_id)
        except Exception:
            thumb_path = ""
        create_medium(dest, file_id)

    lifetime, permanent = _resolve_web_lifetime(keep_requested)

    return _register_saved_public_file(
        file_id=file_id,
        server_name=server_name,
        original_name=original_name,
        client_ip=client_ip,
        guest_token=guest_token,
        lifetime=lifetime,
        permanent=permanent,
        thumb_path=thumb_path,
        view_limit_enabled=view_limit_enabled,
        max_views=max_views,
        password=password,
        banned=banned,
    )


def get_file_record(file_id: str):
    cleanup_expired_soon()
    db = load_db()
    meta = db.get(file_id)

    if not meta:
        return None, None, None

    if is_expired(meta):  # expiré mais pas encore nettoyé : on ne le sert plus
        return None, None, None

    if (meta.get("status") or "active").lower() != "active":
        return None, None, None

    server_name = os.path.basename(meta.get("server_name", ""))
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], server_name)

    if not server_name or not os.path.isfile(path):
        return None, None, None

    return db, meta, server_name


def delete_thumbnail_by_id(file_id: str) -> bool:
    cleanup_expired()
    db = load_db()
    meta = db.get(file_id)

    if not meta:
        return False

    thumb_path = (meta.get("thumb_path") or "").strip()
    if not thumb_path:
        return False

    deleted = delete_thumbnail_file(thumb_path)
    meta["thumb_path"] = ""
    meta["thumb_delete_at"] = ""
    db[file_id] = meta

    db, _ = purge_expired_thumbnails(db)
    save_db(db)
    return deleted or True

def delete_all_thumbnails() -> int:
    cleanup_expired()
    db = load_db()
    deleted_count = 0

    for file_id, meta in db.items():
        thumb_path = (meta.get("thumb_path") or "").strip()
        if thumb_path:
            if delete_thumbnail_file(thumb_path):
                deleted_count += 1
            meta["thumb_path"] = ""
            meta["thumb_delete_at"] = ""
            db[file_id] = meta

    db, _ = purge_expired_thumbnails(db)
    save_db(db)
    return deleted_count


def delete_by_id(file_id: str, reason: str = "deleted") -> bool:
    cleanup_expired()
    db = load_db()
    meta = db.get(file_id)

    if not meta:
        return False

    server_name = os.path.basename(meta.get("server_name", ""))
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], server_name) if server_name else ""

    deleted_anything = False
    status_before = (meta.get("status") or "active").lower()
    late_check = False
    if (reason == "deleted" and status_before == "pending" and server_name and os.path.isfile(path)
            and str(meta.get("moderation_decision") or "pending") == "pending"
            and requires_image_moderation(server_name)):
        # Supprimée par son auteur AVANT l'analyse : on garde une copie privée le temps que NudeNet
        # l'analyse juste après (pour savoir ce que le filtre en aurait pensé), puis la copie est effacée.
        try:
            from .nsfw_service import late_check_path, nudenet_ready
            if nudenet_ready():
                os.replace(path, late_check_path(file_id, server_name))
                deleted_anything = late_check = True
        except Exception:
            late_check = False
    if reason not in ("deleted", "view_limit", "account_deleted", "expired", "album_deleted"):
        # Supprimée par l'admin ou par la modération : plus jamais publiée d'office sans analyse.
        from .moderation_service import _forget_approved
        _forget_approved(meta, path if server_name and os.path.isfile(path) else "")
    if server_name and os.path.isfile(path):
        try:  # image refusée : on garde son empreinte pour la refuser si elle revient
            from .image_ban_service import ban_file
            ban_file(path, reason, str(meta.get("moderation_label") or ""), file_id)
        except Exception:
            pass
    try:
        if server_name and os.path.isfile(path):
            os.remove(path)
            deleted_anything = True
    except Exception:
        pass
    remove_medium(file_id)

    if not deleted_anything and (meta.get("status") or "active").lower() != "active":
        return True

    if meta.get("account_id"):
        try:  # image d'un membre refusée par la modération : un avertissement de plus pour le compte
            from .image_ban_service import BAN_REASONS
            if reason in BAN_REASONS and (meta.get("status") or "active").lower() in ("active", "pending"):
                from .account_service import add_strike
                add_strike(meta["account_id"])
        except Exception:
            pass

    meta["status"] = "deleted"
    meta["status_before_delete"] = status_before
    meta["deleted_at"] = utcnow().isoformat(timespec="seconds")
    meta["delete_reason"] = reason or "deleted"
    if late_check:
        meta["late_check"] = "queued"
    schedule_thumbnail_cleanup(meta)
    db[file_id] = meta

    db, _ = purge_expired_thumbnails(db)

    save_db(db)
    return True


def file_password_ok(meta: dict, password: str) -> bool:
    """Le mot de passe donné correspond-il à celui du fichier ?"""
    stored = (meta or {}).get("password_hash") or ""
    if not stored or not password:
        return False
    try:
        return check_password_hash(stored, password)
    except Exception:
        return False


def replace_file(file_id: str, file_storage, original_name: str, client_ip: str, max_size_bytes: int) -> dict:
    """Remplace le contenu d'un fichier en gardant son adresse (réservé aux membres).

    La nouvelle image repasse par tout le circuit d'un envoi : taille, conversion HEIC, retrait des
    métadonnées, images interdites, puis NudeNet (elle reste privée jusqu'à la décision).
    La date d'expiration, les vues, le mot de passe et la limite de vues ne changent pas.
    """
    db = load_db()
    meta = db.get(file_id)
    if not isinstance(meta, dict):
        raise FileNotFoundError(file_id)
    restoring = (meta.get("status") or "").lower() == "deleted"
    if restoring and not can_replace_removed(meta, meta.get("account_id")):
        raise FileNotFoundError(file_id)
    if not restoring and (meta.get("status") or "active").lower() not in ("active", "pending"):
        raise FileNotFoundError(file_id)

    _tmp_id, tmp_name, tmp_dest, ext = _prepare_file_destination(original_name)
    file_storage.save(tmp_dest)
    try:
        if max_size_bytes and os.path.getsize(tmp_dest) > int(max_size_bytes):
            raise FileTooLargeError("Fichier trop volumineux.")
        tmp_name, tmp_dest, ext, original_name = _convert_heic_to_jpeg(tmp_dest, tmp_name, ext, original_name)
        strip_uploaded_image(tmp_dest)
        banned = _check_banned(tmp_dest, client_ip)
    except Exception:
        if os.path.exists(tmp_dest):
            try:
                os.remove(tmp_dest)
            except OSError:
                pass
        raise

    folder = current_app.config["UPLOAD_FOLDER"]
    old_name = os.path.basename(str(meta.get("server_name") or ""))
    new_name = f"{file_id}{ext}"
    if old_name and old_name != new_name:
        try:
            os.remove(os.path.join(folder, old_name))
        except OSError:
            pass
    os.replace(tmp_dest, os.path.join(folder, new_name))
    remove_medium(file_id)

    old_thumb = (meta.get("thumb_path") or "").strip()
    if old_thumb:
        delete_thumbnail_file(old_thumb)
    thumb_path = ""
    if is_image_extension(ext):
        try:
            thumb_path = create_thumbnail(os.path.join(folder, new_name), file_id)
        except Exception:
            thumb_path = ""
        create_medium(os.path.join(folder, new_name), file_id)

    db = load_db()
    meta = db.get(file_id) or meta
    now = utcnow().isoformat(timespec="seconds")
    needs_check = requires_image_moderation(new_name)
    meta.update({
        "original_name": original_name,
        "server_name": new_name,
        "status": initial_upload_status(new_name),
        "moderation_requested_at": now if needs_check else "",
        "moderated_at": "",
        "moderation_decision": "pending" if needs_check else "not_required",
        "moderation_detector": "",
        "moderation_score": None,
        "moderation_label": "",
        "moderation_attempts": 0,
        "reports": [],
        "thumb_path": thumb_path,
        "thumb_delete_at": "",
        "replaced_at": now,
        "replace_count": int(meta.get("replace_count") or 0) + 1,
        "ip": client_ip,
    })
    if restoring:  # image retirée par la modération, remplacée par une autre : le lien reprend vie
        for key in ("deleted_at", "delete_reason", "status_before_delete"):
            meta.pop(key, None)
        meta["restored_after_removal"] = now
    if thumb_path:
        meta["thumb_delete_at"] = get_expected_thumb_delete_at(meta)
    db[file_id] = meta
    if banned and banned[0] == "similar" and meta["status"] == "pending":
        from .moderation_service import mark_image_for_review
        mark_image_for_review(db, file_id, meta, "empreinte", None, "deja_refusee")
    save_db(db)
    return meta
