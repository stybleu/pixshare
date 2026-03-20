import os
import secrets
from datetime import datetime, timedelta

from flask import current_app, request, session, url_for
from PIL import Image

try:
    from pillow_heif import register_heif_opener
    register_heif_opener()
    HEIF_ENABLED = True
except Exception:
    HEIF_ENABLED = False

from pixshare.storage import thumbnail_dir
from .auth_service import is_admin
from .json_services import load_db, save_db, load_views, save_views, load_votes, save_votes
from .time_service import parse_dt, utcnow
from .image_quality_service import can_enhance_extension, enhance_image_bytes
from .settings_service import get_thumbnail_retention_hours, permanent_files_enabled


IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".tif", ".tiff", ".heic", ".heif"
}
VIDEO_EXTENSIONS = {".mp4", ".webm", ".avi"}


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
    tok = session.get("guest_token")
    if not tok:
        tok = secrets.token_urlsafe(16)
        session["guest_token"] = tok
    return tok


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

        public_path = os.path.join(
            current_app.config["UPLOAD_FOLDER"],
            os.path.basename(meta.get("server_name", ""))
        )
        public_exists = os.path.isfile(public_path)
        status = (meta.get("status") or "active").lower()

        if status != "active" and not public_exists and not meta.get("thumb_path"):
            to_remove.append(file_id)

    for file_id in to_remove:
        db.pop(file_id, None)
        changed = True

    return db, changed


def cleanup_expired() -> int:
    db = load_db()
    now = utcnow()
    votes = load_votes()
    removed_public_files = 0
    changed = False

    for file_id, meta in list(db.items()):
        status = (meta.get("status") or "active").lower()
        if status != "active":
            continue
        if meta.get("permanent") or not meta.get("expires_at"):
            continue

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

        meta["status"] = "expired"
        meta["deleted_at"] = now.isoformat(timespec="seconds")
        meta["delete_reason"] = "expired"
        schedule_thumbnail_cleanup(meta, now)
        db[file_id] = meta
        votes.pop(file_id, None)
        changed = True

    db, thumbs_changed = purge_expired_thumbnails(db)
    changed = changed or thumbs_changed

    if changed:
        save_db(db)
        save_votes(votes)

    return removed_public_files


def file_meta(file_id: str):
    cleanup_expired()

    if not file_id:
        return None

    db = load_db()
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

    previewable = ext in IMAGE_EXTENSIONS.union(VIDEO_EXTENSIONS) if public_exists else False
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
    mtime_h = (
        datetime.fromtimestamp(os.stat(path).st_mtime).strftime("%Y-%m-%d %H:%M")
        if public_exists
        else (meta.get("deleted_at") or meta.get("uploaded_at", ""))
    )

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
        "download_url": url_for("public.download", file_id=file_id, _external=True) if public_exists else "",
        "public_url": url_for("public.public_file", file_id=file_id, _external=True) if public_exists else "",
        "raw_url": url_for("public.view_file", file_id=file_id, _external=True) if public_exists else "",
        "previewable": previewable,
        "views": int(meta.get("views", 0) or 0),
        "status": status,
        "deleted_at": meta.get("deleted_at", ""),
        "delete_reason": meta.get("delete_reason", ""),
        "thumb_url": url_for("admin.admin_thumbnail", file_id=file_id, _external=False) if thumb_exists else "",
        "has_public_file": public_exists,
        "has_thumb": thumb_exists,
        "thumb_delete_at": meta.get("thumb_delete_at", ""),
    }


def list_all_files():
    cleanup_expired()
    db = load_db()
    items = []

    for file_id in db.keys():
        fm = file_meta(file_id)
        if fm:
            items.append(fm)

    items.sort(key=lambda x: (x.get("uploaded_at", ""), x.get("mtime_h", "")), reverse=True)
    return items


def list_guest_files():
    cleanup_expired()
    db = load_db()
    guest_token = get_guest_token()
    items = []

    for file_id, meta in db.items():
        if meta.get("guest_token") != guest_token:
            continue

        fm = file_meta(file_id)
        if fm and fm.get("status") == "active":
            items.append(fm)

    items.sort(key=lambda x: x.get("mtime_h", ""), reverse=True)
    return items


def can_keep_uploads() -> bool:
    if not permanent_files_enabled():
        return False

    return current_app.config["PERMANENT_UPLOADS_ENABLED"] and (
        not current_app.config["PERMANENT_UPLOADS_ADMIN_ONLY"] or is_admin()
    )


def save_uploaded_file(file_storage, original_name: str, client_ip: str, guest_token: str, keep_requested: bool = False) -> tuple[str, int | None, bool]:
    ext = safe_ext(original_name)

    file_id = generate_file_id()
    server_name = f"{file_id}{ext}"
    dest = os.path.join(current_app.config["UPLOAD_FOLDER"], server_name)

    while os.path.exists(dest):
        file_id = generate_file_id()
        server_name = f"{file_id}{ext}"
        dest = os.path.join(current_app.config["UPLOAD_FOLDER"], server_name)

    enhance_requested = request.form.get("enhance_quality") in {"1", "on", "true", "yes"}

    if enhance_requested and can_enhance_extension(ext):
        file_bytes = file_storage.read()
        try:
            file_bytes = enhance_image_bytes(file_bytes, ext)
        except Exception:
            pass

        with open(dest, "wb") as f:
            f.write(file_bytes)
    else:
        file_storage.save(dest)

    thumb_path = ""
    if is_image_extension(ext):
        try:
            thumb_path = create_thumbnail(dest, file_id)
        except Exception:
            thumb_path = ""

    allow_keep = can_keep_uploads()
    if keep_requested and allow_keep:
        lifetime = None
        permanent = True
    else:
        permanent = False
        try:
            lifetime = int(request.form.get("lifetime", current_app.config["DEFAULT_LIFETIME_MIN"]))
        except ValueError:
            lifetime = current_app.config["DEFAULT_LIFETIME_MIN"]

        lifetime = max(1, min(lifetime, current_app.config["MAX_LIFETIME_MIN"]))

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
        "guest_token": guest_token,
        "views": 0,
        "status": "active",
        "deleted_at": "",
        "delete_reason": "",
        "thumb_path": thumb_path,
        "thumb_delete_at": "",
    }
    save_db(db)

    return file_id, lifetime, permanent


def save_api_uploaded_file(
    file_storage,
    original_name: str,
    client_ip: str,
    api_key_value: str,
    api_key_name: str,
    requested_lifetime: int,
    keep_requested: bool,
    key_data: dict | None = None,
) -> tuple[str, int | None, bool]:
    key_data = key_data or {}
    ext = safe_ext(original_name)

    file_id = generate_file_id()
    server_name = f"{file_id}{ext}"
    dest = os.path.join(current_app.config["UPLOAD_FOLDER"], server_name)

    while os.path.exists(dest):
        file_id = generate_file_id()
        server_name = f"{file_id}{ext}"
        dest = os.path.join(current_app.config["UPLOAD_FOLDER"], server_name)

    file_storage.save(dest)

    thumb_path = ""
    if is_image_extension(ext):
        try:
            thumb_path = create_thumbnail(dest, file_id)
        except Exception:
            thumb_path = ""

    allow_permanent = bool(key_data.get("allow_permanent", False))
    permanent = bool(keep_requested and allow_permanent)

    allowed_lifetimes = key_data.get("allowed_lifetimes") or [5, 10, 20, 30, 60]
    clean_lifetimes = []
    for value in allowed_lifetimes:
        try:
            ivalue = int(value)
        except (TypeError, ValueError):
            continue
        if ivalue > 0 and ivalue not in clean_lifetimes:
            clean_lifetimes.append(ivalue)
    clean_lifetimes = sorted(clean_lifetimes or [10])

    if permanent:
        lifetime = None
    else:
        try:
            lifetime = int(requested_lifetime)
        except (TypeError, ValueError):
            lifetime = int(key_data.get("default_lifetime_minutes", clean_lifetimes[0]))

        if lifetime not in clean_lifetimes:
            try:
                os.remove(dest)
            except Exception:
                pass
            if thumb_path:
                delete_thumbnail_file(thumb_path)
            raise ValueError(f"Lifetime invalide. Valeurs autorisées : {', '.join(str(x) for x in clean_lifetimes)} minutes.")

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
        "guest_token": f"api:{api_key_name}",
        "api_key": api_key_value,
        "api_name": api_key_name,
        "views": 0,
        "status": "active",
        "deleted_at": "",
        "delete_reason": "",
        "thumb_path": thumb_path,
        "thumb_delete_at": "",
    }
    save_db(db)

    return file_id, lifetime, permanent


def get_file_record(file_id: str):
    cleanup_expired()
    db = load_db()
    meta = db.get(file_id)

    if not meta:
        return None, None, None

    if (meta.get("status") or "active").lower() != "active":
        return None, None, None

    server_name = os.path.basename(meta.get("server_name", ""))
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], server_name)

    if not server_name or not os.path.isfile(path):
        return None, None, None

    return db, meta, server_name


def delete_by_id(file_id: str, reason: str = "deleted") -> bool:
    cleanup_expired()
    db = load_db()
    meta = db.get(file_id)

    if not meta:
        return False

    server_name = os.path.basename(meta.get("server_name", ""))
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], server_name) if server_name else ""

    deleted_anything = False
    try:
        if server_name and os.path.isfile(path):
            os.remove(path)
            deleted_anything = True
    except Exception:
        pass

    if not deleted_anything and (meta.get("status") or "active").lower() != "active":
        return True

    meta["status"] = "deleted"
    meta["deleted_at"] = utcnow().isoformat(timespec="seconds")
    meta["delete_reason"] = reason or "deleted"
    schedule_thumbnail_cleanup(meta)
    db[file_id] = meta

    votes = load_votes()
    votes.pop(file_id, None)

    db, _ = purge_expired_thumbnails(db)

    save_db(db)
    save_votes(votes)
    return True