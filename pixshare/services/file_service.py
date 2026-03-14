import os
import secrets
from datetime import datetime, timedelta
from flask import current_app, request, session, url_for
from .auth_service import is_admin
from .json_services import load_db, save_db, load_views, save_views, load_votes, save_votes
from .request_service import get_client_ip
from .time_service import parse_dt, utcnow


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


def cleanup_expired() -> int:
    db = load_db()
    now = utcnow()
    to_delete = []

    for file_id, meta in db.items():
        if meta.get("permanent") or not meta.get("expires_at"):
            continue
        exp = parse_dt(meta.get("expires_at", ""))
        if exp <= now:
            to_delete.append(file_id)

    removed = 0
    votes = load_votes()
    for file_id in to_delete:
        meta = db.get(file_id, {})
        server_name = os.path.basename(meta.get("server_name", ""))
        path = os.path.join(current_app.config["UPLOAD_FOLDER"], server_name)
        try:
            if server_name and os.path.isfile(path):
                os.remove(path)
        except Exception:
            pass
        db.pop(file_id, None)
        votes.pop(file_id, None)
        removed += 1

    if removed:
        save_db(db)
        save_votes(votes)
    return removed


def file_meta(file_id: str):
    cleanup_expired()
    if not file_id:
        return None

    db = load_db()
    meta = db.get(file_id)
    if not meta:
        return None

    server_name = os.path.basename(meta.get("server_name", ""))
    if not server_name:
        return None

    path = os.path.join(current_app.config["UPLOAD_FOLDER"], server_name)
    if not os.path.isfile(path):
        return None

    stat = os.stat(path)
    ext = os.path.splitext(server_name)[1].lower()
    previewable = ext in {".png", ".jpg", ".jpeg", ".gif", ".webp"}
    permanent = bool(meta.get("permanent")) or (not meta.get("expires_at"))

    if permanent:
        remaining_h = "∞"
    else:
        exp = parse_dt(meta.get("expires_at", ""))
        remaining_s = max(0, int((exp - utcnow()).total_seconds()))
        remaining_min = remaining_s // 60
        remaining_sec = remaining_s % 60
        remaining_h = f"{remaining_min:02d}:{remaining_sec:02d}"

    return {
        "id": file_id,
        "original": meta.get("original_name", "unknown"),
        "server": server_name,
        "uploaded_at": meta.get("uploaded_at", ""),
        "expires_at": meta.get("expires_at", ""),
        "remaining_h": remaining_h,
        "permanent": permanent,
        "ip": meta.get("ip", ""),
        "size_h": human_size(stat.st_size),
        "mtime_h": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
        "download_url": url_for("public.download", file_id=file_id, _external=True),
        "public_url": url_for("public.public_file", file_id=file_id, _external=True),
        "raw_url": url_for("public.view_file", file_id=file_id, _external=True),
        "previewable": previewable,
        "views": int(meta.get("views", 0) or 0),
    }


def list_all_files():
    cleanup_expired()
    db = load_db()
    items = []
    for file_id in db.keys():
        fm = file_meta(file_id)
        if fm:
            items.append(fm)
    items.sort(key=lambda x: x.get("mtime_h", ""), reverse=True)
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
        if fm:
            items.append(fm)
    items.sort(key=lambda x: x.get("mtime_h", ""), reverse=True)
    return items


def can_keep_uploads() -> bool:
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

    file_storage.save(dest)

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
    }
    save_db(db)
    return file_id, lifetime, permanent


def get_file_record(file_id: str):
    cleanup_expired()
    db = load_db()
    meta = db.get(file_id)
    if not meta:
        return None, None, None
    server_name = os.path.basename(meta.get("server_name", ""))
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], server_name)
    if not server_name or not os.path.isfile(path):
        return None, None, None
    return db, meta, server_name


def delete_by_id(file_id: str) -> bool:
    cleanup_expired()
    db = load_db()
    meta = db.get(file_id)
    if not meta:
        return False
    server_name = os.path.basename(meta.get("server_name", ""))
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], server_name)
    try:
        if server_name and os.path.isfile(path):
            os.remove(path)
    except Exception:
        pass
    db.pop(file_id, None)
    save_db(db)

    votes = load_votes()
    if file_id in votes:
        votes.pop(file_id, None)
        save_votes(votes)
    return True
