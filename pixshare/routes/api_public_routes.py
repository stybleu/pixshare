from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from flask import Blueprint, current_app, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

from pixshare.services.api_auth_service import (
    authenticate_api_key,
    consume_upload_for_key,
    get_api_max_file_size_bytes,
    remaining_uploads_info,
)
from pixshare.services.json_services import load_files, save_files

api_bp = Blueprint("api", __name__, url_prefix="/api")


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def api_error(status_code: int, error_code: str, message: str):
    return jsonify({
        "success": False,
        "status": status_code,
        "error": {
            "code": error_code,
            "message": message,
        }
    }), status_code


def api_success(data: dict[str, Any], status_code: int = 200):
    return jsonify({
        "success": True,
        "status": status_code,
        "data": data,
    }), status_code


def allowed_extensions() -> set[str]:
    values = current_app.config.get(
        "ALLOWED_EXTENSIONS",
        {"png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff", "mp4", "webm"}
    )
    return {str(v).lower().lstrip(".") for v in values}


def is_allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in allowed_extensions()


def ensure_upload_folder() -> Path:
    upload_folder = current_app.config.get("UPLOAD_FOLDER", "uploads")
    path = Path(upload_folder)
    path.mkdir(parents=True, exist_ok=True)
    return path


def build_file_id() -> str:
    return secrets.token_urlsafe(8).replace("-", "").replace("_", "")


def build_storage_name(original_filename: str) -> str:
    ext = Path(original_filename).suffix.lower()
    return f"{secrets.token_urlsafe(12).replace('-', '').replace('_', '')}{ext}"


def build_delete_token() -> str:
    return secrets.token_urlsafe(16).replace("-", "").replace("_", "")


def get_file_size(file_path: Path) -> int:
    try:
        return file_path.stat().st_size
    except OSError:
        return 0


def parse_expiration_minutes(auth_key_data: dict[str, Any]) -> int | None:
    """
    Retourne :
    - None => permanent
    - int => durée en minutes
    """
    requested = request.form.get("expiration", "").strip()

    allow_permanent = bool(auth_key_data.get("allow_permanent", False))
    default_lifetime = int(auth_key_data.get("default_lifetime_minutes", 10))
    allowed_lifetimes = auth_key_data.get("allowed_lifetimes", [5, 10, 20, 30, 60])

    if requested == "":
        return default_lifetime

    if requested.lower() in {"0", "permanent", "never", "none"}:
        if allow_permanent:
            return None
        return default_lifetime

    try:
        minutes = int(requested)
    except ValueError:
        return default_lifetime

    if minutes in allowed_lifetimes:
        return minutes

    return default_lifetime


def build_file_urls(file_record: dict[str, Any]) -> dict[str, str]:
    filename = file_record["stored_filename"]
    file_id = file_record["id"]
    delete_token = file_record.get("delete_token", "")
    base = request.url_root.rstrip("/")

    return {
        "url": f"{base}/api/raw/{filename}",
        "url_viewer": f"{base}/file/{file_id}",
        "api_url": f"{base}/api/file/{file_id}",
        "delete_url": f"{base}/api/delete/{delete_token}" if delete_token else "",
    }


def serialize_file_record(file_record: dict[str, Any]) -> dict[str, Any]:
    urls = build_file_urls(file_record)

    return {
        "id": file_record["id"],
        "title": file_record.get("original_filename", ""),
        "filename": file_record.get("stored_filename", ""),
        "original_filename": file_record.get("original_filename", ""),
        "url_viewer": urls["url_viewer"],
        "url": urls["url"],
        "display_url": urls["url"],
        "delete_url": urls["delete_url"],
        "mime": file_record.get("mime", "application/octet-stream"),
        "extension": file_record.get("extension", ""),
        "size": file_record.get("size", 0),
        "uploaded_at": file_record.get("uploaded_at"),
        "expiration": file_record.get("expires_at"),
        "is_permanent": file_record.get("is_permanent", False),
        "uploader_api_key_name": file_record.get("api_key_name", ""),
    }


def load_all_files() -> dict[str, Any]:
    data = load_files()
    if not isinstance(data, dict):
        return {}
    return data


def save_all_files(data: dict[str, Any]) -> None:
    save_files(data)


# ---------------------------------------------------------
# Routes
# ---------------------------------------------------------

@api_bp.route("/account", methods=["GET"])
def api_account():
    auth = authenticate_api_key()
    if not auth.ok:
        return api_error(
            auth.status_code,
            auth.error or "auth_error",
            auth.message or "Accès refusé."
        )

    key_data = auth.key_data or {}
    limits = remaining_uploads_info(key_data)

    return api_success({
        "key_name": key_data.get("name", ""),
        "is_active": bool(key_data.get("is_active", False)),
        "max_file_size_mb": int(key_data.get("max_file_size_mb", 0)),
        "allow_permanent": bool(key_data.get("allow_permanent", False)),
        "default_lifetime_minutes": int(key_data.get("default_lifetime_minutes", 10)),
        "allowed_lifetimes": key_data.get("allowed_lifetimes", []),
        "limits": limits,
    })


@api_bp.route("/upload", methods=["POST"])
def api_upload():
    auth = authenticate_api_key()
    if not auth.ok:
        return api_error(
            auth.status_code,
            auth.error or "auth_error",
            auth.message or "Accès refusé."
        )

    key_value = auth.key_value or ""
    key_data = auth.key_data or {}

    if "file" not in request.files:
        return api_error(400, "missing_file", "Aucun fichier envoyé dans le champ 'file'.")

    uploaded_file = request.files["file"]
    if not uploaded_file or not uploaded_file.filename:
        return api_error(400, "empty_file", "Fichier vide ou nom de fichier absent.")

    original_filename = secure_filename(uploaded_file.filename)
    if not original_filename:
        return api_error(400, "invalid_filename", "Nom de fichier invalide.")

    if not is_allowed_file(original_filename):
        return api_error(400, "file_type_not_allowed", "Type de fichier non autorisé.")

    max_size_bytes = get_api_max_file_size_bytes(key_data)

    uploaded_file.stream.seek(0, os.SEEK_END)
    file_size = uploaded_file.stream.tell()
    uploaded_file.stream.seek(0)

    if file_size > max_size_bytes:
        return api_error(
            413,
            "file_too_large",
            f"Fichier trop volumineux. Taille max autorisée : {key_data.get('max_file_size_mb', 10)} MB."
        )

    expiration_minutes = parse_expiration_minutes(key_data)
    now = datetime.utcnow()
    expires_at = None if expiration_minutes is None else (now + timedelta(minutes=expiration_minutes))

    upload_folder = ensure_upload_folder()
    stored_filename = build_storage_name(original_filename)
    destination = upload_folder / stored_filename

    uploaded_file.save(destination)

    real_size = get_file_size(destination)
    ext = Path(original_filename).suffix.lower().lstrip(".")
    mime = uploaded_file.mimetype or "application/octet-stream"

    file_id = build_file_id()
    delete_token = build_delete_token()

    files_data = load_all_files()
    file_record = {
        "id": file_id,
        "delete_token": delete_token,

        # format historique du site public
        "original_name": original_filename,
        "server_name": stored_filename,
        "permanent": expires_at is None,

        # format API
        "original_filename": original_filename,
        "stored_filename": stored_filename,
        "extension": ext,
        "mime": mime,
        "size": real_size,

        "uploaded_at": now.isoformat() + "Z",
        "expires_at": None if expires_at is None else expires_at.isoformat() + "Z",

        "is_permanent": expires_at is None,
        "api_key_name": key_data.get("name", ""),
        "api_key_value": key_value,
        "source": "api",

        # cohérence avec le reste du site
        "views": 0,
        "status": "active",
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr or ""),
    }

    files_data[file_id] = file_record
    save_all_files(files_data)

    updated_key_data = consume_upload_for_key(key_value)
    limits = remaining_uploads_info(updated_key_data or key_data)

    return api_success({
        **serialize_file_record(file_record),
        "limits": limits,
    }, status_code=200)


@api_bp.route("/file/<file_id>", methods=["GET"])
def api_file_info(file_id: str):
    auth = authenticate_api_key()
    if not auth.ok:
        return api_error(
            auth.status_code,
            auth.error or "auth_error",
            auth.message or "Accès refusé."
        )

    files_data = load_all_files()
    file_record = files_data.get(file_id)

    if not file_record:
        return api_error(404, "file_not_found", "Fichier introuvable.")

    return api_success(serialize_file_record(file_record))


@api_bp.route("/file/<file_id>", methods=["DELETE"])
def api_delete_file(file_id: str):
    auth = authenticate_api_key()
    if not auth.ok:
        return api_error(
            auth.status_code,
            auth.error or "auth_error",
            auth.message or "Accès refusé."
        )

    key_value = auth.key_value or ""
    files_data = load_all_files()
    file_record = files_data.get(file_id)

    if not file_record:
        return api_error(404, "file_not_found", "Fichier introuvable.")

    if file_record.get("api_key_value") != key_value:
        return api_error(403, "forbidden_file_access", "Cette clé API ne peut pas supprimer ce fichier.")

    upload_folder = ensure_upload_folder()
    stored_filename = file_record.get("stored_filename") or file_record.get("server_name", "")
    file_path = upload_folder / stored_filename

    if stored_filename and file_path.exists():
        try:
            file_path.unlink()
        except OSError:
            return api_error(500, "delete_failed", "Impossible de supprimer le fichier du disque.")

    files_data.pop(file_id, None)
    save_all_files(files_data)

    return api_success({
        "id": file_id,
        "deleted": True,
    })


@api_bp.route("/delete/<token>", methods=["GET", "DELETE"])
def api_delete_by_token(token: str):
    files_data = load_all_files()

    file_id = None
    file_record = None

    for fid, record in files_data.items():
        if record.get("delete_token") == token:
            file_id = fid
            file_record = record
            break

    if not file_record or not file_id:
        return api_error(404, "invalid_delete_token", "Token de suppression invalide.")

    upload_folder = ensure_upload_folder()
    stored_filename = file_record.get("stored_filename") or file_record.get("server_name", "")
    file_path = upload_folder / stored_filename

    if stored_filename and file_path.exists():
        try:
            file_path.unlink()
        except OSError:
            return api_error(500, "delete_failed", "Impossible de supprimer le fichier.")

    files_data.pop(file_id, None)
    save_all_files(files_data)

    return api_success({
        "id": file_id,
        "deleted": True,
    })


@api_bp.route("/raw/<path:filename>", methods=["GET"])
def api_raw_file(filename: str):
    upload_folder = ensure_upload_folder()
    return send_from_directory(upload_folder, filename)


api_public_bp = api_bp