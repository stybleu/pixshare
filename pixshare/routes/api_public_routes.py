from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from PIL import Image
from flask import Blueprint, Response, current_app, request, send_file, send_from_directory
from werkzeug.utils import secure_filename

from pixshare.services.api_auth_service import (
    authenticate_api_key,
    consume_upload_for_key,
    get_api_max_file_size_bytes,
    remaining_uploads_info,
)
from pixshare.services.json_services import load_files, save_files

api_bp = Blueprint("api", __name__, url_prefix="/api")

from pixshare.config import Config
config = Config()
# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def pretty_json_response(payload: dict[str, Any], status_code: int = 200) -> Response:
    return Response(
        json.dumps(payload, ensure_ascii=False, indent=2),
        status=status_code,
        mimetype="application/json",
    )


def api_error(status_code: int, error_code: str, message: str):
    return pretty_json_response(
        {
            "success": False,
            "status": status_code,
            "error": {
                "code": error_code,
                "message": message,
            },
        },
        status_code=status_code,
    )


def api_success(data: dict[str, Any], status_code: int = 200):
    return pretty_json_response(
        {
            "success": True,
            "status": status_code,
            "data": data,
        },
        status_code=status_code,
    )


def allowed_extensions() -> set[str]:
    values = current_app.config.get(
        "ALLOWED_EXTENSIONS",
        {"png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff", "mp4", "webm"},
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


def load_all_files() -> dict[str, Any]:
    data = load_files()
    if not isinstance(data, dict):
        return {}
    return data


def save_all_files(data: dict[str, Any]) -> None:
    save_files(data)


def get_real_ip() -> str:
    x_forwarded_for = (request.headers.get("X-Forwarded-For") or "").strip()
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()

    cf_connecting_ip = (request.headers.get("CF-Connecting-IP") or "").strip()
    if cf_connecting_ip:
        return cf_connecting_ip

    return (request.remote_addr or "").strip()


def hash_api_key(key_value: str) -> str:
    return hashlib.sha256(key_value.encode("utf-8")).hexdigest()


def build_file_id(files_data: dict[str, Any]) -> str:
    while True:
        file_id = secrets.token_urlsafe(8).replace("-", "").replace("_", "")
        if file_id and file_id not in files_data:
            return file_id


def build_storage_name(original_filename: str, upload_folder: Path) -> str:
    ext = Path(original_filename).suffix.lower()
    while True:
        filename = f"{secrets.token_urlsafe(12).replace('-', '').replace('_', '')}{ext}"
        if not (upload_folder / filename).exists():
            return filename


def build_delete_token(files_data: dict[str, Any]) -> str:
    existing_tokens = {
        str(record.get("delete_token", "")).strip()
        for record in files_data.values()
        if isinstance(record, dict)
    }

    while True:
        token = secrets.token_urlsafe(16).replace("-", "").replace("_", "")
        if token and token not in existing_tokens:
            return token


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


def parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def is_file_expired(file_record: dict[str, Any]) -> bool:
    if file_record.get("is_permanent", False):
        return False

    expires_at = parse_iso_datetime(file_record.get("expires_at"))
    if expires_at is None:
        return False

    now = datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    return expires_at <= now


def file_belongs_to_key(file_record: dict[str, Any], key_value: str) -> bool:
    if not key_value:
        return False

    expected_hash = file_record.get("api_key_hash", "")
    if expected_hash:
        return expected_hash == hash_api_key(key_value)

    # compatibilité temporaire avec anciens enregistrements
    old_key_value = file_record.get("api_key_value", "")
    return old_key_value == key_value


def find_file_by_stored_filename(files_data: dict[str, Any], filename: str) -> dict[str, Any] | None:
    for record in files_data.values():
        if not isinstance(record, dict):
            continue

        stored_filename = record.get("stored_filename") or record.get("server_name", "")
        if stored_filename == filename:
            return record

    return None


def get_output_format_from_filename(filename: str) -> str:
    ext = Path(filename).suffix.lower().lstrip(".")

    mapping = {
        "jpg": "JPEG",
        "jpeg": "JPEG",
        "png": "PNG",
        "webp": "WEBP",
        "bmp": "BMP",
        "gif": "GIF",
        "tif": "TIFF",
        "tiff": "TIFF",
    }

    return mapping.get(ext, "PNG")


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
            auth.message or "Accès refusé.",
        )

    key_data = auth.key_data or {}
    limits = remaining_uploads_info(key_data)

    return api_success(
        {
            "key": {
                "name": key_data.get("name", ""),
                "is_active": bool(key_data.get("is_active", False)),
            },
            "quota": {
                "total": {
                    "used": limits["used_total"],
                    "max": limits["max_total"],
                    "remaining": limits["remaining_total"],
                },
                "daily": {
                    "used": limits["used_today"],
                    "max": limits["max_per_day"],
                    "remaining": limits["remaining_today"],
                },
            },
            "limits": {
                "max_file_size_mb": int(key_data.get("max_file_size_mb", 0)),
                "allow_permanent": bool(key_data.get("allow_permanent", False)),
            },
            "upload_config": {
    "default_lifetime_minutes": int(key_data.get("default_lifetime_minutes", 10)),
    "allowed_lifetimes": key_data.get("allowed_lifetimes", []),

    "resize": {
        "enabled": True,
        "mode": "ratio_only",
        "ratio": {
            "min": 0.1,
            "max": 3.0
        },
        "max_dimension": config.API_MAX_DIMENSION
    }
}
        }
    )


@api_bp.route("/upload", methods=["POST"])
def api_upload():
    auth = authenticate_api_key()
    if not auth.ok:
        return api_error(
            auth.status_code,
            auth.error or "auth_error",
            auth.message or "Accès refusé.",
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
            f"Fichier trop volumineux. Taille max autorisée : {key_data.get('max_file_size_mb', 10)} MB.",
        )

    expiration_minutes = parse_expiration_minutes(key_data)
    now = datetime.utcnow()
    expires_at = None if expiration_minutes is None else (now + timedelta(minutes=expiration_minutes))

    files_data = load_all_files()
    upload_folder = ensure_upload_folder()

    stored_filename = build_storage_name(original_filename, upload_folder)
    destination = upload_folder / stored_filename

    try:
        uploaded_file.save(destination)
    except OSError:
        return api_error(500, "upload_save_failed", "Impossible d'enregistrer le fichier.")

    real_size = get_file_size(destination)
    ext = Path(original_filename).suffix.lower().lstrip(".")
    mime = uploaded_file.mimetype or "application/octet-stream"

    image_width = None
    image_height = None
    resize_info = None

    try:
        with Image.open(destination) as img:
            image_width, image_height = img.size

            max_dim = 4000
            global_ratio_max = 3.0
            global_ratio_min = 0.1

            max_ratio_for_this_image = min(
                max_dim / image_width,
                max_dim / image_height,
                global_ratio_max,
            )

            resize_info = {
                "enabled": True,
                "mode": "ratio_only",
                "ratio": {
                    "min": global_ratio_min,
                    "max": global_ratio_max,
                    "max_for_this_image": round(max_ratio_for_this_image, 4),
                },
                "max_dimension": max_dim,
            }
    except Exception:
        # Ce n'est pas une image lisible par PIL ou le format ne permet pas l'analyse.
        image_width = None
        image_height = None
        resize_info = None

    file_id = build_file_id(files_data)
    delete_token = build_delete_token(files_data)

    file_record = {
        "id": file_id,
        "delete_token": delete_token,
        "original_name": original_filename,
        "server_name": stored_filename,
        "permanent": expires_at is None,
        "original_filename": original_filename,
        "stored_filename": stored_filename,
        "extension": ext,
        "mime": mime,
        "size": real_size,
        "uploaded_at": now.isoformat() + "Z",
        "expires_at": None if expires_at is None else expires_at.isoformat() + "Z",
        "is_permanent": expires_at is None,
        "api_key_name": key_data.get("name", ""),
        "api_key_hash": hash_api_key(key_value),
        "source": "api",
        "views": 0,
        "status": "active",
        "ip": get_real_ip(),
        "width": image_width,
        "height": image_height,
    }

    files_data[file_id] = file_record

    try:
        save_all_files(files_data)
    except Exception:
        try:
            if destination.exists():
                destination.unlink()
        except OSError:
            pass
        return api_error(500, "metadata_save_failed", "Impossible d'enregistrer les métadonnées du fichier.")

    updated_key_data = consume_upload_for_key(key_value)
    limits = remaining_uploads_info(updated_key_data or key_data)

    response_data = {
        **serialize_file_record(file_record),
        "limits": limits,
    }

    if image_width is not None and image_height is not None:
        response_data["width"] = image_width
        response_data["height"] = image_height

    if resize_info is not None:
        response_data["resize"] = resize_info

    return api_success(
        response_data,
        status_code=200,
    )

@api_bp.route("/file/<file_id>", methods=["GET"])
def api_file_info(file_id: str):
    auth = authenticate_api_key()
    if not auth.ok:
        return api_error(
            auth.status_code,
            auth.error or "auth_error",
            auth.message or "Accès refusé.",
        )

    key_value = auth.key_value or ""
    files_data = load_all_files()
    file_record = files_data.get(file_id)

    if not file_record:
        return api_error(404, "file_not_found", "Fichier introuvable.")

    if not file_belongs_to_key(file_record, key_value):
        return api_error(403, "forbidden_file_access", "Cette clé API ne peut pas accéder à ce fichier.")

    if is_file_expired(file_record):
        return api_error(410, "file_expired", "Ce fichier a expiré.")

    return api_success(serialize_file_record(file_record))


@api_bp.route("/file/<file_id>", methods=["DELETE"])
def api_delete_file(file_id: str):
    auth = authenticate_api_key()
    if not auth.ok:
        return api_error(
            auth.status_code,
            auth.error or "auth_error",
            auth.message or "Accès refusé.",
        )

    key_value = auth.key_value or ""
    files_data = load_all_files()
    file_record = files_data.get(file_id)

    if not file_record:
        return api_error(404, "file_not_found", "Fichier introuvable.")

    if not file_belongs_to_key(file_record, key_value):
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

    try:
        save_all_files(files_data)
    except Exception:
        return api_error(500, "metadata_delete_failed", "Le fichier a été supprimé du disque, mais la base n'a pas pu être mise à jour.")

    return api_success(
        {
            "id": file_id,
            "deleted": True,
        }
    )


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

    try:
        save_all_files(files_data)
    except Exception:
        return api_error(500, "metadata_delete_failed", "Le fichier a été supprimé du disque, mais la base n'a pas pu être mise à jour.")

    return api_success(
        {
            "id": file_id,
            "deleted": True,
        }
    )


@api_bp.route("/raw/<path:filename>", methods=["GET"])
def api_raw_file(filename: str):
    files_data = load_all_files()
    file_record = find_file_by_stored_filename(files_data, filename)

    if not file_record:
        return api_error(404, "file_not_found", "Fichier introuvable.")

    if is_file_expired(file_record):
        return api_error(410, "file_expired", "Ce fichier a expiré.")

    upload_folder = ensure_upload_folder()
    stored_filename = file_record.get("stored_filename") or file_record.get("server_name", "")

    if not stored_filename:
        return api_error(404, "file_not_found", "Fichier introuvable.")

    file_path = upload_folder / stored_filename
    if not file_path.exists():
        return api_error(404, "file_not_found", "Fichier introuvable sur le disque.")

    ratio = request.args.get("ratio", type=float)

    if ratio is None:
        return send_from_directory(upload_folder, stored_filename)

    if ratio < 0.1 or ratio > 3.0:
        return api_error(400, "invalid_ratio", "Le ratio doit être entre 0.1 et 3.0.")

    try:
        with Image.open(file_path) as img:
            original_width, original_height = img.size
    
            MAX_DIM = config.API_MAX_DIMENSION
    
            # 👉 Calcul du ratio max réel pour cette image
            max_ratio_for_this_image = min(
                MAX_DIM / original_width,
                MAX_DIM / original_height,
                3.0  # ton max global actuel
            )
    
            # 👉 Calcul des nouvelles dimensions demandées
            new_width = int(original_width * ratio)
            new_height = int(original_height * ratio)
    
            # 👉 Vérification
            if new_width > MAX_DIM or new_height > MAX_DIM:
                return api_error(
                    400,
                    "image_too_large",
                    f"Dimensions trop grandes. Ratio max autorisé pour cette image : {round(max_ratio_for_this_image, 2)}"
                )

            output_format = get_output_format_from_filename(stored_filename)

            if output_format == "JPEG":
                if img.mode in ("RGBA", "LA", "P"):
                    background = Image.new("RGB", img.size, (255, 255, 255))
                    if "A" in img.getbands():
                        background.paste(img, mask=img.getchannel("A"))
                    else:
                        background.paste(img)
                    img = background
                elif img.mode != "RGB":
                    img = img.convert("RGB")

            img = img.resize((new_width, new_height), Image.LANCZOS)

            buffer = io.BytesIO()

            mime_types = {
                "JPEG": "image/jpeg",
                "PNG": "image/png",
                "WEBP": "image/webp",
                "BMP": "image/bmp",
                "GIF": "image/gif",
                "TIFF": "image/tiff",
            }

            if output_format not in mime_types:
                output_format = "PNG"

            img.save(buffer, format=output_format)
            buffer.seek(0)

            return send_file(
                buffer,
                mimetype=mime_types[output_format],
                as_attachment=False,
                download_name=stored_filename,
            )

    except Exception:
        return api_error(400, "processing_error", "Erreur lors du traitement de l'image.")


api_public_bp = api_bp