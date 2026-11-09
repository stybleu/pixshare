"""API simplifiée « façon imgbb » et liste des fichiers.

POST /api/1/upload : une seule requête. La clé peut venir de ?key=, du champ « key »
                     ou des en-têtes habituels ; « image » est un fichier, du base64
                     ou un lien http(s). Plusieurs fichiers possibles par requête.
GET  /api/files    : liste paginée des fichiers de la clé.
"""
from __future__ import annotations

import base64
import binascii
import math
import mimetypes
import os
import re
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from flask import Blueprint, request
from PIL import Image
from werkzeug.utils import secure_filename

from pixshare.routes.api_public_routes import (
    API_IMAGE_EXTENSIONS,
    api_error,
    api_success,
    build_delete_token,
    build_file_id,
    build_file_urls,
    build_storage_name,
    ensure_upload_folder,
    file_belongs_to_key,
    get_real_ip,
    hash_api_key,
    is_allowed_file,
    is_file_expired,
    load_all_files,
    parse_iso_datetime,
    pretty_json_response,
    requires_image_moderation,
    save_all_files,
    serialize_file_record,
)
from pixshare.services.api_auth_service import (
    authenticate_api_key,
    consume_upload_for_key,
    get_api_max_file_size_bytes,
    remaining_uploads_info,
)
from pixshare.services.settings_service import upload_service_enabled
from pixshare.services.url_import_service import PIL_FORMAT_TO_EXT, UrlImportError, download_remote_image_to_temp
from pixshare.services.image_metadata_service import strip_uploaded_image

api_v1_bp = Blueprint("api_v1", __name__, url_prefix="/api")

MAX_FILES_PER_REQUEST = 10
MAX_URL_IMPORTS_PER_REQUEST = 3  # un lien lent bloque le serveur : on en limite le nombre
MIN_EXPIRATION_SECONDS = 60
MAX_EXPIRATION_SECONDS = 15552000  # 180 jours, comme imgbb
FILE_FIELDS = ("image", "image[]", "images", "images[]", "file", "files", "files[]")
TEXT_FIELDS = ("image", "image[]", "images", "images[]")
DEFAULT_LIFETIMES = [5, 10, 20, 30, 60, 120, 360, 720, 1440, 2880, 4320, 10080]


class Rejected(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


# ---------------------------------------------------------
# Lecture de la requête
# ---------------------------------------------------------

def _param(name: str) -> str:
    value = request.form.get(name)
    if value is None:
        value = request.args.get(name)
    if value is None:
        payload = request.get_json(silent=True)
        if isinstance(payload, dict) and payload.get(name) is not None:
            value = str(payload[name])
    return (value or "").strip()


def _collect_sources() -> list[tuple[str, Any]]:
    sources: list[tuple[str, Any]] = []
    for field in FILE_FIELDS:
        for storage in request.files.getlist(field):
            if storage and storage.filename:
                sources.append(("file", storage))

    texts: list[str] = []
    for field in TEXT_FIELDS:
        texts += request.form.getlist(field)
    payload = request.get_json(silent=True)
    if isinstance(payload, dict):
        value = payload.get("image", payload.get("images"))
        if isinstance(value, str):
            texts.append(value)
        elif isinstance(value, list):
            texts += [v for v in value if isinstance(v, str)]
    sources += [("text", t.strip()) for t in texts if t.strip()]
    return sources


def _expiration_minutes(key_data: dict[str, Any]) -> int | None:
    """Durée demandée en secondes (comme imgbb), bornée par ce que la clé autorise."""
    allowed = [int(v) for v in (key_data.get("allowed_lifetimes") or DEFAULT_LIFETIMES)] or DEFAULT_LIFETIMES
    default = int(key_data.get("default_lifetime_minutes", 10))
    raw = _param("expiration")
    if raw == "":
        return default
    if raw.lower() in {"0", "permanent", "never", "none"}:
        return None if key_data.get("allow_permanent") else default
    try:
        seconds = int(raw)
    except ValueError:
        seconds = 0
    if not MIN_EXPIRATION_SECONDS <= seconds <= MAX_EXPIRATION_SECONDS:
        raise Rejected(
            400, "invalid_expiration",
            f"« expiration » doit être un nombre de secondes entre {MIN_EXPIRATION_SECONDS} et {MAX_EXPIRATION_SECONDS}.",
        )
    return min(max(math.ceil(seconds / 60), min(allowed)), max(allowed))


# ---------------------------------------------------------
# Une source -> un fichier enregistré sur le disque
# ---------------------------------------------------------

def _inspect_image(path: str) -> tuple[str, int, int]:
    try:
        with Image.open(path) as img:
            img.verify()
        with Image.open(path) as img:
            return (img.format or "").upper(), img.size[0], img.size[1]
    except Exception as exc:
        raise Rejected(400, "invalid_image", "Image illisible ou format non pris en charge.") from exc


def _title_name(custom: str, fallback: str, ext: str) -> str:
    stem = secure_filename(custom) if custom else ""
    stem = os.path.splitext(stem)[0] if os.path.splitext(stem)[1].lower() == ext else stem
    return (stem or os.path.splitext(fallback)[0] or "image") + ext


def _from_uploaded_file(storage, folder: Path, max_bytes: int, custom_name: str):
    original = secure_filename(storage.filename or "")
    if not original:
        raise Rejected(400, "invalid_filename", "Nom de fichier invalide.")
    if not is_allowed_file(original):
        raise Rejected(400, "file_type_not_allowed", "Type de fichier non autorisé.")
    ext = Path(original).suffix.lower()

    storage.stream.seek(0, os.SEEK_END)
    size = storage.stream.tell()
    storage.stream.seek(0)
    if size > max_bytes:
        raise Rejected(413, "file_too_large", f"Fichier trop volumineux (max {max_bytes // (1024 * 1024)} Mo).")

    name = _title_name(custom_name, original, ext)
    stored = build_storage_name(name, folder)
    destination = folder / stored
    try:
        storage.save(destination)
    except OSError as exc:
        raise Rejected(500, "upload_save_failed", "Impossible d'enregistrer le fichier.") from exc

    width = height = None
    if ext.lstrip(".") in API_IMAGE_EXTENSIONS:
        try:
            _, width, height = _inspect_image(str(destination))
        except Rejected:
            destination.unlink(missing_ok=True)
            raise
    return name, stored, width, height


def _from_base64(text: str, folder: Path, max_bytes: int, custom_name: str):
    if text.startswith("data:"):
        text = text.partition(",")[2]
    compact = re.sub(r"\s+", "", text)
    if len(compact) * 3 // 4 > max_bytes + 3:
        raise Rejected(413, "file_too_large", f"Fichier trop volumineux (max {max_bytes // (1024 * 1024)} Mo).")
    compact = compact.replace("-", "+").replace("_", "/")
    compact += "=" * (-len(compact) % 4)
    try:
        raw = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Rejected(400, "invalid_image", "« image » n'est ni un fichier, ni un lien http(s), ni du base64 valide.") from exc
    if len(raw) > max_bytes:
        raise Rejected(413, "file_too_large", f"Fichier trop volumineux (max {max_bytes // (1024 * 1024)} Mo).")

    fd, tmp_path = tempfile.mkstemp(prefix="api_b64_", suffix=".bin", dir=str(folder))
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
    try:
        image_format, width, height = _inspect_image(tmp_path)
        ext = PIL_FORMAT_TO_EXT.get(image_format, "")
        if not ext or not is_allowed_file("x" + ext):
            raise Rejected(400, "file_type_not_allowed", "Type de fichier non autorisé.")
        name = _title_name(custom_name, "image", ext)
        stored = build_storage_name(name, folder)
        os.replace(tmp_path, folder / stored)
    except Exception:
        Path(tmp_path).unlink(missing_ok=True)
        raise
    return name, stored, width, height


def _from_url(url: str, folder: Path, max_bytes: int, custom_name: str):
    try:
        tmp_path, original, _size, _ctype = download_remote_image_to_temp(url, str(folder), max_bytes)
    except UrlImportError as exc:
        raise Rejected(400, "url_import_failed", str(exc)) from exc
    except Exception as exc:
        raise Rejected(400, "url_import_failed", "Impossible de télécharger cette adresse.") from exc
    try:
        image_format, width, height = _inspect_image(tmp_path)
        ext = PIL_FORMAT_TO_EXT.get(image_format) or Path(original).suffix.lower()
        if not is_allowed_file("x" + ext):
            raise Rejected(400, "file_type_not_allowed", "Type de fichier non autorisé.")
        name = _title_name(custom_name, original, ext)
        stored = build_storage_name(name, folder)
        os.replace(tmp_path, folder / stored)
    except Exception:
        Path(tmp_path).unlink(missing_ok=True)
        raise
    return name, stored, width, height


# ---------------------------------------------------------
# Enregistrement et réponse
# ---------------------------------------------------------

def _new_record(files_data, key_value, key_data, name, stored, width, height, folder, now, expires_at):
    strip_uploaded_image(Path(folder) / stored)  # retire GPS, appareil, date…
    pending = requires_image_moderation(stored)
    stamp = now.isoformat() + "Z"
    try:
        size = (folder / stored).stat().st_size
    except OSError:
        size = 0
    return {
        "id": build_file_id(files_data),
        "delete_token": build_delete_token(files_data),
        "original_name": name,
        "server_name": stored,
        "permanent": expires_at is None,
        "original_filename": name,
        "stored_filename": stored,
        "extension": Path(stored).suffix.lower().lstrip("."),
        "mime": mimetypes.guess_type(stored)[0] or "application/octet-stream",
        "size": size,
        "uploaded_at": stamp,
        "expires_at": None if expires_at is None else expires_at.isoformat() + "Z",
        "is_permanent": expires_at is None,
        "api_key_name": key_data.get("name", ""),
        "api_key_hash": hash_api_key(key_value),
        "source": "api",
        "views": 0,
        "status": "pending" if pending else "active",
        "moderation_requested_at": stamp if pending else "",
        "moderated_at": "",
        "moderation_decision": "pending" if pending else "not_required",
        "moderation_detector": "",
        "moderation_score": None,
        "ip": get_real_ip(),
        "width": width,
        "height": height,
    }


def _imgbb_item(record: dict[str, Any]) -> dict[str, Any]:
    urls = build_file_urls(record)
    uploaded = parse_iso_datetime(record.get("uploaded_at"))
    expires = parse_iso_datetime(record.get("expires_at"))
    seconds = 0
    if expires and uploaded:
        seconds = max(0, int((expires - uploaded).total_seconds()))
    stem = Path(record.get("original_filename", "")).stem
    return {
        "id": record["id"],
        "title": stem,
        "url_viewer": urls["url_viewer"],
        "url": urls["url"],
        "display_url": urls["url"],
        "width": record.get("width"),
        "height": record.get("height"),
        "size": record.get("size", 0),
        "time": str(int(uploaded.timestamp())) if uploaded else "",
        "expiration": str(seconds),
        "image": {
            "filename": record["stored_filename"],
            "name": stem,
            "mime": record.get("mime", ""),
            "extension": record.get("extension", ""),
            "url": urls["url"],
        },
        "delete_url": urls["delete_url"],
        "expires_at": record.get("expires_at"),
        "status": record.get("status", "active"),
        "moderation_status": (
            "pending" if record.get("status") == "pending" else record.get("moderation_decision", "approved")
        ),
    }


def _label(kind: str, value: Any) -> str:
    if kind == "file":
        return secure_filename(value.filename or "") or "fichier"
    return value[:80] if re.match(r"https?://", value, re.I) else "base64"


@api_v1_bp.route("/1/upload", methods=["POST"])
def api_v1_upload():
    if not upload_service_enabled():
        return api_error(503, "upload_service_suspended", "Le service d'upload est temporairement suspendu.")

    auth = authenticate_api_key(allow_param=True)
    if not auth.ok:
        return api_error(auth.status_code, auth.error or "auth_error", auth.message or "Accès refusé.")
    key_value, key_data = auth.key_value or "", auth.key_data or {}

    sources = _collect_sources()
    if not sources:
        return api_error(400, "missing_image", "Aucune image reçue : envoie un fichier, du base64 ou un lien dans « image ».")
    if len(sources) > MAX_FILES_PER_REQUEST:
        return api_error(400, "too_many_files", f"{MAX_FILES_PER_REQUEST} fichiers maximum par requête.")

    try:
        expiration_minutes = _expiration_minutes(key_data)
    except Rejected as exc:
        return api_error(exc.status, exc.code, exc.message)

    limits = remaining_uploads_info(key_data)
    capacity = min(limits["remaining_total"], limits["remaining_today"])
    quota_code = "upload_limit_reached" if limits["remaining_total"] <= limits["remaining_today"] else "daily_upload_limit_reached"

    folder = ensure_upload_folder()
    max_bytes = get_api_max_file_size_bytes(key_data)
    single = len(sources) == 1
    custom_name = _param("name") if single else ""
    now = datetime.utcnow()
    expires_at = None if expiration_minutes is None else now + timedelta(minutes=expiration_minutes)

    files_data = load_all_files()
    records: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    url_imports = 0

    for index, (kind, value) in enumerate(sources):
        try:
            if len(records) >= capacity:
                raise Rejected(429 if quota_code.startswith("daily") else 403, quota_code, "Quota d'envois atteint.")
            if kind == "file":
                saved = _from_uploaded_file(value, folder, max_bytes, custom_name)
            elif re.match(r"https?://", value, re.I):
                url_imports += 1
                if url_imports > MAX_URL_IMPORTS_PER_REQUEST:
                    raise Rejected(400, "too_many_urls", f"{MAX_URL_IMPORTS_PER_REQUEST} liens maximum par requête.")
                saved = _from_url(value, folder, max_bytes, custom_name)
            else:
                saved = _from_base64(value, folder, max_bytes, custom_name)
        except Rejected as exc:
            errors.append({"index": index, "name": _label(kind, value), "code": exc.code, "message": exc.message, "status": exc.status})
            continue
        name, stored, width, height = saved
        record = _new_record(files_data, key_value, key_data, name, stored, width, height, folder, now, expires_at)
        files_data[record["id"]] = record
        records.append(record)

    if not records:
        if single:
            first = errors[0]
            return api_error(first["status"], first["code"], first["message"])
        return pretty_json_response(
            {"success": False, "status": 400, "error": {"code": "upload_failed", "message": "Aucun fichier n'a pu être envoyé.", "details": errors}},
            status_code=400,
        )

    try:
        save_all_files(files_data)
    except Exception:
        for record in records:
            (folder / record["stored_filename"]).unlink(missing_ok=True)
        return api_error(500, "metadata_save_failed", "Impossible d'enregistrer les métadonnées du fichier.")

    updated = key_data
    for _ in records:
        updated = consume_upload_for_key(key_value) or updated
    limits = remaining_uploads_info(updated)

    items = [_imgbb_item(r) for r in records]
    if single:
        return api_success({**items[0], "limits": limits})
    return api_success({"count": len(items), "files": items, "errors": errors, "limits": limits})


def _uploaded_ts(record: dict[str, Any]) -> float:
    moment = parse_iso_datetime(record.get("uploaded_at"))
    return moment.timestamp() if moment else 0.0


@api_v1_bp.route("/files", methods=["GET"])
def api_list_files():
    auth = authenticate_api_key()
    if not auth.ok:
        return api_error(auth.status_code, auth.error or "auth_error", auth.message or "Accès refusé.")
    key_value = auth.key_value or ""

    page = request.args.get("page", 1, type=int) or 1
    per_page = request.args.get("per_page", 20, type=int) or 20
    page, per_page = max(1, page), min(100, max(1, per_page))
    status = (request.args.get("status") or "all").strip().lower()
    if status not in {"all", "active", "pending"}:
        return api_error(400, "invalid_status", "« status » doit valoir all, active ou pending.")
    query = (request.args.get("q") or "").strip().lower()

    records = [
        r for r in load_all_files().values()
        if isinstance(r, dict) and file_belongs_to_key(r, key_value) and not is_file_expired(r)
        and (status == "all" or (r.get("status") or "active") == status)
        and (not query or query in str(r.get("original_filename", "")).lower())
    ]
    records.sort(key=_uploaded_ts, reverse=True)
    total = len(records)
    pages = max(1, math.ceil(total / per_page))
    window = records[(page - 1) * per_page: page * per_page]
    return api_success({
        "files": [serialize_file_record(r) for r in window],
        "pagination": {
            "page": page, "per_page": per_page, "total": total,
            "total_pages": pages, "has_next": page < pages,
        },
    })
