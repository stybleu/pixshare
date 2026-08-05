from __future__ import annotations

import hmac
import os
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar

from flask import Blueprint, current_app, jsonify, request, send_file, url_for

from pixshare.services.file_service import cleanup_expired, delete_by_id
from pixshare.services.json_services import load_db, save_db
from pixshare.services.moderation_service import create_moderation_notice

moderation_api_bp = Blueprint(
    "moderation_api",
    __name__,
    url_prefix="/api/admin/moderation",
)

F = TypeVar("F", bound=Callable[..., Any])
IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp",
    ".tif", ".tiff", ".heic", ".heif",
}


def _json_error(status: int, code: str, message: str):
    return jsonify({
        "success": False,
        "status": status,
        "error": {"code": code, "message": message},
    }), status


def _extract_api_key() -> str:
    header_key = (request.headers.get("X-Moderation-Key") or "").strip()
    if header_key:
        return header_key

    authorization = (request.headers.get("Authorization") or "").strip()
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()

    return ""


def moderation_key_required(view: F) -> F:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any):
        expected_key = (
            current_app.config.get("MODERATION_API_KEY")
            or os.environ.get("MODERATION_API_KEY")
            or ""
        ).strip()
        provided_key = _extract_api_key()

        if not expected_key:
            return _json_error(
                503,
                "moderation_api_not_configured",
                "L'API de modération n'est pas configurée.",
            )

        if not provided_key or not hmac.compare_digest(
            provided_key.encode("utf-8"),
            expected_key.encode("utf-8"),
        ):
            return _json_error(401, "invalid_moderation_key", "Clé de modération invalide.")

        return view(*args, **kwargs)

    return wrapped  # type: ignore[return-value]


def _stored_filename(meta: dict[str, Any]) -> str:
    return os.path.basename(
        str(meta.get("server_name") or meta.get("stored_filename") or "")
    )


def _is_image(meta: dict[str, Any]) -> bool:
    filename = _stored_filename(meta)
    return bool(filename and Path(filename).suffix.lower() in IMAGE_EXTENSIONS)


def _is_pending_image(meta: dict[str, Any]) -> bool:
    return (meta.get("status") or "active").lower() == "pending" and _is_image(meta)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load_pending_image(file_id: str):
    cleanup_expired()
    database = load_db()
    meta = database.get(file_id)
    if not isinstance(meta, dict):
        return database, None
    if not _is_pending_image(meta):
        return database, None
    return database, meta


@moderation_api_bp.get("/images")
@moderation_key_required
def list_images_for_moderation():
    """List only images that are private and waiting for the bot."""
    cleanup_expired()
    database = load_db()

    try:
        limit = int(request.args.get("limit", "100"))
    except ValueError:
        limit = 100
    limit = max(1, min(limit, 500))

    after = (request.args.get("after") or "").strip()
    rows: list[dict[str, Any]] = []

    for file_id, meta in sorted(database.items(), key=lambda item: item[0]):
        if after and file_id <= after:
            continue
        if not isinstance(meta, dict) or not _is_pending_image(meta):
            continue

        filename = _stored_filename(meta)
        rows.append({
            "id": file_id,
            "filename": filename,
            "original_filename": meta.get("original_name") or meta.get("original_filename") or filename,
            "uploaded_at": meta.get("uploaded_at", ""),
            "size": meta.get("size", 0),
            "mime": meta.get("mime", ""),
            "content_url": url_for(
                "moderation_api.get_pending_image_content",
                file_id=file_id,
                _external=True,
            ),
            "approve_url": url_for(
                "moderation_api.approve_image_by_bot",
                file_id=file_id,
                _external=True,
            ),
            "delete_url": url_for(
                "moderation_api.delete_image_by_bot",
                file_id=file_id,
                _external=True,
            ),
        })

        if len(rows) >= limit:
            break

    next_after = rows[-1]["id"] if len(rows) == limit else ""

    return jsonify({
        "success": True,
        "data": {
            "images": rows,
            "count": len(rows),
            "next_after": next_after,
        },
    })


@moderation_api_bp.get("/images/<file_id>/content")
@moderation_key_required
def get_pending_image_content(file_id: str):
    """Send pending image bytes only to the authenticated moderation bot."""
    _database, meta = _load_pending_image(file_id)
    if meta is None:
        return _json_error(404, "pending_image_not_found", "Image en attente introuvable.")

    filename = _stored_filename(meta)
    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
    if not filename or not os.path.isfile(file_path):
        return _json_error(404, "image_content_not_found", "Contenu de l'image introuvable.")

    response = send_file(
        file_path,
        mimetype=meta.get("mime") or None,
        as_attachment=False,
        conditional=True,
    )
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["X-Robots-Tag"] = "noindex, noimageindex, noarchive"
    return response


@moderation_api_bp.post("/images/<file_id>/approve")
@moderation_key_required
def approve_image_by_bot(file_id: str):
    """Make a pending image public after a safe bot decision."""
    database, meta = _load_pending_image(file_id)
    if meta is None:
        return _json_error(409, "image_not_pending", "Cette image n'est plus en attente.")

    payload = request.get_json(silent=True) or {}
    detector = str(payload.get("detector") or "external_bot").strip()[:80]
    score = payload.get("score")

    meta["status"] = "active"
    meta["moderated_at"] = _utc_now_iso()
    meta["moderation_decision"] = "approved"
    meta["moderation_detector"] = detector
    meta["moderation_score"] = score
    database[file_id] = meta
    save_db(database)

    current_app.logger.info(
        "Image approuvée par le bot: file_id=%s detector=%s score=%r",
        file_id, detector, score,
    )

    return jsonify({
        "success": True,
        "data": {
            "id": file_id,
            "approved": True,
            "detector": detector,
            "score": score,
        },
    })


@moderation_api_bp.delete("/images/<file_id>")
@moderation_key_required
def delete_image_by_bot(file_id: str):
    """Delete a pending image after an unsafe bot decision."""
    _database, meta = _load_pending_image(file_id)
    if meta is None:
        return _json_error(409, "image_not_pending", "Cette image n'est plus en attente.")

    payload = request.get_json(silent=True) or {}
    reason = str(payload.get("reason") or "contenu_illicite").strip()[:80]
    detector = str(payload.get("detector") or "external_bot").strip()[:80]
    score = payload.get("score")

    notice_reason = reason if reason in {"non_respect_cgu", "contenu_illicite", "spam_abus"} else "non_respect_cgu"

    if not delete_by_id(file_id, reason=f"bot:{reason}"):
        return _json_error(500, "delete_failed", "La suppression de l'image a échoué.")

    create_moderation_notice(meta, file_id, reason=notice_reason)

    current_app.logger.warning(
        "Image supprimée par le bot: file_id=%s detector=%s score=%r reason=%s",
        file_id, detector, score, reason,
    )

    return jsonify({
        "success": True,
        "data": {
            "id": file_id,
            "deleted": True,
            "reason": reason,
            "detector": detector,
            "score": score,
        },
    })
