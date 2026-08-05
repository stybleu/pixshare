from __future__ import annotations

import hmac
import os
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar

from flask import Blueprint, current_app, jsonify, request, url_for

from pixshare.services.file_service import cleanup_expired, delete_by_id
from pixshare.services.json_services import load_db
from pixshare.services.moderation_service import create_moderation_notice

moderation_api_bp = Blueprint(
    "moderation_api",
    __name__,
    url_prefix="/api/admin/moderation",
)

F = TypeVar("F", bound=Callable[..., Any])
IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".bmp",
    ".tif",
    ".tiff",
    ".heic",
    ".heif",
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

        if not provided_key or not hmac.compare_digest(provided_key, expected_key):
            return _json_error(401, "invalid_moderation_key", "Clé de modération invalide.")

        return view(*args, **kwargs)

    return wrapped  # type: ignore[return-value]


def _stored_filename(meta: dict[str, Any]) -> str:
    return os.path.basename(
        str(meta.get("server_name") or meta.get("stored_filename") or "")
    )


def _is_active_image(meta: dict[str, Any]) -> bool:
    if (meta.get("status") or "active").lower() != "active":
        return False

    filename = _stored_filename(meta)
    return bool(filename and Path(filename).suffix.lower() in IMAGE_EXTENSIONS)


@moderation_api_bp.get("/images")
@moderation_key_required
def list_images_for_moderation():
    """Liste les images actives que le bot externe peut analyser."""
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
        if not isinstance(meta, dict) or not _is_active_image(meta):
            continue

        filename = _stored_filename(meta)
        rows.append({
            "id": file_id,
            "filename": filename,
            "original_filename": meta.get("original_name") or meta.get("original_filename") or filename,
            "uploaded_at": meta.get("uploaded_at", ""),
            "size": meta.get("size", 0),
            "mime": meta.get("mime", ""),
            "raw_url": url_for("api.api_raw_file", filename=filename, _external=True),
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


@moderation_api_bp.delete("/images/<file_id>")
@moderation_key_required
def delete_image_by_bot(file_id: str):
    """Supprime une image après décision du bot de modération externe."""
    database = load_db()
    meta = database.get(file_id)

    if not isinstance(meta, dict):
        return _json_error(404, "file_not_found", "Image introuvable.")

    if not _is_active_image(meta):
        return _json_error(409, "file_not_active_image", "Ce fichier n'est pas une image active.")

    payload = request.get_json(silent=True) or {}
    reason = str(payload.get("reason") or "contenu_illicite").strip()[:80]
    detector = str(payload.get("detector") or "external_bot").strip()[:80]
    score = payload.get("score")

    notice_reason = reason if reason in {"non_respect_cgu", "contenu_illicite", "spam_abus"} else "non_respect_cgu"

    if not delete_by_id(file_id, reason=f"bot:{reason}"):
        return _json_error(500, "delete_failed", "La suppression de l'image a échoué.")

    create_moderation_notice(meta, file_id, reason=notice_reason)

    current_app.logger.warning(
        "Image supprimée par le bot de modération: file_id=%s detector=%s score=%r reason=%s",
        file_id,
        detector,
        score,
        reason,
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
