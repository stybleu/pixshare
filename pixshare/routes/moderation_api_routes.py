from __future__ import annotations

import hmac
import math
import os
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar

from flask import Blueprint, current_app, jsonify, request, send_file, url_for

from pixshare.services.file_service import cleanup_expired, delete_by_id
from pixshare.services.json_services import load_db
from pixshare.services.moderation_service import (
    approve_image as _approve,
    create_moderation_notice,
    mark_image_for_review as _mark_review,
)

moderation_api_bp = Blueprint("moderation_api", __name__, url_prefix="/api/admin/moderation")

F = TypeVar("F", bound=Callable[..., Any])
IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp",
    ".tif", ".tiff", ".heic", ".heif",
    ".jfif", ".jpe", ".apng",
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
            return _json_error(503, "moderation_api_not_configured", "L'API de modération n'est pas configurée.")

        if not provided_key or not hmac.compare_digest(
            provided_key.encode("utf-8"), expected_key.encode("utf-8")
        ):
            return _json_error(401, "invalid_moderation_key", "Clé de modération invalide.")

        return view(*args, **kwargs)

    return wrapped  # type: ignore[return-value]


def _stored_filename(meta: dict[str, Any]) -> str:
    return os.path.basename(str(meta.get("server_name") or meta.get("stored_filename") or ""))


def _is_image(meta: dict[str, Any]) -> bool:
    filename = _stored_filename(meta)
    return bool(filename and Path(filename).suffix.lower() in IMAGE_EXTENSIONS)


def _is_pending_image(meta: dict[str, Any], include_review: bool = False) -> bool:
    if (meta.get("status") or "active").lower() != "pending" or not _is_image(meta):
        return False
    decision = str(meta.get("moderation_decision") or "pending").lower()
    return include_review or decision != "manual_review"


def _load_pending_image(file_id: str, include_review: bool = True):
    cleanup_expired()
    database = load_db()
    meta = database.get(file_id)
    if not isinstance(meta, dict) or not _is_pending_image(meta, include_review=include_review):
        return database, None
    return database, meta


def _clean_detector(value: Any) -> str:
    return str(value or "external_bot").strip()[:80] or "external_bot"


def _clean_score(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(score):
        return None
    return max(0.0, min(score, 1.0))


@moderation_api_bp.get("/health")
@moderation_key_required
def moderation_health():
    """Endpoint léger permettant au bot externe de vérifier la connexion."""
    return jsonify({"success": True, "data": {"service": "pixshare-moderation", "status": "ok"}})


@moderation_api_bp.get("/images")
@moderation_key_required
def list_images_for_moderation():
    """Liste les images privées encore à traiter automatiquement."""
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
        if not isinstance(meta, dict) or not _is_pending_image(meta, include_review=False):
            continue

        filename = _stored_filename(meta)
        rows.append({
            "id": file_id,
            "filename": filename,
            "original_filename": meta.get("original_name") or meta.get("original_filename") or filename,
            "uploaded_at": meta.get("uploaded_at", ""),
            "size": meta.get("size", 0),
            "mime": meta.get("mime", ""),
            "content_url": url_for("moderation_api.get_pending_image_content", file_id=file_id, _external=True),
            "decision_url": url_for("moderation_api.decide_image_by_bot", file_id=file_id, _external=True),
            # Compatibilité avec l'ancien bot :
            "approve_url": url_for("moderation_api.approve_image_by_bot", file_id=file_id, _external=True),
            "delete_url": url_for("moderation_api.delete_image_by_bot", file_id=file_id, _external=True),
        })
        if len(rows) >= limit:
            break

    next_after = rows[-1]["id"] if len(rows) == limit else ""
    return jsonify({"success": True, "data": {"images": rows, "count": len(rows), "next_after": next_after}})


@moderation_api_bp.get("/images/<file_id>/content")
@moderation_key_required
def get_pending_image_content(file_id: str):
    _database, meta = _load_pending_image(file_id, include_review=True)
    if meta is None:
        return _json_error(404, "pending_image_not_found", "Image en attente introuvable.")

    filename = _stored_filename(meta)
    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
    if not filename or not os.path.isfile(file_path):
        return _json_error(404, "image_content_not_found", "Contenu de l'image introuvable.")

    response = send_file(file_path, mimetype=meta.get("mime") or None, as_attachment=False, conditional=True)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["X-Robots-Tag"] = "noindex, noimageindex, noarchive"
    return response


@moderation_api_bp.post("/images/<file_id>/decision")
@moderation_key_required
def decide_image_by_bot(file_id: str):
    """Décision unique: approve, reject ou review."""
    database, meta = _load_pending_image(file_id, include_review=True)
    if meta is None:
        return _json_error(409, "image_not_pending", "Cette image n'est plus en attente.")

    payload = request.get_json(silent=True) or {}
    decision = str(payload.get("decision") or "").strip().lower()
    detector = _clean_detector(payload.get("detector"))
    score = _clean_score(payload.get("score"))
    label = str(payload.get("label") or "").strip()[:80]

    if decision == "approve":
        _approve(database, file_id, meta, detector, score)
        current_app.logger.info("Image approuvée: file_id=%s detector=%s score=%r", file_id, detector, score)
        return jsonify({"success": True, "data": {"id": file_id, "decision": "approved", "score": score}})

    if decision == "review":
        _mark_review(database, file_id, meta, detector, score, label)
        current_app.logger.warning("Image envoyée en revue manuelle: file_id=%s detector=%s score=%r label=%s", file_id, detector, score, label)
        return jsonify({"success": True, "data": {"id": file_id, "decision": "manual_review", "score": score}})

    if decision == "reject":
        reason = str(payload.get("reason") or "non_respect_cgu").strip()[:80]
        notice_reason = reason if reason in {"non_respect_cgu", "contenu_illicite", "spam_abus"} else "non_respect_cgu"
        if not delete_by_id(file_id, reason=f"bot:{reason}"):
            return _json_error(500, "delete_failed", "La suppression de l'image a échoué.")
        create_moderation_notice(meta, file_id, reason=notice_reason)
        current_app.logger.warning("Image supprimée: file_id=%s detector=%s score=%r reason=%s label=%s", file_id, detector, score, reason, label)
        return jsonify({"success": True, "data": {"id": file_id, "decision": "rejected", "score": score, "reason": reason}})

    return _json_error(400, "invalid_decision", "decision doit valoir approve, reject ou review.")


# Anciennes routes conservées pour compatibilité.
@moderation_api_bp.post("/images/<file_id>/approve")
@moderation_key_required
def approve_image_by_bot(file_id: str):
    database, meta = _load_pending_image(file_id, include_review=True)
    if meta is None:
        return _json_error(409, "image_not_pending", "Cette image n'est plus en attente.")
    payload = request.get_json(silent=True) or {}
    detector = _clean_detector(payload.get("detector"))
    score = _clean_score(payload.get("score"))
    _approve(database, file_id, meta, detector, score)
    return jsonify({"success": True, "data": {"id": file_id, "approved": True, "detector": detector, "score": score}})


@moderation_api_bp.delete("/images/<file_id>")
@moderation_key_required
def delete_image_by_bot(file_id: str):
    _database, meta = _load_pending_image(file_id, include_review=True)
    if meta is None:
        return _json_error(409, "image_not_pending", "Cette image n'est plus en attente.")
    payload = request.get_json(silent=True) or {}
    reason = str(payload.get("reason") or "non_respect_cgu").strip()[:80]
    detector = _clean_detector(payload.get("detector"))
    score = _clean_score(payload.get("score"))
    notice_reason = reason if reason in {"non_respect_cgu", "contenu_illicite", "spam_abus"} else "non_respect_cgu"
    if not delete_by_id(file_id, reason=f"bot:{reason}"):
        return _json_error(500, "delete_failed", "La suppression de l'image a échoué.")
    create_moderation_notice(meta, file_id, reason=notice_reason)
    return jsonify({"success": True, "data": {"id": file_id, "deleted": True, "reason": reason, "detector": detector, "score": score}})
