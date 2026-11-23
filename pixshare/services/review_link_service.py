"""Modérer depuis le mail : liens signés « Approuver / Supprimer » utilisables sans se connecter.

- Lien signé avec la clé secrète du site, valable 48 h, pour une seule image.
- Un clic ouvre une page de confirmation (les boîtes mail ouvrent parfois les liens toutes seules
  pour les vérifier : sans cette étape, elles pourraient décider à ta place).
- Une fois l'image traitée (ici ou dans l'admin), le lien ne sert plus à rien.
"""
from __future__ import annotations

import io
import os

from flask import current_app
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from PIL import Image, ImageFilter, ImageOps

from pixshare.services.json_services import block_ip, load_db
from pixshare.services.moderation_service import approve_image, create_moderation_notice
from pixshare.services.nsfw_stats_service import bump as bump_stat

MAX_AGE = 48 * 3600
_SALT = "pixshare-review-link-v1"
NOT_NUDENET = ("analyse_impossible", "signalement", "deja_refusee")


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(str(current_app.config.get("SECRET_KEY") or current_app.secret_key), salt=_SALT)


def make_token(file_id: str) -> str:
    return _serializer().dumps({"f": file_id})


def read_token(token: str) -> tuple[str | None, str]:
    """(file_id, "") si le lien est bon, sinon (None, raison lisible)."""
    try:
        data = _serializer().loads(token, max_age=MAX_AGE)
    except SignatureExpired:
        return None, "Ce lien a expiré (48 heures). Traite l'image depuis l'admin."
    except BadSignature:
        return None, "Lien invalide."
    file_id = str((data or {}).get("f") or "")
    return (file_id or None), ("" if file_id else "Lien invalide.")


def waiting_meta(file_id: str) -> dict | None:
    meta = load_db().get(file_id)
    if (isinstance(meta, dict) and (meta.get("status") or "").lower() == "pending"
            and str(meta.get("moderation_decision") or "").lower() == "manual_review"):
        return meta
    return None


def image_path(meta: dict) -> str:
    return os.path.join(current_app.config["UPLOAD_FOLDER"], os.path.basename(str(meta.get("server_name") or "")))


def mail_image_mode() -> str:
    mode = (os.environ.get("MAIL_REVIEW_IMAGE") or "net").strip().lower()
    return mode if mode in ("net", "flou", "aucune") else "net"


def mail_thumbnail(meta: dict, mode: str | None = None) -> bytes | None:
    """Petite image JPEG (480 px) pour le mail : nette, floutée ou rien (variable MAIL_REVIEW_IMAGE)."""
    mode = mode or mail_image_mode()
    if mode == "aucune":
        return None
    try:
        with Image.open(image_path(meta)) as im:
            im.seek(0)
            pic = ImageOps.exif_transpose(im).convert("RGB")
        pic.thumbnail((480, 480))
        if mode == "flou":
            pic = pic.filter(ImageFilter.GaussianBlur(14))
        buf = io.BytesIO()
        pic.save(buf, "JPEG", quality=78)
        return buf.getvalue()
    except Exception:
        return None


def decide(file_id: str, action: str, notify: bool = True, block_hours: float | None = None) -> str:
    """Applique la décision. Retourne "approved", "deleted" ou "done" (déjà traitée)."""
    from pixshare.services.file_service import delete_by_id

    db = load_db()
    meta = db.get(file_id)
    if not waiting_meta(file_id):
        return "done"
    label = str(meta.get("moderation_label") or "")
    if action == "approve":
        if label == "signalement":
            meta["reports"], meta["report_reasons"] = [], {}
        approve_image(db, file_id, meta, "admin-mail", meta.get("moderation_score"))
        if label not in NOT_NUDENET:
            bump_stat("review_approved")
            from pixshare.services.admin_ok_service import remember_approved
            remember_approved(meta, file_id)
        return "approved"
    if action == "delete":
        if delete_by_id(file_id, reason="non_respect_cgu"):
            if label not in NOT_NUDENET:
                bump_stat("review_deleted")
            if notify:
                create_moderation_notice(meta, file_id=file_id, reason="non_respect_cgu")
            ip = str(meta.get("ip") or "")
            if block_hours is not None and ip and not meta.get("by_admin"):
                block_ip(ip, "Depuis le mail de modération", block_hours or None)
            return "deleted"
    return "done"
