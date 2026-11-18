"""Extension de navigateur PixShare (réservée aux membres).

L'extension s'identifie avec la clé personnelle créée dans « Mon compte » (en-tête
Authorization: Bearer pxs_…). Pas de cookie : pas de risque de requête forgée par un autre site.
Les envois passent par le même circuit que le site (limites du membre, formats, empreintes
des images refusées, retrait des métadonnées, NudeNet).
"""
from __future__ import annotations

import io
import os
import zipfile

from flask import Blueprint, current_app, jsonify, request, send_file, url_for
from werkzeug.utils import secure_filename

from pixshare.services import account_service as accounts
from pixshare.services.file_service import (
    FileTooLargeError,
    allowed_file,
    get_guest_token,
    requires_image_moderation,
    save_saved_local_file,
    save_uploaded_file,
)
from pixshare.services.image_ban_service import BannedImageError
from pixshare.services.json_services import load_blocked
from pixshare.services.request_service import get_client_ip
from pixshare.services.settings_service import (
    get_lifetime_choices,
    get_max_upload_size_bytes,
    get_max_upload_size_mb,
    get_uploads_per_hour,
    upload_service_enabled,
)
from pixshare.services.system_service import has_room_for
from pixshare.services.translation_service import translate
from pixshare.services.upload_limit_service import check_upload_rate, limit_message
from pixshare.services.url_import_service import UrlImportError, download_remote_image_to_temp

extension_bp = Blueprint("extension", __name__)

EXTENSION_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "extension")


def _error(message: str, status: int):
    response = jsonify({"ok": False, "error": message})
    response.status_code = status
    return response


def _member():
    """(compte, None) si la clé est bonne, sinon (None, réponse d'erreur)."""
    header = request.headers.get("Authorization", "")
    key = header[7:].strip() if header.lower().startswith("bearer ") else ""
    if not key:
        return None, _error("Clé manquante : collez votre clé PixShare dans les réglages de l'extension.", 401)
    rec = accounts.account_for_extension_key(key)
    if not rec:
        return None, _error("Clé refusée : elle a été supprimée ou remplacée, ou le compte est suspendu. "
                            "Créez une nouvelle clé dans « Mon compte ».", 401)
    accounts.act_as(rec)
    return rec, None


def _choices(rec) -> list[dict]:
    return [{"minutes": minutes, "label": translate(key)} for minutes, key in get_lifetime_choices(rec)]


@extension_bp.route("/extension/moi", methods=["GET"], endpoint="me")
def me():
    """Vérifie la clé (page de réglages de l'extension) et donne les durées et la taille permises."""
    rec, error = _member()
    if error:
        return error
    return jsonify({"ok": True, "email": rec.get("email", ""), "max_mb": get_max_upload_size_mb(rec),
                    "lifetimes": _choices(rec), "default_lifetime": current_app.config.get("DEFAULT_LIFETIME_MIN", 10)})


@extension_bp.route("/extension/envoi", methods=["POST"], endpoint="upload")
def upload():
    rec, error = _member()
    if error:
        return error
    ip = get_client_ip()
    if ip and ip in load_blocked():
        return _error("Accès bloqué.", 403)
    if not upload_service_enabled():
        return _error("Le service d'envoi est suspendu pour le moment.", 503)
    rate = check_upload_rate(f"acct:{rec['id']}", limit=get_uploads_per_hour(rec))
    if not rate.allowed:
        return _error(limit_message(rate, member=True), 429)
    if not has_room_for(request.content_length):
        return _error("Le stockage est plein pour le moment. Réessayez un peu plus tard.", 507)

    max_bytes = get_max_upload_size_bytes()
    max_mb = get_max_upload_size_mb()
    if (request.content_length or 0) > max_bytes + 64 * 1024:
        return _error(f"Fichier trop volumineux (maximum {max_mb} Mo).", 413)

    guest_token = get_guest_token()
    f = request.files.get("file")
    image_url = (request.form.get("image_url") or "").strip()
    try:
        if f and f.filename:
            original = f.filename[:200]
            safe_name = secure_filename(original)
            if not safe_name or not allowed_file(safe_name):
                return _error("Ce format de fichier n'est pas accepté.", 415)
            file_id, lifetime, _permanent = save_uploaded_file(
                f, original_name=original, client_ip=ip, guest_token=guest_token, max_size_bytes=max_bytes)
            name = safe_name
        elif image_url:
            temp_path, name, _, _ = download_remote_image_to_temp(image_url, current_app.config["UPLOAD_FOLDER"], max_bytes)
            file_id, lifetime, _permanent = save_saved_local_file(
                temp_path, original_name=name, client_ip=ip, guest_token=guest_token)
        else:
            return _error("Aucun fichier reçu.", 400)
    except FileTooLargeError:
        return _error(f"Fichier trop volumineux (maximum {max_mb} Mo).", 413)
    except BannedImageError:
        return _error("Cette image a déjà été refusée par la modération : elle ne peut pas être publiée.", 422)
    except UrlImportError as exc:
        return _error(str(exc), 422)
    except Exception:
        current_app.logger.exception("Envoi depuis l'extension impossible")
        return _error("L'envoi n'a pas pu aboutir. Réessayez.", 500)

    pending = requires_image_moderation(name)
    return jsonify({
        "ok": True,
        "id": file_id,
        "page_url": url_for("public.image_page", file_id=file_id, _external=True),
        "direct_url": url_for("public.view_file", file_id=file_id, _external=True),
        "my_files_url": url_for("public.index", _external=True) + "#mes-fichiers",
        "lifetime_minutes": lifetime,
        "pending": pending,
        "message": ("Lien copié. L'image sera visible après la vérification automatique (quelques secondes)."
                    if pending else "Lien copié."),
    })


@extension_bp.route("/extension/pixshare-extension.zip", methods=["GET"], endpoint="download")
def download():
    """L'extension à installer, toujours à jour avec le site (fabriquée à la demande)."""
    root = os.path.realpath(EXTENSION_DIR)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for current, _dirs, files in os.walk(root):
            for name in sorted(files):
                full = os.path.join(current, name)
                zf.write(full, os.path.join("pixshare-extension", os.path.relpath(full, root)))
    buf.seek(0)
    response = send_file(buf, mimetype="application/zip", as_attachment=True, download_name="pixshare-extension.zip")
    response.headers["Cache-Control"] = "no-store"
    return response
