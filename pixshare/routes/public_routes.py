from flask import Blueprint, abort, current_app, flash, jsonify, make_response, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.utils import secure_filename

import hashlib
import os
import time

from pixshare.config import Config

from pixshare.security.csrf import validate_csrf
from pixshare.services.auth_service import is_admin, is_locked, register_fail, reset_fail
from pixshare.services.contact_service import create_contact_message
from pixshare.services.file_service import (
    CONTENT_ERROR_MESSAGE,
    FileContentError,
    FileTooLargeError,
    accepted_formats,
    allowed_file,
    is_audio_filename,
    can_keep_uploads,
    cleanup_expired,
    delete_by_id,
    file_password_ok,
    get_file_record,
    medium_path,
    attach_guest_cookie,
    get_existing_guest_token,
    get_guest_token,
    is_owner,
    get_or_create_visitor_token,
    is_image_filename,
    is_video_filename,
    list_guest_files,
    list_removed_files,
    register_unique_view,
    requires_image_moderation,
    save_saved_local_file,
    save_uploaded_file,
)
from pixshare.services.json_services import (
    load_blocked,
    load_db,
    load_views,
    save_db,
)
from pixshare.services.request_service import get_client_ip
from pixshare.services.upload_limit_service import check_upload_rate, limit_message
from pixshare.services.settings_service import (
    get_max_lifetime,
    get_guest_pass_max_lifetime,
    LIFETIME_CHOICES,
    get_default_lifetime,
    get_lifetime_choices,
    get_max_upload_size_bytes,
    get_max_upload_size_mb,
    accounts_enabled,
    get_uploads_per_hour,
    limits_table,
    upload_service_enabled,
)
from pixshare.services.account_service import current_account, is_member
from pixshare.services import guest_pass_service as guest_pass
from pixshare.services.url_import_service import UrlImportError, download_remote_image_to_temp
from pixshare.services.moderation_service import pop_pending_notice
from pixshare.services.embed_service import embed_codes
from pixshare.services.image_ban_service import BannedImageError

BANNED_MESSAGE = "Cette image a déjà été refusée car elle ne respecte pas les conditions d'utilisation."
from pixshare.services.report_service import REPORT_REASONS, report_file
from pixshare.services.turnstile_service import turnstile_ok
from pixshare.services.system_service import has_room_for

from pixshare.services.time_service import get_remaining_time_label, format_duration_minutes
from pixshare.services.usage_tracking_service import record_usage_event

public_bp = Blueprint("public", __name__)

config = Config()


def _parse_view_limit_form() -> tuple[bool, int | None]:
    """Retourne la limite de vues choisie pour CET upload uniquement.

    Par défaut, la limite est désactivée pour ne pas donner l'impression
    que toutes les images sont soumises à cette règle.
    """
    enabled = (request.form.get("view_limit_enabled") or "").strip().lower() in {"1", "on", "true", "yes"}
    if not enabled:
        return False, None

    try:
        max_views = int(request.form.get("max_views", 20))
    except (TypeError, ValueError):
        max_views = 20

    max_views = max(1, min(max_views, 100))
    return True, max_views


def _view_limit_reached(meta: dict) -> bool:
    if not bool(meta.get("view_limit_enabled", False)):
        return False

    try:
        max_views = int(meta.get("max_views") or 0)
        views = int(meta.get("views") or 0)
    except (TypeError, ValueError):
        return False

    return max_views > 0 and views >= max_views


def _limited_access_allowed(file_id: str, meta: dict) -> bool:
    """Fichier à vues limitées : l'image brute (/view, /download) n'est servie
    qu'à celui qui l'a envoyé, à l'admin, ou à un visiteur dont la vue a été
    comptée en ouvrant la page /file/. Avant, ces adresses directes
    contournaient la limite."""
    if not bool(meta.get("view_limit_enabled", False)):
        return True
    if is_admin():
        return True
    if is_owner(meta):
        return True
    token = (request.cookies.get(current_app.config["VISITOR_COOKIE_NAME"]) or "").strip()
    if not token:
        return False
    seen = load_views().get(file_id, [])
    return isinstance(seen, list) and token in seen


def _count_view(file_id: str, meta: dict, visitor_token: str, has_cookie: bool) -> bool:
    """Compte une vue unique, mais pas :
    - celles de l'envoyeur (« Mes envois », sa page de partage) ni de l'admin ;
    - celles des robots (aperçus WhatsApp, Discord, Facebook, moteurs de recherche…).
    Sans cookie (image intégrée sur un autre site, navigateur qui les bloque), le visiteur est
    reconnu par une empreinte chiffrée (jamais son adresse IP en clair) : recharger ne recompte pas."""
    if is_admin() or is_owner(meta):
        return False
    from pixshare.services.visitor_stats_service import is_bot
    user_agent = request.headers.get("User-Agent", "") or ""
    if is_bot(user_agent):
        return False
    if has_cookie:
        return register_unique_view(file_id, visitor_token)
    secret = str(current_app.config.get("SECRET_KEY") or "")
    raw = f"{secret}|vue|{file_id}|{get_client_ip() or ''}|{user_agent[:200]}"
    counted = register_unique_view(file_id, "e:" + hashlib.sha256(raw.encode()).hexdigest()[:20])
    # Le cookie posé avec cette réponse est noté aussi : à la visite suivante (avec cookie), la même
    # personne n'est pas recomptée, et l'image d'un fichier à vues limitées lui reste accessible.
    register_unique_view(file_id, visitor_token)
    return counted


# --------------------------------------------------------------- mot de passe
FILE_PASSWORD_MIN = 4
FILE_PASSWORD_MAX = 128
UNLOCKED_SESSION_KEY = "unlocked_files"


def _is_unlocked(file_id: str, meta: dict) -> bool:
    """Fichier protégé : visible seulement par l'envoyeur, l'admin, ou un visiteur
    qui a donné le bon mot de passe (retenu dans sa session)."""
    if not meta.get("password_hash"):
        return True
    if is_admin():
        return True
    if is_owner(meta):
        return True
    return file_id in (session.get(UNLOCKED_SESSION_KEY) or [])


def _remember_unlocked(file_id: str) -> None:
    unlocked = [f for f in (session.get(UNLOCKED_SESSION_KEY) or []) if f != file_id]
    unlocked.append(file_id)
    session[UNLOCKED_SESSION_KEY] = unlocked[-30:]


def _read_file_password():
    """Mot de passe facultatif du formulaire d'envoi : (mot de passe, message d'erreur)."""
    password = request.form.get("file_password") or ""
    if not password:
        return "", ""
    if len(password) < FILE_PASSWORD_MIN or len(password) > FILE_PASSWORD_MAX:
        return "", f"Le mot de passe doit faire entre {FILE_PASSWORD_MIN} et {FILE_PASSWORD_MAX} caractères."
    return password, ""


@public_bp.before_request
def flash_pending_moderation_notice():
    guest_token = get_existing_guest_token()
    account = current_account()
    if not guest_token and not account:
        return

    notice = pop_pending_notice(guest_token, (account or {}).get("id", ""))
    if not notice:
        return

    flash(notice.get("message") or "Un de vos envois a été retiré par la modération.", notice.get("level") or "warning")


# =========================================================
# Public site
# =========================================================

MAX_FILES_PER_SEND = 10
AUDIO_FOR_MEMBERS = "Les sons (MP3, OGG, WAV…) sont réservés aux comptes gratuits : créez-en un en une minute pour les envoyer."


def _save_several(files, too_many, ip, guest_token, keep, view_limit_enabled, max_views, max_size_bytes, password):
    """Plusieurs fichiers dans un seul envoi : chacun est vérifié et compté comme un envoi (limites horaires
    comprises) ; un fichier refusé n'empêche pas les autres de partir."""
    account = current_account()
    rate_key = f"acct:{account['id']}" if account else ip
    saved, problems, waiting, rate_note = [], [], 0, ""
    for index, upload in enumerate(files):
        original = upload.filename
        safe_name = secure_filename(original)
        if not safe_name or not allowed_file(safe_name, member=guest_pass.features_unlocked()):
            problems.append(f"« {original} » : " + (AUDIO_FOR_MEMBERS if is_audio_filename(safe_name)
                                                   else "format non accepté"))
            continue
        if index:  # le premier a déjà été compté par la vérification commune
            rate = check_upload_rate(rate_key, exempt=is_admin(), limit=get_uploads_per_hour(account or False))
            if not rate.allowed:
                rate_note = limit_message(rate, member=bool(account))
                problems.append(f"{len(files) - index} photo(s) non envoyée(s) : limite d'envois atteinte")
                break
        try:
            new_id, _lifetime, _permanent = save_uploaded_file(
                upload, original_name=original, client_ip=ip, guest_token=guest_token, keep_requested=keep,
                view_limit_enabled=view_limit_enabled, max_views=max_views, max_size_bytes=max_size_bytes,
                password=password)
        except FileTooLargeError:
            problems.append(f"« {original} » : trop volumineux (maximum {get_max_upload_size_mb()} Mo)")
            continue
        except BannedImageError:
            problems.append(f"« {original} » : image déjà refusée par la modération")
            continue
        except FileContentError:
            problems.append(f"« {original} » : ce n'est pas une vraie photo ou vidéo")
            continue
        saved.append(new_id)
        if requires_image_moderation(safe_name):
            waiting += 1
    if too_many:
        problems.append(f"{MAX_FILES_PER_SEND} photos au plus par envoi : les suivantes n'ont pas été prises")
    if saved:
        text = f"{len(saved)} envoi(s) réussi(s) ✅"
        if waiting:
            text += f" {waiting} image(s) en vérification automatique : leur lien s'affiche dès qu'elles sont validées."
        flash(text, "success" if not problems else "info")
    for problem in problems[:5]:
        flash(problem, "warning")
    if rate_note:
        flash(rate_note, "warning")
    if not saved:
        return attach_guest_cookie(redirect(url_for("public.index")))
    return attach_guest_cookie(redirect(url_for("public.index", nouveau=",".join(saved), _anchor=f"file-{saved[0]}")))


@public_bp.route("/", methods=["GET", "POST"], endpoint="index")
def index():
    cleanup_expired()

    ip = get_client_ip()
    blocked = load_blocked()
    if ip and ip in blocked:
        return redirect("https://www.google.fr"), 302

    guest_token = get_guest_token()

    uploads_enabled = upload_service_enabled()
    rate_limit_retry = 0

    if request.method == "POST":
        validate_csrf()

        if not uploads_enabled:
            flash("L'envoi est suspendu pour le moment. Réessayez plus tard.", "warning")
            return attach_guest_cookie(redirect(url_for("public.index")))

        if not turnstile_ok(request.form, ip):
            flash("Vérification anti-robot échouée : cochez la case puis réessayez.", "warning")
            return attach_guest_cookie(redirect(url_for("public.index")))

        if not has_room_for(request.content_length):
            cleanup_expired()  # libère d'abord les fichiers expirés
            if not has_room_for(request.content_length):
                flash("Le stockage est plein pour le moment. Réessayez un peu plus tard.", "warning")
                return attach_guest_cookie(redirect(url_for("public.index")))

        chosen = [x for x in request.files.getlist("file") if x and x.filename]
        too_many = len(chosen) > MAX_FILES_PER_SEND
        chosen = chosen[:MAX_FILES_PER_SEND]
        f = chosen[0] if chosen else None
        image_url = (request.form.get("image_url") or "").strip()
        keep = (request.form.get("keep", "") in {"1", "on", "true", "yes"})

        # Limite d'envois par IP (l'admin n'est pas limité). Quand elle est atteinte,
        # on réaffiche la page avec un message et le code 429 (voir la fin de la fonction).
        rate_limited = False
        if (f and f.filename) or image_url:
            account = current_account()
            rate = check_upload_rate(
                f"acct:{account['id']}" if account else ip,
                exempt=is_admin(),
                limit=get_uploads_per_hour(account or False),
            )
            if not rate.allowed:
                rate_limited = True
                rate_limit_retry = rate.retry_after
                flash(limit_message(rate, member=bool(account)), "warning")

        # Sans compte : les options des membres (taille, durée, mot de passe, filtres, sons…)
        # sont accordées pour quelques envois par heure (réglage « options avancées »).
        if not rate_limited and ((f and f.filename) or image_url) and not is_member() \
                and guest_pass.offered() and guest_pass.wants_advanced(chosen):
            refusal = guest_pass.try_unlock(ip, guest_token)
            if refusal:
                flash(refusal, "warning")
                return attach_guest_cookie(redirect(url_for("public.index")))

        max_size_bytes = get_max_upload_size_bytes()
        view_limit_enabled, max_views = _parse_view_limit_form()
        file_password, password_error = _read_file_password()
        if not guest_pass.features_unlocked():
            # Limite de vues et mot de passe : options des comptes (ignorées sinon).
            view_limit_enabled, file_password, password_error = False, "", ""
        if not rate_limited and password_error and ((f and f.filename) or image_url):
            flash(password_error, "warning")
            return attach_guest_cookie(redirect(url_for("public.index")))

        if not rate_limited and len(chosen) > 1:
            return _save_several(chosen, too_many, ip, guest_token, keep, view_limit_enabled, max_views,
                                 max_size_bytes, file_password)

        if not rate_limited and f and f.filename:
            original = f.filename
            safe_name = secure_filename(original)
            if not safe_name:
                flash("Nom de photo invalide.", "danger")
                return attach_guest_cookie(redirect(url_for("public.index")))

            if not allowed_file(safe_name, member=guest_pass.features_unlocked()):
                if is_audio_filename(safe_name):
                    flash(AUDIO_FOR_MEMBERS, "info")
                else:
                    flash(f"Ce format n'est pas accepté. Formats acceptés : {accepted_formats(guest_pass.features_unlocked())}", "danger")
                return attach_guest_cookie(redirect(url_for("public.index")))

            content_length = request.content_length or 0
            if content_length > max_size_bytes:
                max_mb = get_max_upload_size_mb()
                flash(f"Trop volumineux. Taille maximale : {max_mb} Mo.", "danger")
                return attach_guest_cookie(redirect(url_for("public.index")))

            try:
                new_id, lifetime, permanent = save_uploaded_file(
                    f,
                    original_name=original,
                    client_ip=ip,
                    guest_token=guest_token,
                    keep_requested=keep,
                    view_limit_enabled=view_limit_enabled,
                    max_views=max_views,
                    max_size_bytes=max_size_bytes,
                    password=file_password,
                )
            except FileTooLargeError:
                max_mb = get_max_upload_size_mb()
                flash(f"Trop volumineux. Taille maximale : {max_mb} Mo.", "danger")
                return attach_guest_cookie(redirect(url_for("public.index")))
            except BannedImageError:
                flash(BANNED_MESSAGE, "danger")
                return attach_guest_cookie(redirect(url_for("public.index")))
            except FileContentError:
                flash(CONTENT_ERROR_MESSAGE, "danger")
                return attach_guest_cookie(redirect(url_for("public.index")))

            if requires_image_moderation(safe_name):
                flash("Image reçue ✅ Vérification automatique en cours : son lien s'affiche dès qu'elle est validée.", "info")
            elif permanent:
                flash("Envoi réussi ✅ (sans expiration)", "success")
            else:
                flash(f"Envoi réussi ✅ (expiration : {format_duration_minutes(lifetime)})", "success")

            # On arrive directement sur le fichier envoyé, avec son lien à copier.
            return attach_guest_cookie(redirect(url_for("public.index", nouveau=new_id, _anchor=f"file-{new_id}")))

        if not rate_limited and image_url:
            try:
                temp_path, original_name, _, _ = download_remote_image_to_temp(
                    image_url,
                    current_app.config["UPLOAD_FOLDER"],
                    max_size_bytes,
                )
                new_id, lifetime, permanent = save_saved_local_file(
                    temp_path,
                    original_name=original_name,
                    client_ip=ip,
                    guest_token=guest_token,
                    keep_requested=keep,
                    view_limit_enabled=view_limit_enabled,
                    max_views=max_views,
                    password=file_password,
                )
            except UrlImportError as exc:
                flash(str(exc), "danger")
                return attach_guest_cookie(redirect(url_for("public.index")))
            except BannedImageError:
                flash(BANNED_MESSAGE, "danger")
                return attach_guest_cookie(redirect(url_for("public.index")))
            except FileContentError:
                flash(CONTENT_ERROR_MESSAGE, "danger")
                return attach_guest_cookie(redirect(url_for("public.index")))
            except Exception:
                flash("Impossible d'importer cette image depuis l'URL fournie.", "danger")
                return attach_guest_cookie(redirect(url_for("public.index")))

            if requires_image_moderation(original_name):
                flash("Image reçue ✅ Vérification automatique en cours : son lien s'affiche dès qu'elle est validée.", "info")
            elif permanent:
                flash("Image importée ✅ (sans expiration)", "success")
            else:
                flash(f"Image importée ✅ (expiration : {format_duration_minutes(lifetime)})", "success")

            # On arrive directement sur le fichier envoyé, avec son lien à copier.
            return attach_guest_cookie(redirect(url_for("public.index", nouveau=new_id, _anchor=f"file-{new_id}")))

        if not rate_limited:
            flash("Choisissez une photo ou collez l'adresse d'une image.", "warning")
            return attach_guest_cookie(redirect(url_for("public.index")))

    guest_files = list_guest_files()
    for item in guest_files:
        file_id = item.get("id") or item.get("file_id")
        if not file_id:
            continue
    
        item["views"] = int(item.get("views", 0) or 0)

        if item.get("status") == "active":
            item["remaining_time"] = get_remaining_time_label(item.get("expires_at"))
        elif item.get("status") == "pending":
            item["remaining_time"] = "⏸ délai en pause pendant la vérification"
        else:
            item["remaining_time"] = ""
            

    response = make_response(render_template(
        "index.html",
        guest_files=guest_files,
        removed_files=list_removed_files(),
        max_mb=get_max_upload_size_mb(),
        admin=is_admin(),
        version=current_app.config["APP_VERSION"],
        can_keep=can_keep_uploads(),
        default_lifetime=get_default_lifetime(),
        lifetime_choices=get_lifetime_choices(),
        uploads_enabled=uploads_enabled,
        account=current_account(),
        limits=limits_table(),
        accounts_open=accounts_enabled(),
        guest_pass=(not current_account() and not is_admin() and guest_pass.offered()),
        guest_pass_per_hour=guest_pass.per_hour(),
        guest_usage=(guest_pass.usage(ip, guest_token) if not current_account() and not is_admin()
                     and guest_pass.offered() else None),
        pass_lifetime_choices=[c for c in LIFETIME_CHOICES if c[0] <= get_guest_pass_max_lifetime()],
        guest_max_life=get_max_lifetime(False),
    ))
    if rate_limit_retry:
        response.status_code = 429
        response.headers["Retry-After"] = str(rate_limit_retry)
    return attach_guest_cookie(response)


CONTACT_MAX_MESSAGE = 5000
CONTACT_MAX_FIELD = 200
CONTACT_PER_HOUR = 5


def _contact_rate_ok(ip: str) -> bool:
    """5 messages par heure et par IP (compteur en mémoire)."""
    now = time.time()
    buckets = current_app.extensions.setdefault("pixshare_contact_rate", {})
    recent = [t for t in buckets.get(ip, []) if now - t < 3600]
    if len(recent) >= CONTACT_PER_HOUR:
        buckets[ip] = recent
        return False
    recent.append(now)
    buckets[ip] = recent
    if len(buckets) > 5000:
        for key in [k for k, v in buckets.items() if not v or now - v[-1] >= 3600]:
            buckets.pop(key, None)
    return True


@public_bp.route("/contact", methods=["GET", "POST"], endpoint="contact")
def contact():
    ip = get_client_ip()
    if ip and ip in load_blocked():
        return redirect("https://www.google.fr"), 302

    if request.method == "POST":
        validate_csrf()

        if not turnstile_ok(request.form, ip):
            flash("Vérification anti-robot échouée : cochez la case puis réessayez.", "warning")
            return redirect(url_for("public.contact"))

        msg_type = (request.form.get("type") or "contact").strip()
        if msg_type not in ("contact", "report", "appeal"):
            msg_type = "contact"
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip()
        subject = (request.form.get("subject") or "").strip()
        message = (request.form.get("message") or "").strip()
        file_url = (request.form.get("file_url") or "").strip()

        if not subject or not message:
            flash("Indiquez un sujet et un message.", "warning")
            return redirect(url_for("public.contact"))

        if len(message) > CONTACT_MAX_MESSAGE or len(subject) > CONTACT_MAX_FIELD * 2:
            flash(f"Message trop long ({CONTACT_MAX_MESSAGE} caractères maximum).", "warning")
            return redirect(url_for("public.contact"))

        if not _contact_rate_ok(get_client_ip()):
            flash("Trop de messages envoyés. Réessayez dans une heure.", "warning")
            return redirect(url_for("public.contact"))

        # Seuls les vrais liens web sont gardés (pas de « javascript: » piégé).
        if not file_url.lower().startswith(("http://", "https://")):
            file_url = ""

        create_contact_message(
            msg_type[:30], name[:CONTACT_MAX_FIELD], email[:CONTACT_MAX_FIELD],
            subject[:CONTACT_MAX_FIELD * 2], message, file_url[:CONTACT_MAX_FIELD * 5],
        )
        flash("Message envoyé ✅", "success")
        return redirect(url_for("public.contact"))

    return render_template(
        "contact.html",
        prefill_type=(request.args.get("type") or "contact"),
        prefill_subject=(request.args.get("subject") or ""),
        prefill_file_url=(request.args.get("file_url") or ""),
        version=current_app.config["APP_VERSION"],
    )


@public_bp.route("/view/<file_id>", endpoint="view_file")
def view_file(file_id):
    db, meta, server_name = get_file_record(file_id)
    if not meta:
        abort(404)

    if not _is_unlocked(file_id, meta):
        abort(404)

    if bool(meta.get("view_limit_enabled", False)):
        if not _limited_access_allowed(file_id, meta):
            abort(404)
        response = make_response(send_from_directory(current_app.config["UPLOAD_FOLDER"], server_name,
                                                     as_attachment=False))
        response.headers["X-Robots-Tag"] = "noindex, noimageindex"
        return response

    # Lien /view/ ouvert directement dans le navigateur : petite page avec l'image et un bouton « Signaler ».
    # Intégrée ailleurs (<img>, forums, aperçus WhatsApp/Discord), l'image reste servie telle quelle.
    if (request.headers.get("Sec-Fetch-Dest") == "document" and request.args.get("raw") != "1"
            and is_image_filename(meta.get("original_name", ""))):
        response = make_response(render_template(
            "view_image.html",
            file_id=file_id,
            original_name=meta.get("original_name", ""),
            raw_url=url_for("public.view_file", file_id=file_id, raw=1),
            report_reasons=REPORT_REASONS,
        ))
        response.headers["X-Robots-Tag"] = "noindex, noimageindex"
        response.headers["Cache-Control"] = "private, no-cache"
        response.headers["Vary"] = "Sec-Fetch-Dest"
        return response

    visitor_token, must_set_cookie = get_or_create_visitor_token()

    if _count_view(file_id, meta, visitor_token, has_cookie=not must_set_cookie):
        meta["views"] = int(meta.get("views", 0) or 0) + 1
        db[file_id] = meta
        save_db(db)

    served_name = server_name
    if request.args.get("m") == "1" and os.path.isfile(medium_path(file_id)):
        served_name = os.path.basename(medium_path(file_id))

    response = make_response(send_from_directory(
        current_app.config["UPLOAD_FOLDER"],
        served_name,
        as_attachment=False,
    ))
    response.headers["Cache-Control"] = "private, max-age=600"
    response.headers["Vary"] = "Sec-Fetch-Dest"  # même adresse : page (navigateur) ou image (intégration)
    response.headers["X-Robots-Tag"] = "noindex, noimageindex"  # jamais dans Google Images

    if must_set_cookie:
        response.set_cookie(
            current_app.config["VISITOR_COOKIE_NAME"],
            visitor_token,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            secure=not bool(current_app.debug),
            samesite="Lax",
        )

    return response


@public_bp.route("/image/<file_id>", endpoint="image_page")
def image_page(file_id):
    _db, meta, _server_name = get_file_record(file_id)
    if not meta:
        abort(404)

    # Vues limitées ou mot de passe : on passe par /file/, la seule page qui
    # compte les vues et demande le mot de passe.
    if bool(meta.get("view_limit_enabled", False)) or not _is_unlocked(file_id, meta):
        return redirect(url_for("public.public_file", file_id=file_id))

    meta = dict(meta)
    meta["remaining_time"] = get_remaining_time_label(meta.get("expires_at"))

    original_name = meta.get("original_name", "")
    if not is_image_filename(original_name):
        abort(404)

    record_usage_event(file_id, "image_page", stored_filename=meta.get("server_name", ""))

    file_url = url_for("public.view_file", file_id=file_id)
    download_url = url_for("public.download", file_id=file_id)
    report_url = url_for(
        "public.contact",
        type="report",
        subject="Signaler un contenu PixShare",
        file_url=request.url,
    )

    response = make_response(
        render_template(
            "image_page.html",
            file_id=file_id,
            file_url=file_url,
            download_url=download_url,
            report_url=report_url,
            report_reasons=REPORT_REASONS,
            embed_codes=embed_codes(
                url_for("public.image_page", file_id=file_id, _external=True),
                url_for("public.view_file", file_id=file_id, _external=True),
                original_name,
            ),
            original_name=original_name,
            meta=meta,
            version=current_app.config["APP_VERSION"],
        )
    )

    response.headers["X-Robots-Tag"] = "noindex, noimageindex"  # les images des utilisateurs restent privées
    return response


@public_bp.route("/report/<file_id>", methods=["POST"], endpoint="report_file")
def report_file_route(file_id):
    """Signalement en un clic depuis la page d'une image."""
    validate_csrf()
    ip = get_client_ip()
    if ip and ip in load_blocked():
        return redirect(url_for("public.index"))
    outcome = report_file(file_id, ip, (request.form.get("reason") or "").strip())
    if outcome == "hidden":
        flash("Merci : l'image est masquée en attendant la vérification de l'administrateur.", "success")
        return redirect(url_for("public.index"))
    if outcome == "missing":
        abort(404)
    if outcome == "already":
        flash("Vous avez déjà signalé cette image. Merci !", "info")
    else:
        flash("Merci, votre signalement a bien été envoyé.", "success")
    if request.form.get("back") == "view":
        return redirect(url_for("public.view_file", file_id=file_id))
    return redirect(url_for("public.image_page", file_id=file_id))


@public_bp.route("/download/<file_id>", endpoint="download")
def download(file_id):
    cleanup_expired()
    _, meta, server_name = get_file_record(file_id)
    if not meta:
        abort(404)

    if not _is_unlocked(file_id, meta) or not _limited_access_allowed(file_id, meta):
        abort(404)

    record_usage_event(file_id, "download", stored_filename=server_name)

    return send_from_directory(
        current_app.config["UPLOAD_FOLDER"],
        server_name,
        as_attachment=True,
        download_name=meta.get("original_name", "download"),
    )


@public_bp.route("/download/<file_id>.pdf", endpoint="download_pdf")
def download_pdf(file_id):
    """La photo (surtout un document scanné) en PDF A4, fabriqué à la volée : rien de plus n'est stocké."""
    cleanup_expired()
    _, meta, server_name = get_file_record(file_id)
    if not meta or not is_image_filename(server_name):
        abort(404)
    if not _is_unlocked(file_id, meta) or not _limited_access_allowed(file_id, meta):
        abort(404)
    from PIL import Image, ImageOps
    from pixshare.services.photo_filter_service import to_pdf_bytes
    try:
        with Image.open(os.path.join(current_app.config["UPLOAD_FOLDER"], server_name)) as src:
            data = to_pdf_bytes(ImageOps.exif_transpose(src) or src)
    except Exception:
        abort(404)
    record_usage_event(file_id, "download", stored_filename=server_name)
    name = os.path.splitext(secure_filename(meta.get("original_name") or "") or "document")[0] or "document"
    response = make_response(data)
    response.headers.update({"Content-Type": "application/pdf",
                             "Content-Disposition": f'attachment; filename="{name}.pdf"',
                             "X-Robots-Tag": "noindex", "Cache-Control": "private, no-store"})
    return response


@public_bp.route("/file/<file_id>", endpoint="public_file")
def public_file(file_id):
    cleanup_expired()
    db, stored_meta, _server_name = get_file_record(file_id)
    if not stored_meta:
        abort(404)

    # Limite de vues isolée : elle ne s'applique qu'aux fichiers
    # uploadés avec l'option activée. La suppression est déclenchée
    # uniquement lorsqu'une personne rouvre la page publique du fichier.
    if _view_limit_reached(stored_meta):
        delete_by_id(file_id, reason="view_limit")
        abort(404)

    # Fichier protégé : on demande le mot de passe (aucune vue n'est comptée avant).
    if not _is_unlocked(file_id, stored_meta):
        response = make_response(render_template(
            "file_locked.html",
            file_id=file_id,
            version=current_app.config["APP_VERSION"],
        ))
        response.headers["X-Robots-Tag"] = "noindex, noimageindex"
        return response

    record_usage_event(file_id, "viewer", stored_filename=stored_meta.get("server_name", ""))

    visitor_token, must_set_cookie = get_or_create_visitor_token()
    if _count_view(file_id, stored_meta, visitor_token, has_cookie=not must_set_cookie):
        stored_meta["views"] = int(stored_meta.get("views", 0) or 0) + 1
        db[file_id] = stored_meta
        save_db(db)

    meta = dict(stored_meta)
    meta["remaining_time"] = get_remaining_time_label(meta.get("expires_at"))

    response = make_response(
        render_template(
            "file.html",
            file_id=file_id,
            file_url=url_for("public.view_file", file_id=file_id),
            download_url=url_for("public.download", file_id=file_id),
            original_name=meta.get("original_name", ""),
            version=current_app.config["APP_VERSION"],
            meta=meta,
            views=int(meta.get("views", 0) or 0),
            views_remaining=(max(0, int(meta.get("max_views", 0) or 0) - int(meta.get("views", 0) or 0)) if meta.get("view_limit_enabled") else None),
            is_image=is_image_filename(meta.get("original_name", "")),
            is_video=is_video_filename(meta.get("original_name", "")),
            is_audio=is_audio_filename(meta.get("original_name", "")),
            is_document=bool(meta.get("document_scan")),
        )
    )
    response.headers["X-Robots-Tag"] = "noindex, noimageindex"

    if must_set_cookie:
        response.set_cookie(
            current_app.config["VISITOR_COOKIE_NAME"],
            visitor_token,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            secure=not bool(current_app.debug),
            samesite="Lax",
        )

    return response


@public_bp.route("/file/<file_id>/unlock", methods=["POST"], endpoint="unlock_file")
def unlock_file(file_id):
    cleanup_expired()
    validate_csrf()
    _db, meta, _server_name = get_file_record(file_id)
    if not meta:
        abort(404)

    target = redirect(url_for("public.public_file", file_id=file_id))
    if _is_unlocked(file_id, meta):
        return target

    # Contre les essais en série : 8 erreurs = 15 minutes d'attente (par IP).
    # … et par fichier, toutes adresses confondues (contre un réseau de machines) : 30 erreurs = 15 minutes.
    key = "filepw:" + (get_client_ip() or "?")
    file_key = "filepw-all:" + file_id
    locked, seconds = is_locked(key)
    if not locked:
        locked, seconds = is_locked(file_key)
    if locked:
        flash(f"Trop d'essais. Réessayez dans {max(1, seconds // 60)} min.", "warning")
        return target

    if file_password_ok(meta, request.form.get("password") or ""):
        reset_fail(key)
        _remember_unlocked(file_id)
        return target

    register_fail(key, max_failures=8)
    register_fail(file_key, max_failures=30)
    flash("Mot de passe incorrect.", "danger")
    return target


@public_bp.route("/delete/<file_id>", methods=["POST"], endpoint="delete_own_file")
def delete_own_file(file_id):
    cleanup_expired()
    validate_csrf()

    if not file_id:
        flash("Photo non précisée.", "warning")
        return redirect(url_for("public.index"))

    db = load_db()
    meta = db.get(file_id)
    if not meta:
        flash("Photo introuvable.", "warning")
        return redirect(url_for("public.index"))

    get_guest_token()
    if not is_admin() and not is_owner(meta):
        abort(403)

    ok = delete_by_id(file_id)
    if ok:
        from pixshare.services.legal_log_service import SUPPRESSION, record as legal_record
        legal_record(SUPPRESSION, file_id)
    flash(
        "Supprimé ✅" if ok else "Suppression impossible.",
        "success" if ok else "warning",
    )
    return redirect(url_for("public.index"))

@public_bp.route("/cgu", endpoint="cgu")
def cgu():
    from pixshare.services.settings_service import load_settings
    s = load_settings()
    return render_template("cgu.html", version=current_app.config["APP_VERSION"],
                           absent_members=bool(s.get("admin_absent_mode")) and bool(s.get("admin_absent_members")))


@public_bp.route("/faq", endpoint="faq")
def faq():
    from pixshare.services.faq_service import faq as faq_sections
    sections = faq_sections()
    json_items = [{"@type": "Question", "name": i["q"], "acceptedAnswer": {"@type": "Answer", "text": i["a"]}}
                  for s in sections for i in s["items"]]
    return render_template("faq.html", sections=sections, json_items=json_items,
                           title="Questions fréquentes – PixShare")


@public_bp.route("/album-souvenir", endpoint="albums_info")
def albums_info():
    """Page publique (indexée) qui présente les albums souvenirs d'événement."""
    from pixshare.services.album_service import THEMES, enabled
    from pixshare.services.settings_service import limits_table
    return render_template("albums_info.html", themes=THEMES, albums_on=enabled(), limits=limits_table(),
                           title="Album souvenir de mariage et d'événement partagé par QR code – PixShare")


@public_bp.route("/mentions-legales", endpoint="mentions_legales")
def mentions_legales():
    from pixshare.services.backup_service import is_configured
    return render_template("mentions_legales.html", version=current_app.config["APP_VERSION"],
                           backup_on=is_configured())


@public_bp.route("/mes-fichiers/statut", endpoint="files_status")
def files_status():
    """État des fichiers en cours de vérification (seulement ceux de ce visiteur ou de son compte)."""
    wanted = [i for i in (request.args.get("ids") or "").split(",") if i][:20]
    mine = {f["id"]: f for f in list_guest_files()}
    out = {}
    for file_id in wanted:
        f = mine.get(file_id)
        if not f:
            out[file_id] = "gone"
        elif f.get("status") != "pending":
            out[file_id] = "active"
        elif f.get("moderation_decision") == "manual_review":
            out[file_id] = "review"
        else:
            out[file_id] = "checking"
    response = jsonify(out)
    response.headers["Cache-Control"] = "no-store"
    return response
