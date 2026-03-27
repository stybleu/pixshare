from flask import Blueprint, abort, current_app, flash, make_response, redirect, render_template, request, send_from_directory, url_for
from werkzeug.utils import secure_filename

import json
import os
import secrets
from datetime import datetime, timedelta

from pixshare.config import Config

from pixshare.security.csrf import validate_csrf
from pixshare.services.auth_service import is_admin
from pixshare.services.api_user_service import (
    attach_api_key_to_user,
    create_api_user,
    current_api_user,
    find_user_by_pseudo,
    get_active_api_key,
    clear_active_api_key_for_user,
    get_user_api_keys,
    login_api_user,
    logout_api_user,
    remove_api_key_from_user,
    set_active_api_key_for_user,
    verify_password,
)
from pixshare.services.contact_service import create_contact_message
from pixshare.services.file_service import (
    allowed_file,
    can_keep_uploads,
    cleanup_expired,
    delete_by_id,
    get_file_record,
    get_guest_token,
    get_or_create_visitor_token,
    list_guest_files,
    register_unique_view,
    save_uploaded_file,
)
from pixshare.services.json_services import (
    load_api_keys,
    load_blocked,
    load_db,
    save_api_keys,
    save_db,
)
from pixshare.services.request_service import get_client_ip
from pixshare.services.vote_service import get_vote_summary, is_image_filename, register_vote
from pixshare.services.settings_service import (
    get_default_lifetime,
    get_max_upload_size_bytes,
    get_max_upload_size_mb,
)

public_bp = Blueprint("public", __name__)

config = Config()

REQUEST_FILE = "pixshare/data/api_requests.json"
DEMO_KEY_DAILY_LIMIT = 5
DEMO_KEY_TOTAL_LIMIT = 20
DEMO_ALLOWED_LIFETIMES = [2, 5]
DEMO_KEY_MAX_FILE_SIZE_MB = 10
DEMO_KEY_VALIDITY_DAYS = 7
DEMO_CREATION_LIMIT_PER_IP = 3
DEMO_CREATION_LIMIT_PER_EMAIL = 2


# =========================================================
# Helpers API / requests
# =========================================================

def save_request(data):
    os.makedirs(os.path.dirname(REQUEST_FILE), exist_ok=True)

    if not os.path.exists(REQUEST_FILE):
        with open(REQUEST_FILE, "w", encoding="utf-8") as f:
            json.dump([], f, ensure_ascii=False, indent=2)

    try:
        with open(REQUEST_FILE, "r", encoding="utf-8") as f:
            requests_data = json.load(f)
    except (json.JSONDecodeError, OSError):
        requests_data = []

    if not isinstance(requests_data, list):
        requests_data = []

    requests_data.append(data)

    with open(REQUEST_FILE, "w", encoding="utf-8") as f:
        json.dump(requests_data, f, ensure_ascii=False, indent=2)


def _load_api_requests():
    os.makedirs(os.path.dirname(REQUEST_FILE), exist_ok=True)
    if not os.path.exists(REQUEST_FILE):
        return []

    try:
        with open(REQUEST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    return data if isinstance(data, list) else []


def _count_recent_demo_requests(ip: str, email: str) -> tuple[int, int]:
    requests_data = _load_api_requests()
    now = datetime.utcnow()
    ip_count = 0
    email_count = 0

    for item in requests_data:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "api_demo_auto":
            continue

        created_at = str(item.get("created_at") or "")
        try:
            created_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            continue

        if now - created_dt > timedelta(hours=24):
            continue

        if ip and item.get("ip") == ip:
            ip_count += 1

        if email and str(item.get("email") or "").strip().lower() == email.lower():
            email_count += 1

    return ip_count, email_count


def _build_demo_api_key_record(email: str, project_name: str, usage_type: str, usage_details: str, estimated_uploads: str) -> tuple[str, dict]:
    api_keys = load_api_keys()
    key_value = f"ps_demo_{secrets.token_urlsafe(24).replace('-', '').replace('_', '')}"

    while key_value in api_keys:
        key_value = f"ps_demo_{secrets.token_urlsafe(24).replace('-', '').replace('_', '')}"

    created_at = datetime.utcnow()

    record = {
        "name": f"demo-{project_name[:24] or 'client'}",
        "key_type": "demo",
        "is_active": True,
        "max_uploads_total": DEMO_KEY_TOTAL_LIMIT,
        "uploads_used": 0,
        "max_uploads_per_day": DEMO_KEY_DAILY_LIMIT,
        "daily_uploads_used": 0,
        "daily_reset_date": "",
        "max_file_size_mb": DEMO_KEY_MAX_FILE_SIZE_MB,
        "allow_permanent": False,
        "default_lifetime_minutes": 5,
        "allowed_lifetimes": DEMO_ALLOWED_LIFETIMES,
        "notes": f"Clé API démo auto | {email} | {project_name} | {usage_type}",
        "email": email,
        "project_name": project_name,
        "usage_type": usage_type,
        "usage_details": usage_details,
        "estimated_uploads": estimated_uploads,
        "created_at": created_at.isoformat(timespec="seconds") + "Z",
        "expires_at": (created_at + timedelta(days=DEMO_KEY_VALIDITY_DAYS)).isoformat(timespec="seconds") + "Z",
        "auto_generated": True,
    }

    api_keys[key_value] = record
    save_api_keys(api_keys)
    return key_value, record


def _generate_standard_user_key(pseudo: str) -> tuple[str, dict]:
    api_keys = load_api_keys()
    api_key_value = f"ps_{secrets.token_urlsafe(24).replace('-', '').replace('_', '')}"

    while api_key_value in api_keys:
        api_key_value = f"ps_{secrets.token_urlsafe(24).replace('-', '').replace('_', '')}"

    created_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    key_record = {
        "name": pseudo,
        "key_type": "user",
        "is_active": True,
        "max_uploads_total": 1000,
        "uploads_used": 0,
        "max_uploads_per_day": 50,
        "daily_uploads_used": 0,
        "daily_reset_date": "",
        "max_file_size_mb": 10,
        "allow_permanent": False,
        "default_lifetime_minutes": 10,
        "allowed_lifetimes": [5, 10, 20, 30],
        "notes": f"Clé créée automatiquement pour le compte API {pseudo}",
        "created_at": created_at,
        "auto_generated": True,
    }

    api_keys[api_key_value] = key_record
    save_api_keys(api_keys)

    return api_key_value, key_record


def _normalize_key_value(value):
    if isinstance(value, str):
        return value.strip()

    if isinstance(value, dict):
        return (
            value.get("key")
            or value.get("value")
            or value.get("api_key")
            or value.get("token")
            or ""
        ).strip()

    return ""


def _get_user_key_values(user: dict) -> list[str]:
    raw_keys = []

    try:
        raw_keys = get_user_api_keys(user)
    except TypeError:
        try:
            raw_keys = get_user_api_keys(user.get("id"))
        except TypeError:
            raw_keys = []

    if not raw_keys:
        single = (user.get("api_key") or "").strip()
        return [single] if single else []

    result = []
    for item in raw_keys:
        key_value = _normalize_key_value(item)
        if key_value and key_value not in result:
            result.append(key_value)

    single = (user.get("api_key") or "").strip()
    if single and single not in result:
        result.append(single)

    return result


def _get_active_key_value(user: dict) -> str:
    active = ""

    try:
        active = get_active_api_key(user)
    except TypeError:
        try:
            active = get_active_api_key(user.get("id"))
        except TypeError:
            active = ""

    active = _normalize_key_value(active)

    if not active:
        active = (user.get("api_key") or "").strip()

    return active


def _set_active_key(user: dict, key_value: str):
    try:
        set_active_api_key_for_user(user.get("id"), key_value)
    except TypeError:
        set_active_api_key_for_user(user, key_value)


def _attach_key_to_user(user: dict, key_value: str):
    try:
        attach_api_key_to_user(user.get("id"), key_value)
    except TypeError:
        attach_api_key_to_user(user, key_value)


def _remove_key_from_user(user: dict, key_value: str):
    try:
        remove_api_key_from_user(user.get("id"), key_value)
    except TypeError:
        remove_api_key_from_user(user, key_value)


def _clear_active_key(user: dict):
    try:
        clear_active_api_key_for_user(user.get("id"))
    except TypeError:
        clear_active_api_key_for_user(user)


def _first_enabled_key(key_values: list[str], api_keys_db: dict) -> str:
    for key_value in key_values:
        record = api_keys_db.get(key_value) or {}
        if bool(record.get("is_active", True)):
            return key_value
    return ""


def _build_dashboard_keys(user: dict) -> tuple[list[dict], str, dict | None]:
    api_keys_db = load_api_keys()
    user_key_values = _get_user_key_values(user)
    active_key_value = _get_active_key_value(user)

    dashboard_keys = []
    active_record = None

    for key_value in user_key_values:
        record = dict(api_keys_db.get(key_value, {}))
        record["key_value"] = key_value
        record["is_selected"] = (key_value == active_key_value)
        record["is_current_active"] = record["is_selected"]
        dashboard_keys.append(record)

        if record["is_selected"]:
            active_record = record

    return dashboard_keys, active_key_value, active_record


# =========================================================
# Public site
# =========================================================

@public_bp.route("/", methods=["GET", "POST"], endpoint="index")
def index():
    cleanup_expired()

    ip = get_client_ip()
    blocked = load_blocked()
    if ip and ip in blocked:
        return redirect("https://www.google.fr"), 302

    guest_token = get_guest_token()

    if request.method == "POST":
        validate_csrf()

        f = request.files.get("file")
        if not f or f.filename == "":
            flash("Aucun fichier sélectionné.", "warning")
            return redirect(url_for("public.index"))

        original = f.filename
        safe_name = secure_filename(original)
        if not safe_name:
            flash("Nom de fichier invalide.", "danger")
            return redirect(url_for("public.index"))

        if not allowed_file(safe_name):
            allowed = ", ".join(sorted(current_app.config["ALLOWED_EXTENSIONS"]))
            flash(f"Extension non autorisée. Autorisées : {allowed}", "danger")
            return redirect(url_for("public.index"))

        max_size_bytes = get_max_upload_size_bytes()
        content_length = request.content_length or 0
        if content_length > max_size_bytes:
            max_mb = get_max_upload_size_mb()
            flash(f"Fichier trop volumineux. Taille maximale : {max_mb} Mo.", "danger")
            return redirect(url_for("public.index"))

        keep = (request.form.get("keep", "") in {"1", "on", "true", "yes"})
        _, lifetime, permanent = save_uploaded_file(
            f,
            original_name=original,
            client_ip=ip,
            guest_token=guest_token,
            keep_requested=keep,
        )

        if permanent:
            flash("Fichier upload ✅ (sans expiration)", "success")
        else:
            flash(f"Fichier upload ✅ (expiration: {lifetime} min)", "success")

        return redirect(url_for("public.index"))

    guest_files = list_guest_files()
    for item in guest_files:
        file_id = item.get("id") or item.get("file_id")
        if not file_id:
            continue

        summary = get_vote_summary(file_id, ip)
        item["views"] = int(item.get("views", 0) or 0)
        item["votes_up"] = summary["up"]
        item["votes_down"] = summary["down"]
        item["score"] = summary["score"]

    return render_template(
        "index.html",
        guest_files=guest_files,
        max_mb=get_max_upload_size_mb(),
        admin=is_admin(),
        version=current_app.config["APP_VERSION"],
        can_keep=can_keep_uploads(),
        default_lifetime=get_default_lifetime(),
    )


@public_bp.route("/contact", methods=["GET", "POST"], endpoint="contact")
def contact():
    if request.method == "POST":
        validate_csrf()

        msg_type = (request.form.get("type") or "contact").strip()
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip()
        subject = (request.form.get("subject") or "").strip()
        message = (request.form.get("message") or "").strip()
        file_url = (request.form.get("file_url") or "").strip()

        if not subject or not message:
            flash("Sujet et message requis.", "warning")
            return redirect(url_for("public.contact"))

        create_contact_message(msg_type, name, email, subject, message, file_url)
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
    cleanup_expired()
    _, meta, server_name = get_file_record(file_id)
    if not meta:
        abort(404)

    return send_from_directory(
        current_app.config["UPLOAD_FOLDER"],
        server_name,
        as_attachment=False,
    )


@public_bp.route("/image/<file_id>", endpoint="image_page")
def image_page(file_id):
    cleanup_expired()

    _db, meta, _server_name = get_file_record(file_id)
    if not meta:
        abort(404)

    original_name = meta.get("original_name", "")
    if not is_image_filename(original_name):
        abort(404)

    client_ip = get_client_ip()
    vote_summary = get_vote_summary(file_id, client_ip)
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
            original_name=original_name,
            meta=meta,
            vote_summary=vote_summary,
            version=current_app.config["APP_VERSION"],
        )
    )

    if not bool(meta.get("permanent")):
        response.headers["X-Robots-Tag"] = "noindex, noimageindex"

    return response


@public_bp.route("/download/<file_id>", endpoint="download")
def download(file_id):
    cleanup_expired()
    _, meta, server_name = get_file_record(file_id)
    if not meta:
        abort(404)

    return send_from_directory(
        current_app.config["UPLOAD_FOLDER"],
        server_name,
        as_attachment=True,
        download_name=meta.get("original_name", "download"),
    )


@public_bp.route("/file/<file_id>", endpoint="public_file")
def public_file(file_id):
    cleanup_expired()
    db, meta, _server_name = get_file_record(file_id)
    if not meta:
        abort(404)

    visitor_token, must_set_cookie = get_or_create_visitor_token()
    if register_unique_view(file_id, visitor_token):
        meta["views"] = int(meta.get("views", 0) or 0) + 1
        db[file_id] = meta
        save_db(db)

    client_ip = get_client_ip()
    vote_summary = get_vote_summary(file_id, client_ip)

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
            vote_summary=vote_summary,
            is_image=is_image_filename(meta.get("original_name", "")),
        )
    )
    response.headers["X-Robots-Tag"] = "noindex, noimageindex"

    if must_set_cookie:
        response.set_cookie(
            current_app.config["VISITOR_COOKIE_NAME"],
            visitor_token,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            secure=True,
            samesite="Lax",
        )

    return response


@public_bp.route("/file/<file_id>/vote", methods=["POST"], endpoint="vote_file")
def vote_file(file_id):
    cleanup_expired()
    validate_csrf()

    _db, meta, _server_name = get_file_record(file_id)
    if not meta:
        abort(404)

    original_name = meta.get("original_name", "")
    if not is_image_filename(original_name):
        flash("Le vote est réservé aux images.", "warning")
        return redirect(url_for("public.public_file", file_id=file_id))

    vote_value = (request.form.get("vote") or "").strip().lower()
    if vote_value not in {"up", "down"}:
        flash("Vote invalide.", "warning")
        return redirect(url_for("public.public_file", file_id=file_id))

    client_ip = get_client_ip()
    if not client_ip:
        flash("Impossible d'enregistrer le vote pour le moment.", "warning")
        return redirect(url_for("public.public_file", file_id=file_id))

    register_vote(file_id, client_ip, vote_value)
    return redirect(url_for("public.public_file", file_id=file_id))


@public_bp.route("/delete/<file_id>", methods=["POST"], endpoint="delete_own_file")
def delete_own_file(file_id):
    cleanup_expired()
    validate_csrf()

    if not file_id:
        flash("ID fichier manquant.", "warning")
        return redirect(url_for("public.index"))

    db = load_db()
    meta = db.get(file_id)
    if not meta:
        flash("Fichier introuvable.", "warning")
        return redirect(url_for("public.index"))

    if not is_admin() and meta.get("guest_token") != get_guest_token():
        abort(403)

    ok = delete_by_id(file_id)
    flash(
        "Fichier supprimé ✅" if ok else "Suppression impossible.",
        "success" if ok else "warning",
    )
    return redirect(url_for("public.index"))


@public_bp.route("/cgu", endpoint="cgu")
def cgu():
    return render_template("cgu.html", version=current_app.config["APP_VERSION"])


@public_bp.route("/mentions-legales", endpoint="mentions_legales")
def mentions_legales():
    return render_template("mentions_legales.html", version=current_app.config["APP_VERSION"])


# =========================================================
# API public page
# =========================================================

@public_bp.route("/api")
def api_page():
    user = current_api_user()
    api_user_key = ""
    api_user_key_data = None

    if user:
        dashboard_keys, active_key_value, active_record = _build_dashboard_keys(user)
        api_user_key = active_key_value
        api_user_key_data = active_record
    else:
        dashboard_keys = []

    return render_template(
        "api.html",
        version=current_app.config["APP_VERSION"],
        max_dim=config.API_MAX_DIMENSION,
        api_user=user,
        api_user_key=api_user_key,
        api_user_key_data=api_user_key_data,
        api_user_keys=dashboard_keys,
    )


@public_bp.route("/api/request-key", methods=["POST"])
def request_api_key():
    validate_csrf()

    request_type = (request.form.get("request_type") or "standard").strip().lower()
    if request_type not in {"demo", "standard"}:
        request_type = "standard"

    email = (request.form.get("email") or "").strip()
    project_name = (request.form.get("project_name") or "").strip()
    usage_type = (request.form.get("usage_type") or "").strip()
    usage_details = (request.form.get("usage_details") or "").strip()
    estimated_uploads = (request.form.get("estimated_uploads") or "").strip()
    client_ip = get_client_ip()

    if not email or not project_name or not usage_type:
        flash("Merci de remplir au minimum l’email, le nom du projet et le type d’utilisation.", "warning")
        return redirect(url_for("public.api_page") + "#api-request")

    if request_type == "demo":
        ip_count, email_count = _count_recent_demo_requests(client_ip, email)

        if ip_count >= DEMO_CREATION_LIMIT_PER_IP:
            flash("Trop de clés API démo créées depuis cette IP sur 24h.", "warning")
            return redirect(url_for("public.api_page") + "#api-request")

        if email_count >= DEMO_CREATION_LIMIT_PER_EMAIL:
            flash("Trop de clés API démo créées pour cet email sur 24h.", "warning")
            return redirect(url_for("public.api_page") + "#api-request")

        key_value, key_data = _build_demo_api_key_record(
            email,
            project_name,
            usage_type,
            usage_details,
            estimated_uploads,
        )

        save_request(
            {
                "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                "type": "api_demo_auto",
                "request_type": "demo",
                "email": email,
                "project_name": project_name,
                "usage_type": usage_type,
                "estimated_uploads": estimated_uploads,
                "usage_details": usage_details,
                "ip": client_ip,
                "api_key": key_value,
            }
        )

        flash("Clé API démo générée automatiquement ✅", "success")
        return render_template(
            "api.html",
            version=current_app.config["APP_VERSION"],
            max_dim=config.API_MAX_DIMENSION,
            generated_demo_key=key_value,
            generated_demo_key_info=key_data,
        )

    payload = {
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "type": "api_request",
        "request_type": "standard",
        "email": email,
        "project_name": project_name,
        "usage_type": usage_type,
        "estimated_uploads": estimated_uploads,
        "usage_details": usage_details,
        "ip": client_ip,
    }
    save_request(payload)

    message = f"""
📌 Nouvelle demande API standard

Projet : {project_name}
Type d'utilisation : {usage_type}
Volume estimé : {estimated_uploads or 'Non précisé'}
Détails : {usage_details or 'Aucun détail supplémentaire'}
"""

    create_contact_message(
        msg_type="api_request",
        name="Demande API standard",
        email=email,
        subject="Nouvelle demande API standard",
        message=message.strip(),
        file_url="",
    )

    flash("Demande d’API standard envoyée ✅", "success")
    return redirect(url_for("public.api_page") + "#api-request")


# =========================================================
# API account
# =========================================================

@public_bp.route("/api/register", methods=["POST"])
def api_register():
    validate_csrf()

    pseudo = (request.form.get("pseudo") or "").strip()
    password = (request.form.get("password") or "").strip()

    if not pseudo or not password:
        flash("Pseudo et mot de passe requis.", "warning")
        return redirect(url_for("public.api_page") + "#api-account")

    user, error = create_api_user(pseudo, password)
    if error:
        flash(error, "warning")
        return redirect(url_for("public.api_page") + "#api-account")

    api_key_value, _key_record = _generate_standard_user_key(pseudo)

    _attach_key_to_user(user, api_key_value)
    _set_active_key(user, api_key_value)

    user["api_key"] = api_key_value
    login_api_user(user)

    flash("Compte API créé ✅", "success")
    return redirect(url_for("public.api_dashboard"))


@public_bp.route("/api/login", methods=["POST"])
def api_login():
    validate_csrf()

    pseudo = (request.form.get("pseudo") or "").strip()
    password = (request.form.get("password") or "").strip()

    if not pseudo or not password:
        flash("Pseudo et mot de passe requis.", "warning")
        return redirect(url_for("public.api_page") + "#api-account")

    user = find_user_by_pseudo(pseudo)
    if not user or not verify_password(user, password):
        flash("Identifiants invalides.", "danger")
        return redirect(url_for("public.api_page") + "#api-account")

    login_api_user(user)
    flash("Connexion API réussie ✅", "success")
    return redirect(url_for("public.api_dashboard"))


@public_bp.route("/api/dashboard")
def api_dashboard():
    user = current_api_user()
    if not user:
        flash("Connectez-vous pour accéder à votre dashboard API.", "warning")
        return redirect(url_for("public.api_page") + "#api-account")

    dashboard_keys, active_key_value, active_record = _build_dashboard_keys(user)

    return render_template(
        "api_dashboard.html",
        version=current_app.config["APP_VERSION"],
        user=user,
        api_key=active_key_value,
        key_data=active_record or {},
        user_keys=dashboard_keys,
        active_api_key=active_key_value,
    )


@public_bp.route("/api/logout")
def api_logout():
    logout_api_user()
    flash("Déconnexion API effectuée.", "success")
    return redirect(url_for("public.api_page") + "#api-account")


# =========================================================
# API multikey actions
# =========================================================

@public_bp.route("/api/key/select", methods=["POST"])
def api_select_key():
    validate_csrf()

    user = current_api_user()
    if not user:
        flash("Connexion requise.", "warning")
        return redirect(url_for("public.api_page") + "#api-account")

    selected_key = (request.form.get("selected_key") or "").strip()
    if not selected_key:
        flash("Aucune clé sélectionnée.", "warning")
        return redirect(url_for("public.api_dashboard"))

    user_key_values = _get_user_key_values(user)
    if selected_key not in user_key_values:
        flash("Cette clé ne vous appartient pas.", "danger")
        return redirect(url_for("public.api_dashboard"))

    api_keys_db = load_api_keys()
    if selected_key not in api_keys_db:
        flash("Cette clé n'existe plus dans la base API.", "danger")
        return redirect(url_for("public.api_dashboard"))

    _set_active_key(user, selected_key)
    user["api_key"] = selected_key
    login_api_user(user)

    flash("Clé active mise à jour ✅", "success")
    return redirect(url_for("public.api_dashboard"))


@public_bp.route("/api/key/toggle-active", methods=["POST"])
def api_toggle_key():
    validate_csrf()

    user = current_api_user()
    if not user:
        flash("Connexion requise.", "warning")
        return redirect(url_for("public.api_page") + "#api-account")

    key_to_toggle = (request.form.get("key_to_toggle") or "").strip()
    if not key_to_toggle:
        flash("Aucune clé sélectionnée.", "warning")
        return redirect(url_for("public.api_dashboard"))

    user_key_values = _get_user_key_values(user)
    if key_to_toggle not in user_key_values:
        flash("Cette clé ne vous appartient pas.", "danger")
        return redirect(url_for("public.api_dashboard"))

    api_keys_db = load_api_keys()
    key_data = api_keys_db.get(key_to_toggle)
    if not isinstance(key_data, dict):
        flash("Cette clé n'existe plus dans la base API.", "danger")
        return redirect(url_for("public.api_dashboard"))

    new_state = not bool(key_data.get("is_active", True))
    key_data["is_active"] = new_state
    api_keys_db[key_to_toggle] = key_data
    save_api_keys(api_keys_db)

    active_key_value = _get_active_key_value(user)

    if not new_state and active_key_value == key_to_toggle:
        remaining_keys = [k for k in user_key_values if k != key_to_toggle]
        new_active_key = _first_enabled_key(remaining_keys, api_keys_db)
        if new_active_key:
            _set_active_key(user, new_active_key)
            user["api_key"] = new_active_key
        else:
            _clear_active_key(user)
            user["api_key"] = ""
    elif new_state and not active_key_value:
        _set_active_key(user, key_to_toggle)
        user["api_key"] = key_to_toggle

    login_api_user(user)

    if new_state:
        flash("Clé réactivée ✅", "success")
    else:
        flash("Clé rendue inactive ✅", "warning")
    return redirect(url_for("public.api_dashboard"))


@public_bp.route("/api/key/delete", methods=["POST"])
def api_delete_key():
    validate_csrf()

    user = current_api_user()
    if not user:
        flash("Connexion requise.", "warning")
        return redirect(url_for("public.api_page") + "#api-account")

    key_to_delete = (request.form.get("key_to_delete") or "").strip()
    if not key_to_delete:
        flash("Aucune clé à supprimer.", "warning")
        return redirect(url_for("public.api_dashboard"))

    user_key_values = _get_user_key_values(user)
    if key_to_delete not in user_key_values:
        flash("Cette clé ne vous appartient pas.", "danger")
        return redirect(url_for("public.api_dashboard"))

    if len(user_key_values) <= 1:
        flash("Vous devez conserver au moins une clé API.", "warning")
        return redirect(url_for("public.api_dashboard"))

    api_keys_db = load_api_keys()
    if key_to_delete in api_keys_db:
        del api_keys_db[key_to_delete]
        save_api_keys(api_keys_db)

    _remove_key_from_user(user, key_to_delete)

    remaining_keys = [k for k in user_key_values if k != key_to_delete]
    active_key_value = _get_active_key_value(user)
    refreshed_api_keys_db = load_api_keys()

    if active_key_value == key_to_delete:
        new_active_key = _first_enabled_key(remaining_keys, refreshed_api_keys_db)
        if new_active_key:
            _set_active_key(user, new_active_key)
            user["api_key"] = new_active_key
        else:
            _clear_active_key(user)
            user["api_key"] = ""
    elif not _get_active_key_value(user):
        new_active_key = _first_enabled_key(remaining_keys, refreshed_api_keys_db)
        if new_active_key:
            _set_active_key(user, new_active_key)
            user["api_key"] = new_active_key

    login_api_user(user)

    flash("Clé supprimée ✅", "success")
    return redirect(url_for("public.api_dashboard"))


@public_bp.route("/api/key/create-standard", methods=["POST"])
def api_create_standard_key():
    validate_csrf()

    user = current_api_user()
    if not user:
        flash("Connexion requise.", "warning")
        return redirect(url_for("public.api_page") + "#api-account")

    pseudo = (user.get("pseudo") or "user").strip()

    new_key_value, _new_key_record = _generate_standard_user_key(pseudo)
    _attach_key_to_user(user, new_key_value)
    _set_active_key(user, new_key_value)

    user["api_key"] = new_key_value
    login_api_user(user)

    create_contact_message(
        msg_type="api_standard_request",
        name=pseudo,
        email="",
        subject="Nouvelle clé API standard créée depuis dashboard",
        message=(
            f"Pseudo : {pseudo}\n"
            f"Nouvelle clé : {new_key_value}\n"
            f"Création automatique depuis dashboard."
        ),
        file_url="",
    )

    flash("Clé standard créée et définie comme clé active ✅", "success")
    return redirect(url_for("public.api_dashboard"))


@public_bp.route("/api/request-standard", methods=["POST"])
def api_request_standard():
    """
    Compatibilité :
    on garde l'URL existante mais maintenant elle crée directement
    une nouvelle clé standard, qui devient active.
    """
    return api_create_standard_key()