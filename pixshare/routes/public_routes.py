from flask import Blueprint, abort, current_app, flash, make_response, redirect, render_template, request, send_from_directory, url_for
from werkzeug.utils import secure_filename

import json, os
import secrets
from datetime import datetime, timedelta

from pixshare.config import Config

from pixshare.security.csrf import validate_csrf
from pixshare.services.auth_service import is_admin
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
from pixshare.services.json_services import load_api_keys, load_blocked, load_db, save_api_keys, save_db
from pixshare.services.request_service import get_client_ip
from pixshare.services.vote_service import get_vote_summary, is_image_filename, register_vote
from pixshare.services.settings_service import get_default_lifetime, get_max_upload_size_bytes, get_max_upload_size_mb

public_bp = Blueprint("public", __name__)

config = Config()

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
        as_attachment=False
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

    response = make_response(render_template(
        "image_page.html",
        file_id=file_id,
        file_url=file_url,
        download_url=download_url,
        report_url=report_url,
        original_name=original_name,
        meta=meta,
        vote_summary=vote_summary,
        version=current_app.config["APP_VERSION"],
    ))

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

    response = make_response(render_template(
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
    ))
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
        "success" if ok else "warning"
    )
    return redirect(url_for("public.index"))


@public_bp.route("/cgu", endpoint="cgu")
def cgu():
    return render_template("cgu.html", version=current_app.config["APP_VERSION"])


@public_bp.route("/mentions-legales", endpoint="mentions_legales")
def mentions_legales():
    return render_template("mentions_legales.html", version=current_app.config["APP_VERSION"])
    
    
@public_bp.route("/api")
def api_page():
    return render_template("api.html", version=current_app.config["APP_VERSION"], max_dim=config.API_MAX_DIMENSION)


REQUEST_FILE = "pixshare/data/api_requests.json"
DEMO_KEY_DAILY_LIMIT = 5
DEMO_KEY_TOTAL_LIMIT = 20
DEMO_ALLOWED_LIFETIMES = [2, 5]
DEMO_KEY_MAX_FILE_SIZE_MB = 10
DEMO_KEY_VALIDITY_DAYS = 7
DEMO_CREATION_LIMIT_PER_IP = 3
DEMO_CREATION_LIMIT_PER_EMAIL = 2


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

        key_value, key_data = _build_demo_api_key_record(email, project_name, usage_type, usage_details, estimated_uploads)
        save_request({
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
        })
        flash("Clé API démo générée automatiquement ✅", "success")
        return render_template(
            "api.html",
            version=current_app.config["APP_VERSION"],
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
        file_url=""
    )

    flash("Demande d’API standard envoyée ✅", "success")
    return redirect(url_for("public.api_page") + "#api-request")
    
@public_bp.route("/api/key", methods=["GET"], endpoint="api_request_key_page")
def api_request_key_page():
    return render_template(
        "api_request_key.html",
        version=current_app.config["APP_VERSION"],
    )