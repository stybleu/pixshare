from flask import Blueprint, abort, current_app, flash, make_response, redirect, render_template, request, send_from_directory, url_for
from werkzeug.utils import secure_filename

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
from pixshare.services.json_services import load_blocked, load_db, save_db
from pixshare.services.request_service import get_client_ip

public_bp = Blueprint("public", __name__)


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

    return render_template(
        "index.html",
        guest_files=list_guest_files(),
        max_mb=int(current_app.config["MAX_CONTENT_LENGTH"] / (1024 * 1024)),
        admin=is_admin(),
        version=current_app.config["APP_VERSION"],
        can_keep=can_keep_uploads(),
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
    return send_from_directory(current_app.config["UPLOAD_FOLDER"], server_name, as_attachment=False)


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

    response = make_response(render_template(
        "file.html",
        file_url=url_for("public.view_file", file_id=file_id),
        original_name=meta.get("original_name", ""),
        version=current_app.config["APP_VERSION"],
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
    flash("Fichier supprimé ✅" if ok else "Suppression impossible.", "success" if ok else "warning")
    return redirect(url_for("public.index"))


@public_bp.route("/cgu", endpoint="cgu")
def cgu():
    return render_template("cgu.html", version=current_app.config["APP_VERSION"])


@public_bp.route("/mentions-legales", endpoint="mentions_legales")
def mentions_legales():
    return render_template("mentions_legales.html", version=current_app.config["APP_VERSION"])
