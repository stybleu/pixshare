import os

from flask import Blueprint, current_app, flash, redirect, render_template, request, send_file, session, url_for, abort

from pixshare.security.csrf import validate_csrf
from pixshare.services.auth_service import admin_required, process_admin_login
from pixshare.services.file_service import cleanup_expired, delete_by_id, get_thumbnail_abs_path, list_all_files
from pixshare.services.json_services import load_blocked, load_contacts, save_blocked, save_contacts
from pixshare.services.settings_service import (
    get_valid_lifetime,
    get_valid_thumbnail_retention_hours,
    load_settings,
    save_settings,
)
from pixshare.services.time_service import get_remaining_time_label

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin/messages/clear", methods=["POST"], endpoint="admin_clear_messages")
@admin_required
def admin_clear_messages():
    validate_csrf()
    save_contacts([])
    flash("Tous les messages ont été supprimés ✅", "success")
    return redirect(url_for("admin.admin_messages"))


@admin_bp.route("/admin/messages", methods=["GET"], endpoint="admin_messages")
@admin_required
def admin_messages():
    items = load_contacts()
    items.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    for i, item in enumerate(items):
        item["_display_index"] = i

    return render_template(
        "admin_messages.html",
        messages=items,
        version=current_app.config["APP_VERSION"]
    )


@admin_bp.route("/admin/messages/delete", methods=["POST"], endpoint="admin_delete_message")
@admin_required
def admin_delete_message():
    validate_csrf()

    created_at = (request.form.get("created_at") or "").strip()
    email = (request.form.get("email") or "").strip()
    message = (request.form.get("message") or "").strip()

    items = load_contacts()
    new_items = []
    deleted = False

    for item in items:
        same_item = (
            item.get("created_at", "").strip() == created_at and
            item.get("email", "").strip() == email and
            item.get("message", "").strip() == message
        )

        if same_item and not deleted:
            deleted = True
            continue

        new_items.append(item)

    if deleted:
        save_contacts(new_items)
        flash("Message supprimé ✅", "success")
    else:
        flash("Message introuvable.", "warning")

    return redirect(url_for("admin.admin_messages"))


@admin_bp.route("/admin/blocked-ips")
@admin_required
def admin_blocked_ips():
    blocked = load_blocked()
    return render_template(
        "admin_blocked_ips.html",
        blocked_ips=blocked,
        version=current_app.config["APP_VERSION"]
    )


@admin_bp.route("/admin/blocked-ips/clear", methods=["POST"])
@admin_required
def admin_clear_blocked_ips():
    validate_csrf()
    save_blocked([])
    flash("La liste des IP bloquées a été vidée.", "success")
    return redirect(url_for("admin.admin_blocked_ips"))


@admin_bp.route("/admin/blocked-ips/unblock", methods=["POST"], endpoint="admin_unblock_ip")
@admin_required
def admin_unblock_ip():
    validate_csrf()
    ip = (request.form.get("ip") or "").strip()

    if not ip:
        flash("IP invalide.", "warning")
        return redirect(url_for("admin.admin_blocked_ips"))

    blocked = load_blocked()

    if ip in blocked:
        blocked.remove(ip)
        save_blocked(blocked)
        flash(f"IP débloquée : {ip}", "success")
    else:
        flash("Cette IP n'est pas dans la liste.", "warning")

    return redirect(url_for("admin.admin_blocked_ips"))


@admin_bp.route("/admin/login", methods=["GET", "POST"], endpoint="admin_login")
def admin_login():
    if request.method == "POST":
        validate_csrf()
        ok, status = process_admin_login(
            username=(request.form.get("username") or "").strip(),
            password=(request.form.get("password") or ""),
        )
        if ok:
            return redirect(url_for("admin.admin_panel"))
        if status == 429:
            flash("Trop d’essais. Réessaie plus tard.", "danger")
            return render_template("admin_login.html", version=current_app.config["APP_VERSION"]), 429
        flash("Identifiants invalides.", "warning")
        return render_template("admin_login.html", version=current_app.config["APP_VERSION"]), 401

    return render_template("admin_login.html", version=current_app.config["APP_VERSION"])


@admin_bp.route("/admin/logout", methods=["POST"], endpoint="admin_logout")
def admin_logout():
    validate_csrf()
    session.pop("is_admin", None)
    flash("Déconnecté.", "success")
    return redirect(url_for("public.index"))


@admin_bp.route("/admin", methods=["GET"], endpoint="admin_panel")
@admin_required
def admin_panel():
    cleanup_expired()

    files = list_all_files()

    for f in files:
        f["remaining_time"] = get_remaining_time_label(f.get("expires_at")) if f.get("status") == "active" else ""

    return render_template(
        "admin.html",
        files=files,
        version=current_app.config["APP_VERSION"]
    )


@admin_bp.route("/admin/thumb/<file_id>", methods=["GET"], endpoint="admin_thumbnail")
@admin_required
def admin_thumbnail(file_id):
    cleanup_expired()
    abs_path = get_thumbnail_abs_path(file_id)
    if not os.path.isfile(abs_path):
        abort(404)
    return send_file(abs_path, mimetype="image/jpeg", conditional=True, max_age=0)


@admin_bp.route("/admin/settings", methods=["GET", "POST"], endpoint="admin_settings")
@admin_required
def admin_settings():
    settings = load_settings()

    if request.method == "POST":
        validate_csrf()

        try:
            max_upload_size_mb = int(request.form.get("max_upload_size_mb", settings.get("max_upload_size_mb", 100)))
        except (TypeError, ValueError):
            flash("Taille maximale invalide.", "warning")
            return redirect(url_for("admin.admin_settings"))

        allow_permanent_files = request.form.get("allow_permanent_files") == "1"

        try:
            default_lifetime_minutes = int(request.form.get("default_lifetime_minutes", settings.get("default_lifetime_minutes", 10)))
        except (TypeError, ValueError):
            flash("Temps d'expiration par défaut invalide.", "warning")
            return redirect(url_for("admin.admin_settings"))

        try:
            thumbnail_retention_hours = int(request.form.get("thumbnail_retention_hours", settings.get("thumbnail_retention_hours", 24)))
        except (TypeError, ValueError):
            flash("Durée de conservation des miniatures invalide.", "warning")
            return redirect(url_for("admin.admin_settings"))

        if get_valid_lifetime(default_lifetime_minutes) != default_lifetime_minutes:
            flash("Temps d'expiration par défaut invalide.", "warning")
            return redirect(url_for("admin.admin_settings"))

        if get_valid_thumbnail_retention_hours(thumbnail_retention_hours) != thumbnail_retention_hours:
            flash("Durée des miniatures invalide.", "warning")
            return redirect(url_for("admin.admin_settings"))

        settings = save_settings({
            "max_upload_size_mb": max_upload_size_mb,
            "allow_permanent_files": allow_permanent_files,
            "default_lifetime_minutes": default_lifetime_minutes,
            "thumbnail_retention_hours": thumbnail_retention_hours,
        })
        flash("Paramètres enregistrés ✅", "success")
        return redirect(url_for("admin.admin_settings"))

    return render_template(
        "admin_settings.html",
        settings=settings,
        version=current_app.config["APP_VERSION"],
    )


@admin_bp.route("/admin/delete", methods=["POST"], endpoint="admin_delete")
@admin_required
def admin_delete():
    validate_csrf()
    file_id = (request.form.get("file_id") or "").strip()
    if not file_id:
        flash("ID manquant.", "warning")
        return redirect(url_for("admin.admin_panel"))

    ok = delete_by_id(file_id, reason="admin_delete")
    flash("Fichier supprimé ✅" if ok else "Fichier introuvable.", "success" if ok else "warning")
    return redirect(url_for("admin.admin_panel"))


@admin_bp.route("/admin/block", methods=["POST"], endpoint="admin_block_ip")
@admin_required
def admin_block_ip():
    validate_csrf()
    ip = (request.form.get("ip") or "").strip()
    if not ip:
        flash("IP manquante.", "warning")
        return redirect(url_for("admin.admin_panel"))

    blocked = load_blocked()
    if ip not in blocked:
        blocked.append(ip)
        save_blocked(blocked)
        flash(f"IP bloquée ✅ : {ip}", "success")
    else:
        flash(f"IP déjà bloquée : {ip}", "info")
    return redirect(url_for("admin.admin_panel"))
