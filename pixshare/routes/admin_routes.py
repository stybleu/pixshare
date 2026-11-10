import ipaddress
import os
from datetime import timedelta

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, send_file, session, url_for

from pixshare.security.csrf import validate_csrf
from pixshare.services.auth_service import admin_required, process_admin_login
from pixshare.services.file_service import (
    cleanup_expired,
    delete_all_thumbnails,
    delete_by_id,
    delete_thumbnail_by_id,
    get_thumbnail_abs_path,
    list_all_files,
    list_all_thumbnails,
)
from pixshare.services.json_services import (
    load_blocked,
    load_contacts,
    load_db,
    save_blocked,
    save_contacts,
    save_db,
)
from pixshare.services.moderation_service import approve_image, create_moderation_notice
from pixshare.services.nsfw_service import (
    effective_settings as nsfw_effective_settings,
    is_manual_review,
    nudenet_installed,
    queue_status as nsfw_queue_status,
    release_waiting_images,
    run_after_response as nsfw_run_after_response,
)
from pixshare.services.settings_service import (
    get_valid_lifetime,
    NSFW_CLASS_GROUPS,
    get_valid_nsfw_classes,
    get_valid_nsfw_threshold,
    get_valid_thumbnail_retention_hours,
    load_settings,
    save_settings,
)
from pixshare.services.request_service import ip_source
from pixshare.services.system_service import get_system_stats
from pixshare.services.theme_service import THEME_CHOICES, THEMES, active_theme, clean_choice, sky_enabled
from pixshare.services.time_service import get_remaining_time_label, format_duration_minutes, utcnow

admin_bp = Blueprint("admin", __name__)

ADMIN_EXPIRATION_OPTIONS = [
    (5, "5 minutes"),
    (10, "10 minutes"),
    (20, "20 minutes"),
    (30, "30 minutes"),
    (60, "1 heure"),
    (120, "2 heures"),
    (360, "6 heures"),
    (720, "12 heures"),
    (1440, "1 jour"),
    (2880, "2 jours"),
    (4320, "3 jours"),
    (10080, "7 jours"),
]



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
        version=current_app.config["APP_VERSION"],
    )


@admin_bp.route("/admin/messages/delete", methods=["POST"])
@admin_required
def admin_delete_message():
    validate_csrf()

    message_id = (request.form.get("id") or "").strip()

    if not message_id:
        flash("ID manquant.", "warning")
        return redirect(url_for("admin.admin_messages"))

    items = load_contacts()
    new_items = []
    deleted = False

    for item in items:
        if item.get("id") == message_id and not deleted:
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
        version=current_app.config["APP_VERSION"],
    )


@admin_bp.route("/admin/blocked-ips/add", methods=["POST"], endpoint="admin_add_blocked_ip")
@admin_required
def admin_add_blocked_ip():
    """Blocage manuel d'une IP saisie à la main (formulaire de l'onglet « IP bloquées »)."""
    validate_csrf()
    raw = (request.form.get("ip") or "").strip()
    try:
        ip = str(ipaddress.ip_address(raw))
    except ValueError:
        flash("IP invalide. Exemples : 82.64.12.34 ou 2001:db8::1", "warning")
        return redirect(url_for("admin.admin_blocked_ips"))

    blocked = load_blocked()
    if ip in blocked:
        flash(f"IP déjà bloquée : {ip}", "info")
    else:
        blocked.append(ip)
        save_blocked(blocked)
        flash(f"IP bloquée ✅ : {ip}", "success")
    return redirect(url_for("admin.admin_blocked_ips"))


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
        if status == 503:
            flash("Connexion admin désactivée : définis les variables d'environnement ADMIN_USER et ADMIN_PASS.", "danger")
            return render_template("admin_login.html", version=current_app.config["APP_VERSION"]), 503
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
    files = list_all_files(include_thumbnails=False)

    for f in files:
        if f.get("status") == "active":
            label = get_remaining_time_label(f.get("expires_at"))
            f["remaining_time"] = label
            f["remaining_h"] = label
        else:
            f["remaining_time"] = ""
            f["remaining_h"] = ""

    return render_template(
        "admin.html",
        files=files,
        review_count=sum(1 for f in files if f.get("status") == "pending" and f.get("moderation_decision") == "manual_review"),
        expiration_options=ADMIN_EXPIRATION_OPTIONS,
        version=current_app.config["APP_VERSION"],
    )


@admin_bp.route("/admin/file/expiration", methods=["POST"], endpoint="admin_set_expiration")
@admin_required
def admin_set_expiration():
    validate_csrf()

    file_id = (request.form.get("file_id") or "").strip()
    expiration_value = (request.form.get("expiration") or "").strip().lower()

    if not file_id:
        flash("ID fichier manquant.", "warning")
        return redirect(url_for("admin.admin_panel"))

    db = load_db()
    meta = db.get(file_id)
    if not meta:
        flash("Fichier introuvable.", "warning")
        return redirect(url_for("admin.admin_panel"))

    if (meta.get("status") or "active").lower() != "active":
        flash("Impossible de modifier l’expiration d’un fichier déjà supprimé ou expiré.", "warning")
        return redirect(url_for("admin.admin_panel"))

    if expiration_value in {"permanent", "none", "keep"}:
        meta["permanent"] = True
        meta["expires_at"] = ""
        db[file_id] = meta
        save_db(db)
        flash("Expiration mise à jour : fichier permanent ✅", "success")
        return redirect(url_for("admin.admin_panel"))

    try:
        minutes = int(expiration_value)
    except (TypeError, ValueError):
        flash("Valeur d’expiration invalide.", "warning")
        return redirect(url_for("admin.admin_panel"))

    if minutes < 1 or minutes > int(current_app.config.get("MAX_LIFETIME_MIN", 10080)):
        flash("Valeur d’expiration hors limite.", "warning")
        return redirect(url_for("admin.admin_panel"))

    expires_at = utcnow() + timedelta(minutes=minutes)
    meta["permanent"] = False
    meta["expires_at"] = expires_at.isoformat(timespec="seconds")
    db[file_id] = meta
    save_db(db)
    flash(f"Expiration mise à jour : {format_duration_minutes(minutes)} à partir de maintenant ✅", "success")
    return redirect(url_for("admin.admin_panel"))


@admin_bp.route("/admin/thumb/<file_id>", methods=["GET"], endpoint="admin_thumbnail")
@admin_required
def admin_thumbnail(file_id):
    cleanup_expired()
    abs_path = get_thumbnail_abs_path(file_id)
    if not os.path.isfile(abs_path):
        abort(404)
    return send_file(abs_path, mimetype="image/jpeg", conditional=True, max_age=0)


@admin_bp.route("/admin/thumbnails", methods=["GET"], endpoint="admin_thumbnails")
@admin_required
def admin_thumbnails():
    cleanup_expired()

    thumbnails = list_all_thumbnails()
    for item in thumbnails:
        if item.get("status") == "active":
            label = get_remaining_time_label(item.get("expires_at"))
            item["remaining_time"] = label
            item["remaining_h"] = label
        else:
            item["remaining_time"] = ""
            item["remaining_h"] = ""

    return render_template(
        "admin_thumbnails.html",
        thumbnails=thumbnails,
        version=current_app.config["APP_VERSION"],
    )


@admin_bp.route("/admin/thumbnails/delete", methods=["POST"], endpoint="admin_delete_thumbnail")
@admin_required
def admin_delete_thumbnail():
    validate_csrf()
    file_id = (request.form.get("file_id") or "").strip()
    if not file_id:
        flash("ID miniature manquant.", "warning")
        return redirect(url_for("admin.admin_thumbnails"))

    ok = delete_thumbnail_by_id(file_id)
    flash("Miniature supprimée ✅" if ok else "Miniature introuvable.", "success" if ok else "warning")
    return redirect(url_for("admin.admin_thumbnails"))


@admin_bp.route("/admin/thumbnails/block-ip", methods=["POST"])
@admin_required
def admin_block_thumbnail_ip():
    validate_csrf()

    ip = (request.form.get("ip") or "").strip()

    if not ip:
        flash("Aucune IP à bloquer.", "warning")
        return redirect(url_for("admin.admin_thumbnails"))

    blocked = load_blocked()
    if ip not in blocked:
        blocked.append(ip)
        save_blocked(blocked)
        flash(f"IP {ip} bloquée avec succès.", "success")
    else:
        flash(f"IP {ip} est déjà bloquée.", "info")

    return redirect(url_for("admin.admin_thumbnails"))


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

        upload_service_enabled_value = request.form.get("upload_service_enabled") == "1"
        allow_permanent_files = request.form.get("allow_permanent_files") == "1"

        try:
            default_lifetime_minutes = int(request.form.get("default_lifetime_minutes", settings.get("default_lifetime_minutes", 10)))
        except (TypeError, ValueError):
            flash("Temps d'expiration par défaut invalide.", "warning")
            return redirect(url_for("admin.admin_settings"))

        keep_thumbnails = request.form.get("keep_thumbnails") == "1"

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

        previous_keep_thumbnails = bool(settings.get("keep_thumbnails", True))

        settings = save_settings({
            "upload_service_enabled": upload_service_enabled_value,
            "max_upload_size_mb": max_upload_size_mb,
            "allow_permanent_files": allow_permanent_files,
            "default_lifetime_minutes": default_lifetime_minutes,
            "thumbnail_retention_hours": thumbnail_retention_hours,
            "keep_thumbnails": keep_thumbnails,
        })

        if previous_keep_thumbnails and not keep_thumbnails:
            deleted_count = delete_all_thumbnails()
            flash(f"Miniatures désactivées et {deleted_count} miniature(s) supprimée(s) ✅", "success")
        else:
            flash("Paramètres enregistrés ✅", "success")
        return redirect(url_for("admin.admin_settings"))

    return render_template(
        "admin_settings.html",
        settings=settings,
        nsfw=_nsfw_context(),
        theme_choices=THEME_CHOICES,
        theme_saved=settings.get("season_theme") or "",
        theme_now=active_theme(settings.get("season_theme")),
        theme_names={k: v[0] for k, v in THEMES.items()},
        sky_on_setting=sky_enabled(settings.get("sky_enabled")),
        version=current_app.config["APP_VERSION"],
    )


def _nsfw_context() -> dict:
    values = nsfw_effective_settings()
    values.update(nsfw_queue_status())
    values["installed"] = nudenet_installed()
    values["class_groups"] = NSFW_CLASS_GROUPS
    return values


@admin_bp.route("/admin/settings/theme", methods=["POST"], endpoint="admin_theme_settings")
@admin_required
def admin_theme_settings():
    validate_csrf()
    choice = clean_choice(request.form.get("season_theme")) or "auto"
    current = load_settings()
    current["season_theme"] = choice
    current["sky_enabled"] = request.form.get("sky_enabled") == "1"
    save_settings(current)
    flash("Thème enregistré ✅ (il revient au réglage de Render au prochain déploiement)", "success")
    return redirect(url_for("admin.admin_settings") + "#theme")


@admin_bp.route("/admin/settings/nsfw", methods=["POST"], endpoint="admin_nsfw_settings")
@admin_required
def admin_nsfw_settings():
    validate_csrf()

    review = get_valid_nsfw_threshold(request.form.get("nsfw_review_threshold"))
    block = get_valid_nsfw_threshold(request.form.get("nsfw_block_threshold"))
    if review is None or block is None:
        flash("Seuils invalides : entre 0,05 et 1 (exemple : 0,60 et 0,85).", "warning")
        return redirect(url_for("admin.admin_settings"))
    if review > block:
        flash("Le seuil de revue ne peut pas dépasser le seuil de suppression.", "warning")
        return redirect(url_for("admin.admin_settings"))

    current = load_settings()
    classes = None
    if request.form.get("nsfw_classes_present") == "1":
        classes = get_valid_nsfw_classes(request.form.getlist("nsfw_classes"))
        if classes is None:
            flash("Coche au moins une partie du corps à surveiller.", "warning")
            return redirect(url_for("admin.admin_settings"))

    current.update({
        "nsfw_auto_moderation": request.form.get("nsfw_auto_moderation") == "1",
        "nsfw_review_threshold": review,
        "nsfw_block_threshold": block,
        "nsfw_tiling": request.form.get("nsfw_tiling") == "1",
    })
    if classes is not None:
        current["nsfw_classes"] = classes
    save_settings(current)
    flash("Réglages NudeNet enregistrés ✅", "success")
    if not nsfw_effective_settings()["enabled"]:
        released = release_waiting_images()
        if released:
            flash(f"NudeNet coupé : {released} image(s) en attente publiée(s). Les nouvelles images ne sont plus bloquées.", "info")
    return redirect(url_for("admin.admin_settings"))


@admin_bp.route("/admin/moderation/run", methods=["POST"], endpoint="admin_nsfw_run")
@admin_required
def admin_nsfw_run():
    """Lance l'analyse des images en attente après l'envoi de la réponse (évite le délai d'expiration du navigateur)."""
    validate_csrf()
    status = nsfw_queue_status()
    if not nsfw_effective_settings()["enabled"]:
        flash("La modération automatique est désactivée.", "warning")
    elif not status["waiting"]:
        flash("Aucune image en attente d'analyse.", "info")
    else:
        flash(f"Analyse lancée pour {min(status['waiting'], 10)} image(s) : recharge la page dans quelques secondes.", "success")
    response = redirect(url_for("admin.admin_settings"))
    if status["waiting"] and nsfw_effective_settings()["enabled"]:
        app = current_app._get_current_object()
        response.call_on_close(lambda: nsfw_run_after_response(app))
    return response


@admin_bp.route("/admin/review/<file_id>", methods=["GET"], endpoint="admin_review_preview")
@admin_required
def admin_review_preview(file_id):
    """Aperçu réservé à l'admin d'une image encore privée (en attente ou en revue manuelle)."""
    meta = load_db().get(file_id)
    if not isinstance(meta, dict) or (meta.get("status") or "").lower() != "pending":
        abort(404)
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], os.path.basename(str(meta.get("server_name") or "")))
    if not os.path.isfile(path):
        abort(404)
    response = send_file(path, conditional=True, max_age=0)
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@admin_bp.route("/admin/review/approve", methods=["POST"], endpoint="admin_review_approve")
@admin_required
def admin_review_approve():
    validate_csrf()
    file_id = (request.form.get("file_id") or "").strip()
    db = load_db()
    meta = db.get(file_id)
    if not is_manual_review(meta):
        flash("Cette image n'est plus en revue manuelle.", "warning")
        return redirect(url_for("admin.admin_panel"))
    approve_image(db, file_id, meta, "admin", meta.get("moderation_score"))
    flash("Image approuvée et publiée ✅", "success")
    return redirect(url_for("admin.admin_panel"))


@admin_bp.route("/admin/delete", methods=["POST"], endpoint="admin_delete")
@admin_required
def admin_delete():
    validate_csrf()
    file_id = (request.form.get("file_id") or "").strip()
    if not file_id:
        flash("ID manquant.", "warning")
        return redirect(url_for("admin.admin_panel"))

    reason = (request.form.get("delete_reason") or "admin_delete").strip()
    notify_uploader = request.form.get("notify_uploader") == "1"

    db = load_db()
    meta = db.get(file_id)
    if not meta:
        flash("Fichier introuvable.", "warning")
        return redirect(url_for("admin.admin_panel"))

    ok = delete_by_id(file_id, reason=reason)
    notice_created = False
    if ok and notify_uploader:
        notice_created = create_moderation_notice(meta, file_id=file_id, reason=reason)

    if ok:
        if notice_created:
            flash("Fichier supprimé et message de modération préparé ✅", "success")
        else:
            flash("Fichier supprimé ✅", "success")
    else:
        flash("Fichier introuvable.", "warning")
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



@admin_bp.route("/admin/system", methods=["GET"], endpoint="admin_system")
@admin_required
def admin_system():
    stats = get_system_stats()
    ip, ip_from = ip_source()
    ip_check = {
        "ip": ip,
        "source": ip_from,
        "xff": request.headers.get("X-Forwarded-For", ""),
        "cf": request.headers.get("CF-Connecting-IP", ""),
        "remote": request.remote_addr or "",
    }

    return render_template(
        "admin_system.html",
        stats=stats,
        ip_check=ip_check,
        version=current_app.config["APP_VERSION"],
    )