import ipaddress
import os
from datetime import timedelta

from flask import Blueprint, abort, current_app, flash, jsonify, make_response, redirect, render_template, request, send_file, session, url_for

from pixshare.security.csrf import validate_csrf
from pixshare.services.auth_service import admin_required, is_admin, process_admin_login
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
    BLOCK_DURATIONS,
    DEFAULT_BLOCK_HOURS,
    block_ip,
    block_remaining_label,
    load_blocked,
    set_block_duration,
    load_blocked_info,
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
    LIFETIME_CHOICES,
    clean_support_url,
    get_support_url,
    MAX_LIFETIME_CHOICES,
    get_max_lifetime,
    get_valid_lifetime,
    get_valid_max_lifetime,
    NSFW_CLASS_GROUPS,
    get_valid_nsfw_classes,
    get_valid_nsfw_threshold,
    get_valid_thumbnail_retention_hours,
    export_matches_env,
    export_settings,
    load_settings,
    save_settings,
)
from pixshare.services.abuse_service import auto_block_settings
from pixshare.services.image_ban_service import list_banned, unban
from pixshare.services.settings_service import nsfw_class_label
from pixshare.services.nsfw_stats_service import bump as bump_stat, load_stats as load_nsfw_stats, reset_stats as reset_nsfw_stats
from pixshare.services.mail_service import mail_configured, send_mail_now
from pixshare.services.request_service import ip_source
from pixshare.services.system_service import get_system_stats
from pixshare.services.theme_service import THEME_CHOICES, THEMES, active_theme, clean_choice, sky_enabled
from pixshare.services.time_service import get_remaining_time_label, format_duration_minutes, utcnow

admin_bp = Blueprint("admin", __name__)


@admin_bp.before_request
def _admin_is_here():
    """Toute page admin ouverte = admin présent : c'est lui qui décide, pas le filtre."""
    if not is_admin():
        return
    try:
        from pixshare.services.admin_presence_service import touch
        deleted = touch() + int(session.pop("absent_deleted", 0) or 0)
        if deleted and request.endpoint != "admin.admin_presence_ping":
            flash(f"Pendant ton absence, le filtre a supprimé {deleted} image(s) douteuse(s). "
                  "Elles sont marquées « par le filtre (admin absent) » dans les fichiers.", "info")
        elif deleted:
            session["absent_deleted"] = deleted
    except Exception:
        current_app.logger.exception("Présence admin non enregistrée")


@admin_bp.route("/admin/presence", methods=["GET"], endpoint="admin_presence_ping")
@admin_required
def admin_presence_ping():
    response = make_response("", 204)
    response.headers["Cache-Control"] = "no-store"
    return response


@admin_bp.context_processor
def _block_duration_choices():
    return {"block_durations": BLOCK_DURATIONS, "default_block_hours": DEFAULT_BLOCK_HOURS, "nsfw_label": nsfw_class_label}


def _form_block_hours() -> float | None:
    """Durée choisie dans un formulaire (heures), None = définitif. Valeur inconnue -> 24 h."""
    allowed = {float(h) for h, _label in BLOCK_DURATIONS}
    try:
        hours = float(request.form.get("hours", DEFAULT_BLOCK_HOURS))
    except (TypeError, ValueError):
        hours = float(DEFAULT_BLOCK_HOURS)
    if hours not in allowed:
        hours = float(DEFAULT_BLOCK_HOURS)
    return hours or None

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
    (20160, "14 jours"),
    (43200, "30 jours"),
    (129600, "90 jours"),
    (525600, "1 an"),
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
        blocked_ips=set(load_blocked()),
        version=current_app.config["APP_VERSION"],
    )


@admin_bp.route("/admin/messages/block-ip", methods=["POST"], endpoint="admin_block_message_ip")
@admin_required
def admin_block_message_ip():
    """Bloque l'IP de l'expéditeur d'un message de contact."""
    validate_csrf()
    try:
        ip = str(ipaddress.ip_address((request.form.get("ip") or "").strip()))
    except ValueError:
        flash("IP invalide.", "warning")
        return redirect(url_for("admin.admin_messages"))

    if ip == ip_source()[0]:
        flash("Tu ne peux pas bloquer ta propre IP.", "warning")
        return redirect(url_for("admin.admin_messages"))

    if block_ip(ip, "Message de contact", _form_block_hours()):
        flash(f"IP bloquée ✅ : {ip}", "success")
    else:
        flash(f"IP déjà bloquée : {ip}", "info")
    return redirect(url_for("admin.admin_messages"))


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
        blocked_info=load_blocked_info(),
        banned_images=list_banned(),
        block_remaining={ip: block_remaining_label(entry) for ip, entry in load_blocked_info().items()},
        auto_block=auto_block_settings(),
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

    reason = (request.form.get("reason") or "").strip() or "Manuel"
    if block_ip(ip, reason, _form_block_hours()):
        flash(f"IP bloquée ✅ : {ip}", "success")
    else:
        flash(f"IP déjà bloquée : {ip}", "info")
    return redirect(url_for("admin.admin_blocked_ips"))


@admin_bp.route("/admin/blocked-ips/clear", methods=["POST"])
@admin_required
def admin_clear_blocked_ips():
    validate_csrf()
    save_blocked([])
    flash("La liste des IP bloquées a été vidée.", "success")
    return redirect(url_for("admin.admin_blocked_ips"))


@admin_bp.route("/admin/blocked-ips/duration", methods=["POST"], endpoint="admin_block_duration")
@admin_required
def admin_block_duration():
    """Change la durée d'un blocage déjà en place (comptée à partir de maintenant)."""
    validate_csrf()
    ip = (request.form.get("ip") or "").strip()
    hours = _form_block_hours()
    if set_block_duration(ip, hours):
        label = next((lbl for h, lbl in BLOCK_DURATIONS if float(h) == float(hours or 0)), "")
        flash(f"Blocage de {ip} : {label.lower()}{'' if not hours else ' à partir de maintenant'} ✅", "success")
    else:
        flash("Cette IP n'est pas dans la liste.", "warning")
    return redirect(url_for("admin.admin_blocked_ips"))


@admin_bp.route("/admin/banned-images/remove", methods=["POST"], endpoint="admin_unban_image")
@admin_required
def admin_unban_image():
    """Retire une image de la liste des images interdites (elle repassera par NudeNet)."""
    validate_csrf()
    if unban((request.form.get("sha256") or "").strip()):
        flash("Image retirée de la liste des images interdites.", "success")
    else:
        flash("Image introuvable dans la liste.", "warning")
    return redirect(url_for("admin.admin_blocked_ips") + "#images-interdites")


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
    try:  # le filtre reprend la main tout de suite
        from pixshare.services.admin_presence_service import logged_out
        logged_out()
    except Exception:
        current_app.logger.exception("Présence admin non enregistrée")
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

    try:
        minutes = int(expiration_value)
    except (TypeError, ValueError):
        flash("Valeur d’expiration invalide.", "warning")
        return redirect(url_for("admin.admin_panel"))

    if minutes < 1 or minutes > 525600:
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

    if block_ip(ip, "Depuis les miniatures", _form_block_hours()):
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

        max_lifetime_minutes = get_valid_max_lifetime(request.form.get("max_lifetime_minutes"))
        if request.form.get("max_lifetime_minutes") and max_lifetime_minutes is None:
            flash("Durée maximale invalide.", "warning")
            return redirect(url_for("admin.admin_settings"))
        if max_lifetime_minutes and default_lifetime_minutes > max_lifetime_minutes:
            flash("Le temps d'expiration par défaut ne peut pas dépasser la durée maximale.", "warning")
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

        previous_keep_thumbnails = bool(settings.get("keep_thumbnails", True))

        settings = save_settings({
            "upload_service_enabled": upload_service_enabled_value,
            "max_upload_size_mb": max_upload_size_mb,
            "allow_permanent_files": allow_permanent_files,
            "default_lifetime_minutes": default_lifetime_minutes,
            "max_lifetime_minutes": max_lifetime_minutes,
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
        approved_count=_approved_count(),
        settings=settings,
        lifetime_choices=LIFETIME_CHOICES,
        max_lifetime_choices=[c for c in LIFETIME_CHOICES if c[0] in MAX_LIFETIME_CHOICES],
        max_lifetime_now=get_max_lifetime(),
        support_saved=settings.get("support_url") or "",
        support_now=get_support_url(),
        mail_ready=mail_configured(),
        mail_alert=_mail_alert_status(),
        settings_export=export_settings(),
        settings_export_saved=export_matches_env(),
        nsfw=_nsfw_context(),
        theme_choices=THEME_CHOICES,
        theme_saved=settings.get("season_theme") or "",
        theme_now=active_theme(settings.get("season_theme")),
        theme_names={k: v[0] for k, v in THEMES.items()},
        sky_on_setting=sky_enabled(settings.get("sky_enabled")),
        version=current_app.config["APP_VERSION"],
    )


def _db_status() -> dict:
    try:
        from pixshare.services import sqlite_store
        from pixshare.services.json_services import _get_data_dir, use_sqlite
        if not use_sqlite():
            return {"enabled": False}
        info = sqlite_store.status(_get_data_dir())
        info["enabled"] = True
        info["size_mb"] = round(info["size"] / 1024 / 1024, 2)
        return info
    except Exception as exc:
        return {"enabled": True, "ok": False, "check": str(exc)}


def _env_check() -> dict:
    try:
        from pixshare.services.env_check_service import check
        return check()
    except Exception:
        return {"groups": [], "problems": [("warning", "Vérification des variables impossible.")]}


def _mail_alert_status() -> dict:
    try:
        from pixshare.services.mail_service import alert_status
        return alert_status()
    except Exception:
        return {}


def _nsfw_context() -> dict:
    values = nsfw_effective_settings()
    values.update(nsfw_queue_status())
    values["installed"] = nudenet_installed()
    values["class_groups"] = NSFW_CLASS_GROUPS
    values["stats"] = load_nsfw_stats()
    return values


@admin_bp.route("/admin/moderation/stats/reset", methods=["POST"], endpoint="admin_nsfw_stats_reset")
@admin_required
def admin_nsfw_stats_reset():
    validate_csrf()
    reset_nsfw_stats()
    flash("Statistiques NudeNet remises à zéro.", "success")
    return redirect(url_for("admin.admin_settings") + "#nudenet")


@admin_bp.route("/admin/settings/support", methods=["POST"], endpoint="admin_support_settings")
@admin_required
def admin_support_settings():
    validate_csrf()
    raw = (request.form.get("support_url") or "").strip()
    url = clean_support_url(raw)
    if raw and not url:
        flash("Lien invalide : colle une adresse complète qui commence par https://", "warning")
        return redirect(url_for("admin.admin_settings") + "#soutien")
    current = load_settings()
    current["support_url"] = url
    save_settings(current)
    flash("Bouton « Soutenir » enregistré ✅" if url else "Bouton « Soutenir » retiré.", "success")
    return redirect(url_for("admin.admin_settings") + "#soutien")


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


@admin_bp.route("/admin/settings/absent", methods=["POST"], endpoint="admin_absent_settings")
@admin_required
def admin_absent_settings():
    validate_csrf()
    current = load_settings()
    current.update({
        "admin_absent_mode": request.form.get("admin_absent_mode") == "1",
        "admin_absent_after_minutes": request.form.get("admin_absent_after_minutes"),
        "admin_absent_members": request.form.get("admin_absent_members") == "1",
    })
    saved = save_settings(current)
    if saved["admin_absent_mode"]:
        flash(f"Mode absent activé ✅ : {saved['admin_absent_after_minutes']} min après ta dernière activité "
              "(ou dès la déconnexion), le filtre supprime seul les images douteuses.", "success")
    else:
        flash("Mode absent coupé : les images douteuses attendent toujours ta décision.", "success")
    return redirect(url_for("admin.admin_settings") + "#absent")


@admin_bp.route("/admin/mail-test", methods=["POST"], endpoint="admin_mail_test")
@admin_required
def admin_mail_test():
    """Envoie un mail de test pour vérifier la configuration SMTP."""
    validate_csrf()
    ok, detail = send_mail_now("PixShare : mail de test", "Si tu lis ce message, les alertes par mail fonctionnent ✅\n")
    flash("Mail de test envoyé ✅" if ok else f"Échec de l'envoi : {detail}", "success" if ok else "warning")
    return redirect(url_for("admin.admin_settings") + "#mail")


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


@admin_bp.route("/moderation/<token>", methods=["GET", "POST"], endpoint="mail_review")
def mail_review(token):
    """Page de décision ouverte depuis le mail d'alerte (sans connexion : le lien signé suffit)."""
    from pixshare.services import review_link_service as rl

    file_id, error = rl.read_token(token)
    meta = rl.waiting_meta(file_id) if file_id else None
    outcome = ""
    if request.method == "POST" and file_id and not error:
        validate_csrf()
        action = request.form.get("action")
        hours = None
        if action == "delete" and request.form.get("block") == "1":
            hours = _form_block_hours() or 0  # 0 = définitif
        outcome = rl.decide(file_id, action, notify=request.form.get("notify") == "1", block_hours=hours)
        meta = None
    response = make_response(render_template(
        "mail_review.html", token=token, error=error, meta=meta, outcome=outcome,
        preselect=request.args.get("a", ""), label=nsfw_class_label((meta or {}).get("moderation_label")),
        version=current_app.config["APP_VERSION"],
    ))
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    return response


@admin_bp.route("/moderation/<token>/image", methods=["GET"], endpoint="mail_review_image")
def mail_review_image(token):
    from pixshare.services import review_link_service as rl

    file_id, error = rl.read_token(token)
    meta = rl.waiting_meta(file_id) if file_id and not error else None
    if not meta or not os.path.isfile(rl.image_path(meta)):
        abort(404)
    response = send_file(rl.image_path(meta), conditional=True, max_age=0)
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Robots-Tag"] = "noindex, noimageindex"
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
    label = meta.get("moderation_label")
    if label == "signalement":
        meta["reports"] = []  # image jugée correcte : il faudra de nouveaux signalements pour la masquer
        meta["report_reasons"] = {}
    approve_image(db, file_id, meta, "admin", meta.get("moderation_score"))
    if label not in ("analyse_impossible", "signalement"):
        bump_stat("review_approved")  # fausse alerte de NudeNet
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

    was_in_review = is_manual_review(meta) and meta.get("moderation_label") not in ("analyse_impossible", "signalement")
    ok = delete_by_id(file_id, reason=reason)
    if ok and was_in_review:
        bump_stat("review_deleted")  # alerte justifiée de NudeNet
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

    if block_ip(ip, "Depuis les fichiers", _form_block_hours()):
        flash(f"IP bloquée ✅ : {ip}", "success")
    else:
        flash(f"IP déjà bloquée : {ip}", "info")
    return redirect(url_for("admin.admin_panel"))



@admin_bp.route("/admin/live", methods=["GET"], endpoint="admin_live")
@admin_required
def admin_live():
    return render_template("admin_live.html", version=current_app.config["APP_VERSION"])


@admin_bp.route("/admin/live.json", methods=["GET"], endpoint="admin_live_data")
@admin_required
def admin_live_data():
    from pixshare.services.live_service import snapshot
    rows = snapshot()
    blocked = set(load_blocked())
    for row in rows:
        row["blocked"] = row.get("ip") in blocked
    response = jsonify({"visitors": rows, "count": len(rows)})
    response.headers["Cache-Control"] = "no-store"
    return response


@admin_bp.route("/admin/stats", methods=["GET"], endpoint="admin_stats")
@admin_required
def admin_stats():
    from pixshare.services.visitor_stats_service import summary
    return render_template("admin_stats.html", st=summary(30), version=current_app.config["APP_VERSION"])


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

    from pixshare.services.system_service import get_disk_contents

    return render_template(
        "admin_system.html",
        stats=stats,
        disk=get_disk_contents(),
        env_check=_env_check(),
        db_status=_db_status(),
        ip_check=ip_check,
        version=current_app.config["APP_VERSION"],
    )

@admin_bp.route("/admin/disque", methods=["GET"], endpoint="admin_disk")
@admin_required
def admin_disk():
    """Explorateur du disque persistant (lecture seule)."""
    from pixshare.services.system_service import get_storage_usage, list_disk_dir

    try:
        page = int(request.args.get("page") or 1)
    except ValueError:
        page = 1
    listing = list_disk_dir(request.args.get("chemin", ""), request.args.get("tri", "nom"), page)
    if listing is None:
        abort(404)
    return render_template("admin_disk.html", d=listing, storage=get_storage_usage(),
                           version=current_app.config["APP_VERSION"])


@admin_bp.route("/admin/disque/ouvrir", methods=["GET"], endpoint="admin_disk_open")
@admin_required
def admin_disk_open():
    """Ouvre un fichier du disque : images et vidéos affichées, textes (JSON…) en texte brut, le reste téléchargé."""
    import mimetypes

    from pixshare.services.system_service import resolve_disk_path

    path = resolve_disk_path(request.args.get("chemin", ""))
    if not path or not os.path.isfile(path):
        abort(404)
    if os.path.basename(path).startswith("pixshare.db"):
        # Fichier brut de la base en cours d'utilisation : copie incohérente. On passe par la sauvegarde.
        return redirect(url_for("admin.admin_db_backup"))
    guessed = mimetypes.guess_type(path)[0] or "application/octet-stream"
    ext = os.path.splitext(path)[1].lower()
    if ext in (".json", ".txt", ".log", ".csv", ".md"):
        mimetype, inline = "text/plain; charset=utf-8", True
    elif guessed.startswith(("image/", "video/")) and ext not in (".svg", ".svgz"):
        mimetype, inline = guessed, True
    else:
        mimetype, inline = "application/octet-stream", False
    response = make_response(send_file(path, mimetype=mimetype, as_attachment=not inline,
                                       download_name=os.path.basename(path)))
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'"
    return response

# ------------------------------------------------------------------ comptes

@admin_bp.route("/admin/comptes", endpoint="admin_accounts")
@admin_required
def admin_accounts():
    from pixshare.services import account_service as accounts
    from pixshare.services.settings_service import GUEST_MAX_LIFETIME_CHOICES, MAX_LIFETIME_CHOICES, limits_table

    counts: dict = {}
    for meta in load_db().values():
        if isinstance(meta, dict) and meta.get("account_id") and (meta.get("status") or "active").lower() in ("active", "pending"):
            counts[meta["account_id"]] = counts.get(meta["account_id"], 0) + 1
    rows = [dict(rec, id=account_id, files=counts.get(account_id, 0)) for account_id, rec in accounts.all_accounts().items()]
    rows.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    return render_template(
        "admin_accounts.html",
        rows=rows,
        settings=load_settings(),
        guest_life_choices=[c for c in LIFETIME_CHOICES if c[0] in GUEST_MAX_LIFETIME_CHOICES],
        limits=limits_table(),
        mail_ready=accounts.mail_ready(),
        strikes_max=accounts.strikes_max(),
        plan_life_choices=[c for c in LIFETIME_CHOICES if c[0] in MAX_LIFETIME_CHOICES],
        plan_max_mb=accounts.PLAN_MAX_MB,
        today=utcnow().strftime("%Y-%m-%d"),
        open_plan=request.args.get("formule", ""),
    )


@admin_bp.route("/admin/comptes/reglages", methods=["POST"], endpoint="admin_accounts_settings")
@admin_required
def admin_accounts_settings():
    validate_csrf()
    current = load_settings()
    current.update({
        "accounts_enabled": request.form.get("accounts_enabled") == "1",
        "guest_max_lifetime_minutes": request.form.get("guest_max_lifetime_minutes"),
        "guest_max_upload_size_mb": request.form.get("guest_max_upload_size_mb"),
        "guest_uploads_per_hour": request.form.get("guest_uploads_per_hour"),
        "member_uploads_per_hour": request.form.get("member_uploads_per_hour"),
        "member_strikes_max": request.form.get("member_strikes_max"),
    })
    save_settings(current)
    flash("Réglages des comptes enregistrés ✅ (pense à copier la sauvegarde des réglages dans Render)", "success")
    return redirect(url_for("admin.admin_accounts"))


def _approved_count() -> int:
    try:
        from pixshare.services.approved_hash_service import count
        return count()
    except Exception:
        return 0


@admin_bp.route("/admin/nudenet/memoire", methods=["POST"], endpoint="admin_approved_clear")
@admin_required
def admin_approved_clear():
    from pixshare.services.approved_hash_service import clear
    validate_csrf()
    flash(f"Mémoire vidée : {clear()} image(s) déjà acceptée(s) seront réanalysées si elles reviennent.", "success")
    return redirect(url_for("admin.admin_settings") + "#nudenet")


@admin_bp.route("/admin/nudenet/test", methods=["GET", "POST"], endpoint="admin_nudenet_test")
@admin_required
def admin_nudenet_test():
    """Envoie une image au filtre pour voir ce qu'il détecte, sans la publier ni la garder."""
    from pixshare.services.nsfw_service import nudenet_installed, test_image

    result, error, preview = None, "", ""
    if request.method == "POST":
        validate_csrf()
        upload = request.files.get("image")
        data = upload.read(25 * 1024 * 1024 + 1) if upload and upload.filename else b""
        if not data:
            error = "Choisis une image."
        elif len(data) > 25 * 1024 * 1024:
            error = "Image trop lourde pour le test (25 Mo maximum)."
        else:
            try:
                result = test_image(data)
                import base64
                from io import BytesIO
                from PIL import Image
                with Image.open(BytesIO(data)) as im:
                    im = im.convert("RGB")
                    im.thumbnail((480, 480))
                    buf = BytesIO()
                    im.save(buf, "JPEG", quality=70)
                preview = "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()
            except Exception as exc:
                error = f"Analyse impossible : {exc}"
    return render_template("admin_nudenet_test.html", result=result, error=error, preview=preview,
                           installed=nudenet_installed(), label=nsfw_class_label)


@admin_bp.route("/admin/blocked-ips/auto", methods=["POST"], endpoint="admin_auto_block_settings")
@admin_required
def admin_auto_block_settings():
    validate_csrf()
    current = load_settings()
    if request.form.get("reset") == "1":
        current.update(auto_block_rejections=None, auto_block_hours=None)
        save_settings(current)
        flash("Blocage automatique : retour aux variables Render.", "success")
    else:
        current.update(auto_block_rejections=request.form.get("auto_block_rejections"),
                       auto_block_hours=request.form.get("auto_block_hours"))
        saved = save_settings(current)
        if saved["auto_block_rejections"] is None or saved["auto_block_hours"] is None:
            flash("Valeur refusée : entre 0 et 100 images, entre 1 et 2160 heures.", "warning")
        elif saved["auto_block_rejections"] == 0:
            flash("Blocage automatique coupé.", "success")
        else:
            flash(f"Blocage automatique : {saved['auto_block_rejections']} image(s) rejetée(s) en "
                  f"{saved['auto_block_hours']} h ✅", "success")
    return redirect(url_for("admin.admin_blocked_ips") + "#auto")


@admin_bp.route("/admin/comptes/formule", methods=["POST"], endpoint="admin_account_plan")
@admin_required
def admin_account_plan():
    from pixshare.services import account_service as accounts

    validate_csrf()
    account_id = (request.form.get("account_id") or "").strip()
    rec = accounts.get_account(account_id)
    if not rec:
        flash("Compte introuvable.", "warning")
        return redirect(url_for("admin.admin_accounts"))
    if request.form.get("do") == "clear":
        accounts.set_plan(account_id, {})
        flash(f"{rec['email']} revient aux réglages des membres.", "success")
        return redirect(url_for("admin.admin_accounts"))
    wanted = {k: request.form.get(k, "") for k in ("name", "life", "mb", "per_hour", "no_ads", "until")}
    saved = accounts.set_plan(account_id, wanted)
    plan = (saved or {}).get("plan") or {}
    ignored = [label for key, label in (("mb", "taille"), ("per_hour", "envois par heure"), ("until", "date"))
               if (wanted.get(key) or "").strip() and key not in plan]
    if ignored:
        flash("Valeur refusée, réglage des membres gardé pour : " + ", ".join(ignored) + ".", "warning")
    if not plan:
        flash(f"Aucune formule pour {rec['email']} : il garde les réglages des membres.", "info")
    elif accounts.plan_expired(plan):
        flash(f"Formule enregistrée pour {rec['email']}, mais la date de fin est déjà passée.", "warning")
    else:
        flash(f"Formule « {plan.get('name') or 'personnalisée'} » enregistrée pour {rec['email']} ✅", "success")
    return redirect(url_for("admin.admin_accounts", formule=account_id))


@admin_bp.route("/admin/comptes/action", methods=["POST"], endpoint="admin_account_action")
@admin_required
def admin_account_action():
    from pixshare.services import account_service as accounts

    validate_csrf()
    account_id = (request.form.get("account_id") or "").strip()
    action = request.form.get("action") or ""
    rec = accounts.get_account(account_id)
    if not rec:
        flash("Compte introuvable.", "warning")
    elif action == "confirm":
        accounts.confirm_account(account_id)
        flash(f"Adresse de {rec['email']} confirmée.", "success")
    elif action == "suspend":
        accounts.set_status(account_id, "suspended")
        flash(f"Compte {rec['email']} suspendu (déconnecté partout).", "success")
    elif action == "activate":
        accounts.set_status(account_id, "active")
        flash(f"Compte {rec['email']} réactivé (avertissements remis à zéro).", "success")
    elif action == "delete":
        removed = accounts.delete_account(account_id)
        flash(f"Compte {rec['email']} supprimé avec ses {removed} fichier(s).", "success")
    else:
        flash("Action inconnue.", "warning")
    return redirect(url_for("admin.admin_accounts"))


@admin_bp.route("/admin/disque/action", methods=["POST"], endpoint="admin_disk_action")
@admin_required
def admin_disk_action():
    """Supprimer, déplacer, renommer, créer un dossier. Les éléments utilisés par le site sont protégés."""
    from pixshare.services.system_service import DiskError, disk_delete, disk_mkdir, disk_move, disk_rename

    validate_csrf()
    here = request.form.get("chemin", "")
    back = redirect(url_for("admin.admin_disk", chemin=here or None))
    action = request.form.get("action", "")
    selected = [r for r in request.form.getlist("selection") if r][:500]
    try:
        if action == "mkdir":
            name = disk_mkdir(here, request.form.get("nom", ""))
            flash(f"Dossier « {name} » créé.", "success")
            return back
        if not selected:
            flash("Coche d'abord un ou plusieurs éléments.", "warning")
            return back
        if action == "delete":
            done, errors = disk_delete(selected)
            if done:
                flash(f"{done} élément(s) supprimé(s).", "success")
        elif action == "move":
            done, errors = disk_move(selected, request.form.get("destination", ""))
            if done:
                flash(f"{done} élément(s) déplacé(s).", "success")
        elif action == "rename":
            if len(selected) != 1:
                flash("Pour renommer, coche un seul élément.", "warning")
                return back
            name = disk_rename(selected[0], request.form.get("nom", ""))
            flash(f"Renommé en « {name} ».", "success")
            errors = []
        else:
            flash("Action inconnue.", "warning")
            return back
    except DiskError as exc:
        flash(str(exc), "danger")
        return back
    for err in errors[:10]:
        flash(err, "warning")
    if len(errors) > 10:
        flash(f"… et {len(errors) - 10} autre(s) refus.", "warning")
    return back


@admin_bp.route("/admin/disque/apercu", methods=["GET"], endpoint="admin_disk_thumb")
@admin_required
def admin_disk_thumb():
    """Petite miniature d'une image du disque pour l'explorateur (fabriquée une fois, gardée dans /tmp)."""
    import hashlib
    import tempfile

    from PIL import Image, ImageOps

    from pixshare.services.system_service import resolve_disk_path

    path = resolve_disk_path(request.args.get("chemin", ""))
    if not path or not os.path.isfile(path):
        abort(404)
    st = os.stat(path)
    if st.st_size > 60 * 1024 * 1024:
        abort(404)
    cache_dir = os.path.join(tempfile.gettempdir(), "pixshare_disk_thumbs")
    os.makedirs(cache_dir, exist_ok=True)
    key = hashlib.sha256(f"{path}|{st.st_mtime_ns}|{st.st_size}".encode()).hexdigest()[:32]
    cached = os.path.join(cache_dir, key + ".webp")
    if not os.path.isfile(cached):
        try:
            try:
                import pillow_heif  # photos HEIC, si disponible
                pillow_heif.register_heif_opener()
            except Exception:
                pass
            with Image.open(path) as im:
                im.draft("RGB", (192, 192))  # JPEG : décodage réduit, beaucoup plus rapide
                im = ImageOps.exif_transpose(im)
                im.thumbnail((128, 128))
                if im.mode not in ("RGB", "RGBA"):
                    im = im.convert("RGBA")
                im.save(cached + ".tmp", "WEBP", quality=70)
            os.replace(cached + ".tmp", cached)
        except Exception:
            abort(404)
    response = make_response(send_file(cached, mimetype="image/webp"))
    response.headers["Cache-Control"] = "private, max-age=86400"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@admin_bp.route("/admin/base/sauvegarde", methods=["GET"], endpoint="admin_db_backup")
@admin_required
def admin_db_backup():
    """Télécharge une copie complète et cohérente de la base (pixshare-AAAA-MM-JJ.db)."""
    import tempfile
    from datetime import datetime

    from pixshare.services import sqlite_store
    from pixshare.services.json_services import _get_data_dir, use_sqlite

    if not use_sqlite():
        abort(404)
    handle, tmp = tempfile.mkstemp(suffix=".db")
    os.close(handle)
    sqlite_store.backup_to(_get_data_dir(), tmp)
    with open(tmp, "rb") as f:
        data = f.read()
    os.remove(tmp)
    name = f"pixshare-{datetime.now().strftime('%Y-%m-%d-%H%M')}.db"
    response = make_response(data)
    response.headers["Content-Type"] = "application/octet-stream"
    response.headers["Content-Disposition"] = f'attachment; filename="{name}"'
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
