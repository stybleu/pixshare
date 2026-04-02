import os
import secrets

from flask import Blueprint, current_app, flash, redirect, render_template, request, send_file, session, url_for, abort

from pixshare.security.csrf import validate_csrf
from pixshare.services.auth_service import admin_required, process_admin_login
from pixshare.services.api_auth_service import ensure_default_api_keys, remaining_uploads_info
from pixshare.services.file_service import cleanup_expired, delete_all_thumbnails, delete_by_id, delete_thumbnail_by_id, get_thumbnail_abs_path, list_all_files, list_all_thumbnails
from pixshare.services.json_services import load_api_keys, load_blocked, load_contacts, save_api_keys, save_blocked, save_contacts
from pixshare.services.settings_service import (
    get_valid_lifetime,
    get_valid_thumbnail_retention_hours,
    load_settings,
    save_settings,
)
from pixshare.services.time_service import get_remaining_time_label
from pixshare.services.system_service import get_system_stats

admin_bp = Blueprint("admin", __name__)


def _parse_positive_int(value, default, minimum=1):
    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, ivalue)


def _parse_allowed_lifetimes(raw_value: str, fallback: list[int] | None = None) -> list[int]:
    fallback = fallback or [5, 10, 20, 30, 60]
    values = []
    for chunk in (raw_value or '').replace(';', ',').split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            ivalue = int(chunk)
        except (TypeError, ValueError):
            continue
        if ivalue > 0 and ivalue not in values:
            values.append(ivalue)
    return sorted(values or fallback)


def _build_api_key_record_from_form(form):
    allowed_lifetimes = _parse_allowed_lifetimes(form.get('allowed_lifetimes') or '5,10,20,30,60')
    default_lifetime = _parse_positive_int(form.get('default_lifetime_minutes'), 10)
    if default_lifetime not in allowed_lifetimes:
        default_lifetime = min(allowed_lifetimes, key=lambda x: abs(x - default_lifetime))

    return {
        'name': (form.get('name') or 'api-client').strip(),
        'is_active': form.get('is_active', '1') == '1',
        'max_uploads_total': _parse_positive_int(form.get('max_uploads_total'), 100),
        'uploads_used': 0,
        'max_uploads_per_day': _parse_positive_int(form.get('max_uploads_per_day'), 10),
        'daily_uploads_used': 0,
        'daily_reset_date': '',
        'max_file_size_mb': _parse_positive_int(form.get('max_file_size_mb'), 10),
        'allow_permanent': form.get('allow_permanent') == '1',
        'default_lifetime_minutes': default_lifetime,
        'allowed_lifetimes': allowed_lifetimes,
        'notes': (form.get('notes') or '').strip(),
    }


def _decorate_api_keys(api_keys: dict) -> list[dict]:
    rows = []
    for key_value, key_data in api_keys.items():
        usage = remaining_uploads_info(key_data)
        rows.append({
            'key_value': key_value,
            'key_preview': f"{key_value[:16]}…{key_value[-8:]}" if len(key_value) > 28 else key_value,
            'name': key_data.get('name') or 'api-client',
            'is_active': bool(key_data.get('is_active', True)),
            'max_file_size_mb': key_data.get('max_file_size_mb', 10),
            'allow_permanent': bool(key_data.get('allow_permanent', False)),
            'default_lifetime_minutes': key_data.get('default_lifetime_minutes', 10),
            'allowed_lifetimes_text': ', '.join(str(x) for x in key_data.get('allowed_lifetimes', [])),
            'notes': key_data.get('notes', ''),
            'daily_reset_date': key_data.get('daily_reset_date', ''),
            **usage,
        })
    rows.sort(key=lambda item: (not item['is_active'], item['name'].lower(), item['key_value']))
    return rows


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

    files = list_all_files(include_thumbnails=False)

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


@admin_bp.route("/admin/thumbnails", methods=["GET"], endpoint="admin_thumbnails")
@admin_required
def admin_thumbnails():
    cleanup_expired()

    thumbnails = list_all_thumbnails()
    for item in thumbnails:
        item["remaining_time"] = get_remaining_time_label(item.get("expires_at")) if item.get("status") == "active" else ""

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
    token = request.form.get("csrf_token", "")
    if token != session.get("csrf_token"):
        flash("Token CSRF invalide.", "danger")
        return redirect(url_for("admin.admin_thumbnails"))

    ip = (request.form.get("ip") or "").strip()
    file_id = (request.form.get("file_id") or "").strip()

    if not ip:
        flash("Aucune IP à bloquer.", "warning")
        return redirect(url_for("admin.admin_thumbnails"))

    blocked = load_blocked_ips()

    if ip not in blocked:
        blocked[ip] = {
            "reason": f"Blocage depuis les miniatures (fichier {file_id})",
            "created_at": datetime.utcnow().isoformat() + "Z"
        }
        save_blocked_ips(blocked)
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
    


@admin_bp.route("/admin/api-keys", methods=["GET"], endpoint="admin_api_keys")
@admin_required
def admin_api_keys():
    api_keys = load_api_keys()
    return render_template(
        "admin_api_keys.html",
        api_keys=_decorate_api_keys(api_keys),
        version=current_app.config["APP_VERSION"]
    )


@admin_bp.route("/admin/api-keys/create", methods=["POST"], endpoint="admin_api_key_create")
@admin_required
def admin_api_key_create():
    validate_csrf()
    ensure_default_api_keys()
    api_keys = load_api_keys()

    custom_key = (request.form.get("custom_key") or "").strip()
    prefix = (request.form.get("key_prefix") or "ps_live").strip() or "ps_live"
    key_value = custom_key or f"{prefix}_{secrets.token_hex(32)}"

    if len(key_value) < 16:
        flash("Clé API trop courte.", "warning")
        return redirect(url_for("admin.admin_api_keys"))

    if key_value in api_keys:
        flash("Cette clé API existe déjà.", "warning")
        return redirect(url_for("admin.admin_api_keys"))

    api_keys[key_value] = _build_api_key_record_from_form(request.form)
    save_api_keys(api_keys)
    flash("Clé API créée ✅", "success")
    return redirect(url_for("admin.admin_api_keys"))


@admin_bp.route("/admin/api-keys/toggle", methods=["POST"], endpoint="admin_api_key_toggle")
@admin_required
def admin_api_key_toggle():
    validate_csrf()
    key_value = (request.form.get("key_value") or "").strip()
    api_keys = load_api_keys()
    key_data = api_keys.get(key_value)

    if not key_data:
        flash("Clé API introuvable.", "warning")
        return redirect(url_for("admin.admin_api_keys"))

    key_data["is_active"] = not bool(key_data.get("is_active", True))
    api_keys[key_value] = key_data
    save_api_keys(api_keys)
    flash("Clé API mise à jour ✅", "success")
    return redirect(url_for("admin.admin_api_keys"))


@admin_bp.route("/admin/api-keys/reset-usage", methods=["POST"], endpoint="admin_api_key_reset_usage")
@admin_required
def admin_api_key_reset_usage():
    validate_csrf()
    key_value = (request.form.get("key_value") or "").strip()
    api_keys = load_api_keys()
    key_data = api_keys.get(key_value)

    if not key_data:
        flash("Clé API introuvable.", "warning")
        return redirect(url_for("admin.admin_api_keys"))

    key_data["uploads_used"] = 0
    key_data["daily_uploads_used"] = 0
    api_keys[key_value] = key_data
    save_api_keys(api_keys)
    flash("Compteurs remis à zéro ✅", "success")
    return redirect(url_for("admin.admin_api_keys"))


@admin_bp.route("/admin/api-keys/delete", methods=["POST"], endpoint="admin_api_key_delete")
@admin_required
def admin_api_key_delete():
    validate_csrf()

    key_value = (request.form.get("key_value") or "").strip()
    api_keys = load_api_keys()

    print("DELETE KEY:", key_value)
    print("ALL KEYS:", api_keys)

    deleted = False

    # Cas 1 : dict classique (OK attendu)
    if isinstance(api_keys, dict):
        if key_value in api_keys:
            del api_keys[key_value]
            deleted = True

    # Cas 2 : liste (sécurité)
    elif isinstance(api_keys, list):
        new_keys = []
        for k in api_keys:
            if k.get("key") == key_value and not deleted:
                deleted = True
                continue
            new_keys.append(k)
        api_keys = new_keys

    if deleted:
        save_api_keys(api_keys)
        flash("Clé API supprimée ✅", "success")
    else:
        flash("Clé API introuvable.", "warning")

    return redirect(url_for("admin.admin_api_keys"))

@admin_bp.route("/admin/system", methods=["GET"], endpoint="admin_system")
@admin_required
def admin_system():
    stats = get_system_stats()

    return render_template(
        "admin_system.html",
        stats=stats,
        version=current_app.config["APP_VERSION"]
    )