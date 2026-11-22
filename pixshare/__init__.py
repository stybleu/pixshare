import logging
import mimetypes

from flask import Flask, g, request

from .config import Config
from .storage import init_storage, project_path
from .security.csrf import inject_csrf_token
from .services.request_service import get_client_ip
from .routes.public_routes import public_bp
from .routes.admin_routes import admin_bp
from .routes.seo_routes import seo_bp
from .routes.account_routes import account_bp
from .routes.extension_routes import extension_bp
from .routes.album_routes import album_bp
from .services.account_service import current_account
from .services.turnstile_service import site_key, turnstile_required
from .services.visitor_stats_service import record_image_display, record_page_view, should_count, should_count_display
from .services.live_service import record as record_live
from .services.auth_service import is_admin
from .services.translation_service import apply_requested_language, build_lang_url, get_current_language, translate
from .services.seo_pages import page_seo
from .services.auth_service import check_admin_config
from .services.nsfw_service import run_after_response
from .services.settings_service import get_support_url, load_settings
from .services.theme_service import active_theme, sky_enabled, theme_message

_log = logging.getLogger(__name__)

for _ext, _mime in {
    ".bmp": "image/bmp", ".jfif": "image/jpeg", ".jpe": "image/jpeg", ".apng": "image/apng",
}.items():
    mimetypes.add_type(_mime, _ext)


def _forget_geolocation() -> None:
    """La géolocalisation des visiteurs a été retirée : on efface la base DB-IP téléchargée
    et les pays/villes déjà comptés dans les statistiques."""
    import os
    import shutil

    from .services.json_services import _get_data_dir
    from .services.visitor_stats_service import forget_locations

    log = logging.getLogger(__name__)
    folder = os.path.join(_get_data_dir(), "geoip")
    if os.path.isdir(folder):
        try:
            shutil.rmtree(folder)
            log.info("Ancienne base de géolocalisation effacée : %s", folder)
        except OSError as exc:
            log.warning("Impossible d'effacer %s : %s", folder, exc)
    try:
        forget_locations()
    except Exception:
        log.exception("Effacement des anciens pays/villes des statistiques impossible")


_ERRORS = {
    400: ("Requête invalide", "La demande n'a pas pu être traitée. Rechargez la page et réessayez."),
    403: ("Accès refusé", "Vous n'avez pas accès à cette page."),
    404: ("Page introuvable", "Cette page n'existe pas, ou la photo a expiré ou été supprimée."),
    413: ("Trop volumineux", "La photo ou la vidéo dépasse la taille maximale indiquée sur l'accueil."),
    429: ("Trop de demandes", "Vous avez fait trop de demandes en peu de temps. Patientez un peu puis réessayez."),
    500: ("Erreur du serveur", "Un problème est survenu de notre côté. Réessayez dans quelques instants."),
}


_PLACEHOLDER: dict = {}


def expired_image_placeholder() -> bytes:
    """Petite image « Image indisponible · PixShare », montrée à la place d'une image disparue intégrée ailleurs
    (forum, Discord, site) : mieux qu'une image cassée. Fabriquée une fois, puis gardée en mémoire."""
    if "png" not in _PLACEHOLDER:
        import io
        from PIL import Image, ImageDraw, ImageFont
        w, h = 480, 300
        img = Image.new("RGB", (w, h), (238, 242, 255))
        d = ImageDraw.Draw(img)
        d.rounded_rectangle((8, 8, w - 9, h - 9), radius=22, outline=(199, 210, 254), width=3)
        cx, top = w // 2, 62
        d.rectangle((cx - 26, top, cx + 26, top + 8), fill=(120, 53, 15))
        d.rectangle((cx - 26, top + 72, cx + 26, top + 80), fill=(120, 53, 15))
        d.polygon([(cx - 20, top + 8), (cx + 20, top + 8), (cx + 4, top + 40), (cx + 20, top + 72),
                   (cx - 20, top + 72), (cx - 4, top + 40)], fill=(186, 230, 253))
        d.polygon([(cx - 12, top + 18), (cx + 12, top + 18), (cx, top + 34)], fill=(245, 158, 11))
        d.polygon([(cx - 16, top + 72), (cx + 16, top + 72), (cx, top + 58)], fill=(245, 158, 11))
        try:
            big, small = ImageFont.load_default(size=30), ImageFont.load_default(size=18)
        except Exception:  # ancienne version de Pillow
            big = small = ImageFont.load_default()
        d.text((cx, 190), "Image indisponible", font=big, fill=(30, 27, 75), anchor="mm")
        d.text((cx, 232), "Ce lien PixShare n'est plus disponible", font=small, fill=(79, 70, 229), anchor="mm")
        buf = io.BytesIO()
        img.save(buf, "PNG", optimize=True)
        _PLACEHOLDER["png"] = buf.getvalue()
    return _PLACEHOLDER["png"]


def _register_error_pages(app: Flask) -> None:
    """Pages d'erreur en français, dans le style du site (au lieu du texte anglais par défaut)."""
    from flask import render_template, request as _req
    from werkzeug.exceptions import HTTPException

    def opened_in_browser() -> bool:
        """Vraie page ouverte dans le navigateur (pas une image affichée dans un forum ou un téléchargement)."""
        dest = (_req.headers.get("Sec-Fetch-Dest") or "").lower()
        if dest:
            return dest == "document"
        return _req.accept_mimetypes.best == "text/html"

    def handler(error):
        code = error.code if isinstance(error, HTTPException) else 500
        title, text = _ERRORS.get(code, ("Erreur", "Une erreur est survenue."))
        link_path = _req.path.startswith(("/view/", "/file/", "/download/"))
        plain = (not _req.accept_mimetypes.accept_html or _req.path.startswith("/static/")
                 or (_req.path.startswith(("/view/", "/download/")) and not opened_in_browser()))
        if (plain and code == 404 and _req.path.startswith("/view/")
                and _req.accept_mimetypes.best_match(["image/png", "text/html"]) == "image/png"):
            try:  # image intégrée ailleurs : une vignette « Image indisponible » plutôt qu'une image cassée
                return expired_image_placeholder(), 404, {"Content-Type": "image/png", "Cache-Control": "public, max-age=600",
                                                          "X-Robots-Tag": "noindex, noimageindex"}
            except Exception:
                pass
        if plain:
            return f"{code} {title}", code, {"Content-Type": "text/plain; charset=utf-8"}
        album_path = _req.path.startswith("/album/")
        kind = ("expired" if (link_path or album_path) else "missing") if code == 404 else "other"
        if kind == "expired" and album_path:
            title, text = ("Cet album n'est plus disponible",
                           "Il a été supprimé par son créateur, ou l'adresse est incomplète. Vérifiez le lien ou le QR code reçu.")
        elif kind == "expired":
            title, text = ("Ce lien n'est plus disponible",
                           "Les photos sur PixShare sont temporaires : celle-ci a expiré, a été supprimée par son "
                           "auteur ou a atteint sa limite de vues.")
        elif kind == "missing":
            title, text = ("Oups, page introuvable",
                           "Cette adresse ne mène nulle part. Elle a peut-être été mal recopiée, ou la page a changé de place.")
        try:
            return render_template("error.html", code=code, error_title=title, error_text=text, kind=kind), code
        except Exception:
            return f"{code} {title}", code, {"Content-Type": "text/plain; charset=utf-8"}

    for code in _ERRORS:
        app.register_error_handler(code, handler)


import mimetypes as _mimetypes
_mimetypes.add_type("audio/wav", ".wav")
_mimetypes.add_type("audio/ogg", ".opus")


def create_app(config_overrides: dict | None = None) -> Flask:
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.from_object(Config)
    if config_overrides:
        app.config.update(config_overrides)
    app.config["UPLOAD_FOLDER"] = project_path(app, app.config["UPLOAD_FOLDER"])

    @app.template_filter("day_fr")
    def day_fr(value: str) -> str:
        """« 31/12/2026 » à partir de « 2026-12-31 »."""
        parts = str(value or "").split("-")
        return "/".join(reversed(parts)) if len(parts) == 3 else str(value or "")

    @app.template_filter("date_fr")
    def date_fr(value: str) -> str:
        """« 17/11/2026 à 17:00 » (heure de Paris) à partir d'une date ISO enregistrée en UTC."""
        from zoneinfo import ZoneInfo

        from .services.time_service import parse_dt
        try:
            return parse_dt(value or "").astimezone(ZoneInfo("Europe/Paris")).strftime("%d/%m/%Y à %H:%M")
        except Exception:
            return value or ""

    _register_error_pages(app)

    init_storage(app)
    with app.app_context():
        check_admin_config()

    @app.context_processor
    def _inject_season_theme():
        try:
            settings = load_settings()
            theme = active_theme(settings.get("season_theme"))
            return {
                "season_theme": theme,
                "season_message": theme_message(theme),
                "sky_on": sky_enabled(settings.get("sky_enabled")),
                "support_url": get_support_url(),
            }
        except Exception:
            return {"season_theme": "", "season_message": "", "sky_on": False, "support_url": ""}

    @app.context_processor
    def _inject_globals():
        data = inject_csrf_token()
        data.update({
            "_": translate,
            "current_lang": get_current_language(),
            "switch_lang_url": build_lang_url,
            "turnstile_site_key": site_key() if turnstile_required() else "",
            "member": current_account(),
            "seo_page": page_seo(request.endpoint, get_current_language()),
        })
        return data


    @app.before_request
    def apply_language():
        apply_requested_language()

    @app.before_request
    def log_request():
        # Les IP sont des données personnelles : on ne les écrit dans les logs
        # qu'en mode debug, et via le logger plutôt que print().
        if app.logger.isEnabledFor(logging.DEBUG):
            app.logger.debug("IP: %s URL: %s", get_client_ip(), request.path)

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data: https:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; "
            "frame-src https://challenges.cloudflare.com; "
            "font-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none';"
        )
        return response

    @app.after_request
    def auto_moderate_after_upload(response):
        # Après l'envoi de la réponse (l'utilisateur n'attend pas l'analyse), NudeNet traite
        # les images en attente. Seuls les envois de fichiers déclenchent l'analyse.
        if (
            request.method == "POST"
            and request.endpoint in ("public.index", "account.replace", "extension.upload", "public.delete_own_file",
                                 "album.add", "album.delete_photo", "album.delete")
            and response.status_code < 400
        ):
            response.call_on_close(lambda: run_after_response(app))
        return response

    @app.after_request
    def nightly_backup_check(response):
        # Sauvegarde R2 de la nuit : vérifiée au plus toutes les 10 minutes, après la réponse,
        # et lancée dans un fil à part (aucune page n'attend).
        from .services import backup_service, disk_alert_service
        if backup_service.should_check():
            response.call_on_close(lambda: backup_service.maybe_nightly_backup(app))
        # Disque presque plein : un mail à l'admin (vérifié au plus toutes les 10 minutes, après la réponse).
        if disk_alert_service.should_check():
            response.call_on_close(lambda: disk_alert_service.check_later(app))
        return response

    @app.after_request
    def count_visit(resp):
        # Statistiques de l'admin : pages vues, visiteurs uniques du jour (sans stocker d'IP)
        # et sites où les images sont affichées. Aucune localisation, aucun profil de visiteur.
        try:
            if should_count(resp) and not is_admin():
                ip = get_client_ip()
                record_page_view(ip)
                record_live(ip)
            elif should_count_display(resp) and not is_admin():
                record_image_display()
        except Exception:
            pass
        return resp

    @app.after_request
    def add_robots_headers(resp):
        if request.path.startswith("/admin"):
            resp.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
        elif request.path.startswith("/static/") and resp.status_code == 200:
            resp.headers["Cache-Control"] = "public, max-age=604800"  # 7 jours (logo, favicon…)
        return resp

    _forget_geolocation()  # ancienne base de géolocalisation : effacée du disque (fonction retirée)

    if not app.config.get("TESTING"):
        from .services.mail_service import resume_pending_alert
        resume_pending_alert(app)  # mail d'alerte perdu lors d'un redémarrage : renvoyé

    app.register_blueprint(seo_bp)
    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(account_bp)
    app.register_blueprint(extension_bp)
    app.register_blueprint(album_bp)

    return app
