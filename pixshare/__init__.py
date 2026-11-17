import logging
import mimetypes

from flask import Flask, request

from .config import Config
from .storage import init_storage, project_path
from .security.csrf import inject_csrf_token
from .services.request_service import get_client_ip
from .routes.public_routes import public_bp
from .routes.admin_routes import admin_bp
from .routes.seo_routes import seo_bp
from .services.turnstile_service import site_key, turnstile_required
from .services.visitor_stats_service import record_image_display, record_page_view, should_count, should_count_display
from .services.live_service import record as record_live
from .services.auth_service import is_admin
from .services.translation_service import apply_requested_language, build_lang_url, get_current_language, translate
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
    import shutil

    from .services.json_services import _get_data_dir
    from .services.visitor_stats_service import forget_locations

    try:
        shutil.rmtree(os.path.join(_get_data_dir(), "geoip"), ignore_errors=True)
        forget_locations()
    except Exception:
        pass


def create_app(config_overrides: dict | None = None) -> Flask:
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.from_object(Config)
    if config_overrides:
        app.config.update(config_overrides)
    app.config["UPLOAD_FOLDER"] = project_path(app, app.config["UPLOAD_FOLDER"])

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
            and request.endpoint == "public.index"
            and response.status_code < 400
        ):
            response.call_on_close(lambda: run_after_response(app))
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

    app.register_blueprint(seo_bp)
    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp)

    return app
