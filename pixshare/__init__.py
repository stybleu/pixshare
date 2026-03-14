from flask import Flask, request

from .config import Config
from .storage import init_storage, project_path
from .security.csrf import inject_csrf_token
from .services.request_service import get_client_ip
from .routes.public_routes import public_bp
from .routes.admin_routes import admin_bp
from .routes.seo_routes import seo_bp
from .services.translation_service import apply_requested_language, build_lang_url, get_current_language, translate


def create_app() -> Flask:
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.from_object(Config)
    app.config["UPLOAD_FOLDER"] = project_path(app, app.config["UPLOAD_FOLDER"])

    init_storage(app)

    @app.context_processor
    def _inject_globals():
        data = inject_csrf_token()
        data.update({
            "_": translate,
            "current_lang": get_current_language(),
            "switch_lang_url": build_lang_url,
        })
        return data

    @app.before_request
    def apply_language():
        apply_requested_language()

    @app.before_request
    def log_request():
        ip = get_client_ip()
        print("IP:", ip, "URL:", request.path)

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data: https:; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' data: https://cdn.jsdelivr.net; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none';"
        )
        return response

    @app.after_request
    def add_robots_headers(resp):
        if request.path.startswith("/admin"):
            resp.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
        return resp

    app.register_blueprint(seo_bp)
    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp)

    return app
