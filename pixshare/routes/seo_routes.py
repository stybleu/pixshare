
from flask import Blueprint, request

from pixshare.services.file_service import get_file_record
from pixshare.services.json_services import load_db

seo_bp = Blueprint("seo", __name__)
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp"}


@seo_bp.route("/healthz", endpoint="healthz")
def healthz():
    """Contrôle de santé pour Render : l'appli répond et peut écrire ses données."""
    import os
    import tempfile

    from flask import current_app

    from pixshare.services.json_services import _get_data_dir

    try:
        for folder in (_get_data_dir(), current_app.config["UPLOAD_FOLDER"]):
            with tempfile.NamedTemporaryFile(dir=folder, prefix=".health-"):
                pass
    except Exception:
        return "stockage indisponible", 503, {"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store"}
    return "ok", 200, {"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Robots-Tag": "noindex"}


@seo_bp.route("/robots.txt", endpoint="robots")
def robots():
    base = request.url_root.rstrip("/")
    content = f"""User-agent: *
Allow: /

Disallow: /admin
Disallow: /admin_panel
Disallow: /admin_login
Disallow: /file/
Disallow: /download/
Disallow: /tmp/
Disallow: /api/

Sitemap: {base}/sitemap.xml
"""
    return content, 200, {"Content-Type": "text/plain; charset=utf-8"}


@seo_bp.route("/sitemap.xml", endpoint="sitemap")
def sitemap():
    base = request.url_root.rstrip("/")
    pages = [
        {"loc": "/", "priority": "1.0", "changefreq": "daily"},
        {"loc": "/mentions-legales", "priority": "0.7", "changefreq": "yearly"},
        {"loc": "/cgu", "priority": "0.7", "changefreq": "yearly"},
        {"loc": "/contact", "priority": "0.6", "changefreq": "yearly"},
    ]

    # Les images des utilisateurs ne sont jamais listées : elles sont privées et temporaires.

    xml = ['<?xml version="1.0" encoding="UTF-8"?>']
    xml.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')
    for page in pages:
        xml.append("<url>")
        xml.append(f"<loc>{base}{page['loc']}</loc>")
        if page.get("lastmod"):  # vraie date seulement : une date toujours « aujourd'hui » est ignorée par Google
            xml.append(f"<lastmod>{page['lastmod']}</lastmod>")
        xml.append(f"<changefreq>{page['changefreq']}</changefreq>")
        xml.append(f"<priority>{page['priority']}</priority>")
        xml.append("</url>")
    xml.append("</urlset>")
    return "\n".join(xml), 200, {"Content-Type": "application/xml"}
