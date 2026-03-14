from datetime import datetime

from flask import Blueprint, current_app, request

from pixshare.services.file_service import get_file_record
from pixshare.services.json_services import load_db

seo_bp = Blueprint("seo", __name__)
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp"}


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

    for file_id, meta in load_db().items():
        original_name = meta.get("original_name", "")
        ext = ("." + original_name.rsplit(".", 1)[-1].lower()) if "." in original_name else ""
        if ext not in IMAGE_EXTENSIONS:
            continue
        if not bool(meta.get("permanent")):
            continue
        _db, valid_meta, _server_name = get_file_record(file_id)
        if not valid_meta:
            continue
        pages.append({
            "loc": f"/image/{file_id}",
            "priority": "0.6",
            "changefreq": "weekly",
        })

    today = datetime.utcnow().date().isoformat()
    xml = ['<?xml version="1.0" encoding="UTF-8"?>']
    xml.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')
    for page in pages:
        xml.append("<url>")
        xml.append(f"<loc>{base}{page['loc']}</loc>")
        xml.append(f"<lastmod>{today}</lastmod>")
        xml.append(f"<changefreq>{page['changefreq']}</changefreq>")
        xml.append(f"<priority>{page['priority']}</priority>")
        xml.append("</url>")
    xml.append("</urlset>")
    return "\n".join(xml), 200, {"Content-Type": "application/xml"}
