from datetime import datetime
from flask import Blueprint, request

seo_bp = Blueprint("seo", __name__)


@seo_bp.route("/robots.txt", endpoint="robots")
def robots():
    base = request.url_root.rstrip("/")
    content = f"""User-agent: *
Allow: /

Sitemap: {base}/sitemap.xml
"""
    return content, 200, {"Content-Type": "text/plain; charset=utf-8"}


@seo_bp.route("/sitemap.xml", endpoint="sitemap")
def sitemap():
    base = request.url_root.rstrip("/")
    pages = [
        {"loc": "/", "priority": "1.0", "changefreq": "daily"},
        {"loc": "/contact", "priority": "0.5", "changefreq": "yearly"},
        {"loc": "/cgu", "priority": "0.3", "changefreq": "yearly"},
    ]
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
