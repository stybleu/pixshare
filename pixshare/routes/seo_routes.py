
import json

from flask import Blueprint, flash, redirect, request, url_for

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
Disallow: /file/
Disallow: /view/
Disallow: /download/
Disallow: /album/
Disallow: /mes-albums

Sitemap: {base}/sitemap.xml
"""
    return content, 200, {"Content-Type": "text/plain; charset=utf-8"}


@seo_bp.route("/sitemap.xml", endpoint="sitemap")
def sitemap():
    base = request.url_root.rstrip("/")
    pages = [
        {"loc": "/", "priority": "1.0", "changefreq": "daily"},
        {"loc": "/album-souvenir", "priority": "0.9", "changefreq": "monthly"},
        {"loc": "/faq", "priority": "0.8", "changefreq": "monthly"},
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


# ------------------------------------------------------------------ appli installable (Android : menu « Partager »)

SERVICE_WORKER = """// PixShare : sert UNIQUEMENT à recevoir une photo partagée depuis la galerie du téléphone.
// Aucune page ni aucune image n'est mise en cache : tout le reste passe par le réseau, comme d'habitude.
self.addEventListener("install", function () { self.skipWaiting(); });
self.addEventListener("activate", function (e) { e.waitUntil(self.clients.claim()); });
self.addEventListener("fetch", function (e) {
  var url = new URL(e.request.url);
  if (e.request.method !== "POST" || url.origin !== self.location.origin || url.pathname !== "/partager") return;
  e.respondWith((async function () {
    try {
      var data = await e.request.formData();
      var files = data.getAll("file").filter(function (f) { return f && typeof f !== "string" && f.size; }).slice(0, 10);
      var cache = await caches.open("pixshare-partage");
      var old = await cache.keys();
      await Promise.all(old.map(function (k) { return cache.delete(k); }));
      await Promise.all(files.map(function (f, i) {
        return cache.put("/partage/" + i, new Response(f, { headers: {
          "Content-Type": f.type || "application/octet-stream", "X-Nom": encodeURIComponent(f.name || "photo") } }));
      }));
    } catch (err) {}
    return Response.redirect("/?partage=1", 303);
  })());
});
"""


@seo_bp.route("/sw.js", endpoint="service_worker")
def service_worker():
    return SERVICE_WORKER, 200, {"Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-cache",
                                 "Service-Worker-Allowed": "/"}


@seo_bp.route("/manifest.webmanifest", endpoint="manifest")
def manifest():
    data = {
        "name": "PixShare – Partage d'images et albums souvenirs",
        "short_name": "PixShare",
        "description": "Hébergeur d'images gratuit : partagez vos photos en un instant.",
        "lang": "fr",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "background_color": "#ffffff",
        "theme_color": "#4f46e5",
        "icons": [
            {"src": url_for("static", filename="favicon-192.png"), "sizes": "192x192", "type": "image/png"},
            {"src": url_for("static", filename="icon-512.png"), "sizes": "512x512", "type": "image/png"},
            {"src": url_for("static", filename="icon-maskable-512.png"), "sizes": "512x512", "type": "image/png",
             "purpose": "maskable"},
        ],
        # Menu « Partager » d'Android : la photo arrive dans le formulaire d'envoi habituel.
        "share_target": {
            "action": "/partager",
            "method": "POST",
            "enctype": "multipart/form-data",
            "params": {"files": [{"name": "file", "accept": ["image/*", "video/*"]}]},
        },
    }
    return json.dumps(data, ensure_ascii=False), 200, {"Content-Type": "application/manifest+json; charset=utf-8",
                                                       "Cache-Control": "public, max-age=86400"}


@seo_bp.route("/partager", methods=["GET", "POST"], endpoint="share_target")
def share_target():
    """Normalement intercepté par le service worker. S'il n'est pas encore actif, on ne garde rien
    (pas de jeton anti-falsification ni de vérification anti-robot ici) : la personne choisit la photo sur l'accueil."""
    if request.method == "POST":
        flash("Le partage n'a pas pu être préparé : choisissez la photo ici, puis appuyez sur Envoyer.", "info")
    return redirect(url_for("public.index"))
