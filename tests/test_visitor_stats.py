"""Compteur de visites : visiteurs uniques par jour, sans robots ni admin, sans IP stockée."""
import io
import json
import os

from PIL import Image

from conftest import csrf, login
from pixshare.services import visitor_stats_service

FIREFOX = "Mozilla/5.0 (Android 14; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0"


def visit(client, ip, ua=FIREFOX, path="/"):
    return client.get(path, headers={"User-Agent": ua}, environ_overrides={"REMOTE_ADDR": ip})


def today(app):
    with app.app_context():
        return visitor_stats_service.summary(30)["today"]


def test_unique_visitors_and_page_views(make_app):
    app = make_app()
    client = app.test_client()
    visit(client, "198.51.100.1")
    visit(client, "198.51.100.1", path="/contact")
    visit(client, "198.51.100.2")
    t = today(app)
    assert (t["visitors"], t["views"]) == (2, 3)


def test_bots_admin_and_technical_pages_are_ignored(make_app):
    app = make_app()
    client = app.test_client()
    visit(client, "198.51.100.3", ua="Mozilla/5.0 (compatible; Googlebot/2.1)")
    visit(client, "198.51.100.4", ua="WhatsApp/2.23")
    visit(client, "198.51.100.5", ua="")
    visit(client, "198.51.100.6", path="/healthz")
    visit(client, "198.51.100.6", path="/robots.txt")
    t = today(app)
    assert (t["visitors"], t["views"]) == (0, 0)
    admin = login(app.test_client())  # la page d'accueil vue avant connexion compte (visiteur anonyme)
    before = today(app)["views"]
    admin.get("/", headers={"User-Agent": FIREFOX})
    admin.get("/contact", headers={"User-Agent": FIREFOX})
    assert today(app)["views"] == before


def test_no_ip_is_stored(make_app):
    app = make_app()
    visit(app.test_client(), "203.0.113.77")
    raw = open(os.path.join(os.environ["PIXSHARE_DATA_DIR"], "visitor_stats.json")).read()
    assert "203.0.113.77" not in raw and json.loads(raw)["days"]


def test_uploads_counted_and_admin_page(make_app):
    app = make_app(NSFW_AUTO_MODERATION=False)
    client = app.test_client()
    buf = io.BytesIO()
    Image.new("RGB", (9, 9)).save(buf, "PNG")
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(buf.getvalue()), "a.png")},
                content_type="multipart/form-data")
    assert today(app)["uploads"] == 1
    page = login(app.test_client()).get("/admin/stats").get_data(as_text=True)
    assert "Statistiques de visite" in page and "Visiteurs par jour" in page and "1 envoi" in page
