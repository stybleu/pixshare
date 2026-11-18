"""Compteur de visites : visiteurs uniques par jour, sans robots ni admin, sans IP stockée."""
import io
import json
import os

from PIL import Image

from conftest import csrf, login
from pixshare.services import json_services, visitor_stats_service

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
    base = os.path.join(os.environ["PIXSHARE_DATA_DIR"], "pixshare.db")
    raw = b"".join(open(base + s, "rb").read() for s in ("", "-wal") if os.path.exists(base + s))
    assert b"203.0.113.77" not in raw  # ni dans la base, ni dans son journal
    with app.app_context():
        assert json_services.load_json("visitor_stats.json", {})["days"]


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


def test_usage_without_knowing_visitors(make_app):
    app = make_app()
    client = app.test_client()
    visit(client, "198.51.100.1")
    client.get("/contact", headers={"User-Agent": FIREFOX, "Referer": "https://www.google.fr/search?q=pixshare",
                                    "cf-ipcountry": "FR", "cf-ipcity": "Chartres"},
               environ_overrides={"REMOTE_ADDR": "198.51.100.1"})
    client.get("/", headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile Safari/604.1",
                             "Referer": "https://discord.com/channels/1/2"}, environ_overrides={"REMOTE_ADDR": "198.51.100.2"})
    with app.app_context():
        st = visitor_stats_service.summary(30)
        raw = json_services.load_json(visitor_stats_service.STATS_FILE, {})
    assert {r["key"]: r["count"] for r in st["referrers"]} == {"Accès direct": 1, "Google": 1, "Discord": 1}
    assert sum(st["hours"]) == 3
    text = str(raw)
    for personal in ("countries", "cities", "devices", "browsers", "Chartres", "FR", "Firefox", "iPhone", "198.51"):
        assert personal not in text, personal
    page = login(app.test_client()).get("/admin/stats").get_data(as_text=True)
    assert "Pays" not in page and "Villes" not in page and "Appareils" not in page
    assert "La publicité couvrirait-elle les frais" in page


def test_sites_where_images_are_shared(make_app):
    app = make_app()
    client = app.test_client()
    buf = io.BytesIO()
    Image.new("RGB", (9, 9)).save(buf, "PNG")
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(buf.getvalue()), "a.png")},
                content_type="multipart/form-data")
    with app.app_context():
        file_id = next(iter(json_services.load_db()))
    viewer = app.test_client()
    for ref in ("https://forum.exemple.fr/topic/12", "https://forum.exemple.fr/topic/13", "https://www.reddit.com/r/x"):
        assert viewer.get(f"/view/{file_id}", headers={"Referer": ref, "Sec-Fetch-Dest": "image"}).status_code == 200
    viewer.get(f"/view/{file_id}", headers={"Sec-Fetch-Dest": "image"})
    with app.app_context():
        st = visitor_stats_service.summary(30)
    assert {r["key"]: r["count"] for r in st["shared_on"]} == {
        "forum.exemple.fr": 2, "Reddit": 1, "Lien ouvert directement ou dans une appli": 1}
    assert st["displays"] == 4
    page = login(app.test_client()).get("/admin/stats").get_data(as_text=True)
    assert "Où les images sont partagées" in page and "forum.exemple.fr" in page


def test_old_location_counters_are_erased(make_app):
    app = make_app()
    with app.app_context():
        day = visitor_stats_service._today().isoformat()
        json_services.save_json(visitor_stats_service.STATS_FILE, {"days": {day: {
            "visitors": 1, "views": 1, "uploads": 0, "countries": {"FR": 1}, "cities": {"Chartres, FR": 1},
            "devices": {"Mobile": 1}, "browsers": {"Firefox": 1}}}})
        visitor_stats_service.forget_locations()
        entry = json_services.load_json(visitor_stats_service.STATS_FILE, {})["days"][day]
    assert entry == {"visitors": 1, "views": 1, "uploads": 0}
