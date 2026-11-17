"""Page « En direct » : visiteurs actifs, sans localisation, IP masquée, blocage, oubli après 5 minutes."""
import json
import os

import pytest

from conftest import csrf, login
from pixshare.services import json_services, live_service

FIREFOX = "Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36"
PARIS = {"User-Agent": FIREFOX, "cf-ipcity": "Chartres", "cf-ipcountry": "FR", "cf-region": "Centre-Val de Loire",
         "cf-iplatitude": "48.4469", "cf-iplongitude": "1.4890"}


@pytest.fixture(autouse=True)
def fresh_live_file(tmp_path, monkeypatch):
    monkeypatch.setattr(live_service, "_LIVE_FILE", str(tmp_path / "live.json"))


def data(admin):
    return json.loads(admin.get("/admin/live.json").get_data(as_text=True))


def test_visitor_appears_without_location_and_with_masked_ip(make_app):
    app = make_app()
    app.test_client().get("/contact", headers=PARIS, environ_overrides={"REMOTE_ADDR": "86.218.162.249"})
    admin = login(app.test_client())
    d = data(admin)
    v = next(x for x in d["visitors"] if x["path"] == "/contact")
    assert not {"city", "country", "region", "lat", "lon", "device"} & set(v)  # même si Cloudflare envoie la ville
    assert v["masked"] == "86.218.x.x" and v["ip"] == "86.218.162.249"


def test_page_and_json_are_admin_only(make_app):
    app = make_app()
    anon = app.test_client()
    assert anon.get("/admin/live").status_code in (302, 401, 403)
    assert anon.get("/admin/live.json").status_code in (302, 401, 403)
    page = login(app.test_client()).get("/admin/live").get_data(as_text=True)
    assert "En direct" in page and "leaflet" not in page and "openstreetmap" not in page


def test_bots_and_admin_not_listed_and_old_visitors_forgotten(make_app, monkeypatch):
    app = make_app()
    app.test_client().get("/", headers={"User-Agent": "Googlebot/2.1"}, environ_overrides={"REMOTE_ADDR": "66.249.66.1"})
    admin = login(app.test_client())
    admin.get("/contact", headers=PARIS)
    assert all(v["ip"] != "66.249.66.1" for v in data(admin)["visitors"])
    app.test_client().get("/cgu", headers=PARIS, environ_overrides={"REMOTE_ADDR": "198.51.100.9"})
    assert any(v["path"] == "/cgu" for v in data(admin)["visitors"])
    real_time = live_service.time.time
    monkeypatch.setattr(live_service.time, "time", lambda: real_time() + 301)
    assert not any(v["path"] == "/cgu" for v in data(admin)["visitors"])


def test_block_from_live_page(make_app):
    app = make_app()
    app.test_client().get("/cgu", headers=PARIS, environ_overrides={"REMOTE_ADDR": "198.51.100.10"})
    admin = login(app.test_client())
    admin.post("/admin/blocked-ips/add", data={"csrf_token": csrf(admin, "/admin/live"), "ip": "198.51.100.10",
                                               "reason": "Depuis le direct", "hours": "0.5"})
    v = next(x for x in data(admin)["visitors"] if x["ip"] == "198.51.100.10")
    assert v["blocked"] is True
    with app.app_context():
        assert json_services.load_blocked_info()["198.51.100.10"]["reason"] == "Depuis le direct"


def test_ipv6_masking():
    assert live_service.mask_ip("2a01:cb00:1234:5678::1") == "2a01:cb00:x:x"
    assert live_service.mask_ip("pas une ip") == "?"
