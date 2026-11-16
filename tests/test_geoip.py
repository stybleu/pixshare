"""Géolocalisation par la base DB-IP quand Cloudflare n'envoie pas la position."""
import gzip
import io
import os

import pytest

from conftest import login
from pixshare.services import geoip_service, live_service

FIREFOX = "Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36"


class FakeReader:
    def get(self, ip):
        if ip == "86.218.162.249":
            return {"city": {"names": {"en": "Chartres", "fr": "Chartres"}},
                    "subdivisions": [{"names": {"fr": "Centre-Val de Loire"}}],
                    "country": {"iso_code": "FR"}, "location": {"latitude": 48.44, "longitude": 1.49}}
        return None


@pytest.fixture
def fake_db(monkeypatch, tmp_path):
    monkeypatch.setattr(live_service, "_LIVE_FILE", str(tmp_path / "live.json"))
    monkeypatch.setattr(geoip_service, "_get_reader", lambda: FakeReader())
    geoip_service._lookup.cache_clear()
    yield
    geoip_service._lookup.cache_clear()


def test_live_page_uses_dbip_without_cloudflare_headers(make_app, fake_db):
    app = make_app()
    app.test_client().get("/cgu", headers={"User-Agent": FIREFOX}, environ_overrides={"REMOTE_ADDR": "86.218.162.249"})
    admin = login(app.test_client())
    v = next(x for x in admin.get("/admin/live.json").get_json()["visitors"] if x["path"] == "/cgu")
    assert (v["city"], v["region"], v["country"], v["lat"], v["lon"]) == ("Chartres", "Centre-Val de Loire", "FR", 48.44, 1.49)
    page = admin.get("/admin/live").get_data(as_text=True)
    assert "IP Geolocation by DB-IP" in page


def test_private_or_unknown_ips_are_not_located(fake_db):
    assert geoip_service.locate("10.24.198.38") is None
    assert geoip_service.locate("127.0.0.1") is None
    assert geoip_service.locate("pas une ip") is None


def test_disabled_with_variable(fake_db, monkeypatch):
    monkeypatch.setenv("GEOIP", "0")
    assert geoip_service.locate("86.218.162.249") is None


class FakeResponse:
    def __init__(self, status, body=b""):
        self.status_code = status
        self.raw = io.BytesIO(body)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_download_falls_back_to_previous_month(make_app, monkeypatch):
    import requests

    app = make_app()
    payload = gzip.compress(b"x" * 2_000_000)
    calls = []

    def fake_get(url, **kw):
        calls.append(url)
        return FakeResponse(404) if len(calls) == 1 else FakeResponse(200, payload)

    monkeypatch.setattr(requests, "get", fake_get)
    with app.app_context():
        assert geoip_service.download(force=True)
        assert os.path.getsize(geoip_service.db_path()) == 2_000_000
        assert geoip_service.status()["state"] == "ok"
    assert len(calls) == 2 and calls[0] != calls[1]


def test_months_to_try_handles_january():
    from datetime import date
    assert geoip_service._months_to_try(date(2027, 1, 5)) == ["2027-01", "2026-12"]
