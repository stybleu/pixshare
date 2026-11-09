"""Blocage manuel d'IP : le formulaire est dans l'onglet « IP bloquées », plus dans « Fichiers »."""
import io

import pytest

from conftest import csrf
from pixshare.services import json_services


@pytest.fixture
def admin(make_app):
    app = make_app()
    client = app.test_client()
    client.post("/admin/login", data={"csrf_token": csrf(client), "username": "boss", "password": "s3cret-pass"})
    return app, client


def blocked(app):
    with app.app_context():
        return json_services.load_blocked()


def add(client, ip):
    return client.post("/admin/blocked-ips/add", data={"csrf_token": csrf(client), "ip": ip})


def test_manual_form_lives_in_the_ip_tab_not_in_files(admin):
    _app, client = admin
    ips = client.get("/admin/blocked-ips").get_data(as_text=True)
    files = client.get("/admin").get_data(as_text=True)
    assert "Bloquer une IP manuellement" in ips and "/admin/blocked-ips/add" in ips
    assert "Bloquer une IP manuellement" not in files
    assert 'action="/admin/block"' not in files.split("Banque de fichiers")[0]


def test_empty_list_still_shows_the_form(admin):
    _app, client = admin
    html = client.get("/admin/blocked-ips").get_data(as_text=True)
    assert "Aucune IP bloquée" in html and "Bloquer une IP manuellement" in html


@pytest.mark.parametrize("typed,stored", [
    ("82.64.12.34", "82.64.12.34"),
    ("  82.64.12.34 \n", "82.64.12.34"),
    ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
])
def test_valid_ip_is_blocked_and_shown(admin, typed, stored):
    app, client = admin
    resp = add(client, typed)
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/admin/blocked-ips")
    assert blocked(app) == [stored]
    assert stored in client.get("/admin/blocked-ips").get_data(as_text=True)


@pytest.mark.parametrize("bad", ["", "abc", "999.1.1.1", "1.2.3", "1.2.3.4, 5.6.7.8", "<script>", "82.64.12.34/24"])
def test_invalid_ip_is_refused(admin, bad):
    app, client = admin
    resp = add(client, bad)
    assert resp.status_code == 302
    assert blocked(app) == []


def test_same_ip_twice_is_stored_once(admin):
    app, client = admin
    add(client, "1.2.3.4")
    add(client, "1.2.3.4")
    assert blocked(app) == ["1.2.3.4"]


def test_blocked_ip_cannot_reach_the_upload_page(admin):
    app, client = admin
    visitor = app.test_client()
    assert visitor.get("/").status_code == 200
    add(client, "127.0.0.1")
    resp = visitor.get("/")
    assert resp.status_code == 302 and "google" in resp.headers["Location"]


def test_endpoint_needs_admin_and_csrf(admin):
    app, client = admin
    anonymous = app.test_client()
    assert anonymous.post("/admin/blocked-ips/add", data={"csrf_token": csrf(anonymous), "ip": "1.2.3.4"}).status_code in {302, 401, 403}
    csrf(client)
    assert client.post("/admin/blocked-ips/add", data={"ip": "1.2.3.4"}).status_code in {400, 403}
    assert blocked(app) == []


def test_per_file_block_button_still_works(admin):
    app, client = admin
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(b"x" * 10), "a.mp4")}, content_type="multipart/form-data")
    html = client.get("/admin").get_data(as_text=True)
    assert 'action="/admin/block"' in html
    client.post("/admin/block", data={"csrf_token": csrf(client), "ip": "9.9.9.9"})
    assert blocked(app) == ["9.9.9.9"]
