"""Anti-robots Turnstile : inactif sans clés ; actif, il bloque les envois sans jeton valide."""
import io

import pytest
from PIL import Image

from conftest import csrf, login
from pixshare.services import json_services, turnstile_service


def png():
    buf = io.BytesIO()
    Image.new("RGB", (10, 10), "blue").save(buf, "PNG")
    return buf.getvalue()


def send(client, **extra):
    data = {"csrf_token": csrf(client), "file": (io.BytesIO(png()), "a.png"), **extra}
    return client.post("/", data=data, content_type="multipart/form-data")


def count(app):
    with app.app_context():
        return len(json_services.load_db())


class Answer:
    def __init__(self, ok):
        self.ok = ok

    def json(self):
        return {"success": self.ok}


@pytest.fixture
def keys(monkeypatch):
    monkeypatch.setenv("TURNSTILE_SITE_KEY", "1x00000000000000000000AA")
    monkeypatch.setenv("TURNSTILE_SECRET_KEY", "secret")


def test_without_keys_nothing_changes(make_app):
    app = make_app(NSFW_AUTO_MODERATION=False)
    client = app.test_client()
    assert "cf-turnstile" not in client.get("/").get_data(as_text=True)
    send(client)
    assert count(app) == 1


def test_widget_shown_and_upload_without_token_refused(make_app, keys):
    app = make_app(NSFW_AUTO_MODERATION=False)
    client = app.test_client()
    html = client.get("/").get_data(as_text=True)
    assert 'class="cf-turnstile' in html and "challenges.cloudflare.com" in client.get("/").headers["Content-Security-Policy"]
    send(client)
    assert count(app) == 0


def test_valid_token_accepted_invalid_refused(make_app, keys, monkeypatch):
    app = make_app(NSFW_AUTO_MODERATION=False)
    client = app.test_client()
    monkeypatch.setattr(turnstile_service.requests, "post", lambda *a, **k: Answer(False))
    send(client, **{"cf-turnstile-response": "faux"})
    assert count(app) == 0
    monkeypatch.setattr(turnstile_service.requests, "post", lambda *a, **k: Answer(True))
    send(client, **{"cf-turnstile-response": "bon"})
    assert count(app) == 1


def test_cloudflare_down_does_not_break_the_site(make_app, keys, monkeypatch):
    app = make_app(NSFW_AUTO_MODERATION=False)
    client = app.test_client()

    def down(*a, **k):
        raise turnstile_service.requests.ConnectionError("panne")

    monkeypatch.setattr(turnstile_service.requests, "post", down)
    send(client, **{"cf-turnstile-response": "jeton"})
    assert count(app) == 1


def test_admin_is_never_asked(make_app, keys):
    app = make_app(NSFW_AUTO_MODERATION=False)
    client = login(app.test_client())
    assert "cf-turnstile" not in client.get("/").get_data(as_text=True)
    send(client)
    assert count(app) == 1


def test_contact_needs_token(make_app, keys):
    app = make_app()
    client = app.test_client()
    assert 'class="cf-turnstile' in client.get("/contact").get_data(as_text=True)
    client.post("/contact", data={"csrf_token": csrf(client, "/contact"), "type": "contact", "name": "x",
                                  "email": "", "subject": "s", "message": "bonjour"})
    with app.app_context():
        assert json_services.load_contacts() == []
def test_contact_saved_without_keys(make_app):
    app = make_app(); client = app.test_client()
    client.post("/contact", data={"csrf_token": csrf(client, "/contact"), "type": "contact", "name": "x", "email": "", "subject": "s", "message": "bonjour"})
    with app.app_context(): assert len(json_services.load_contacts()) == 1
