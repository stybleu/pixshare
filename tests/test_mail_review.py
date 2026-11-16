"""Modérer depuis le mail : aperçu dans le mail, liens signés, page de confirmation sans connexion."""
import re
import time

import pytest

from conftest import csrf
from pixshare.services import json_services, mail_service, review_link_service
from test_nsfw_admin import _review_image, admin, upload  # noqa: F401
from test_nsfw_moderation import ORANGE, fake_nudenet, image_bytes  # noqa: F401

sent = []


class FakeSMTP:
    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        pass

    def login(self, u, p):
        pass

    def send_message(self, msg):
        sent.append(msg)


@pytest.fixture
def mail(monkeypatch):
    sent.clear()
    monkeypatch.setenv("MAIL_SMTP_HOST", "smtp.example.org")
    monkeypatch.setenv("MAIL_TO", "moi@example.org")
    monkeypatch.setenv("MAIL_SITE_URL", "http://localhost")
    monkeypatch.setattr(mail_service.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(mail_service, "DELAY", 0.05)
    monkeypatch.setattr(mail_service, "MIN_INTERVAL", 0.05)
    monkeypatch.setattr(mail_service, "_last_sent", None)
    monkeypatch.setattr(mail_service, "_timer", None)


def wait_mail():
    for _ in range(100):
        if sent:
            return sent[-1]
        time.sleep(0.02)
    raise AssertionError("aucun mail envoyé")


def links(msg):
    html = msg.get_body(("html",)).get_content()
    return html, re.findall(r'href="http://localhost(/moderation/[^"?]+)\?a=(approve|delete)"', html)


def test_mail_has_preview_and_buttons(mail, admin):
    app, client, file_id = _review_image(admin)
    msg = wait_mail()
    html, found = links(msg)
    assert {a for _p, a in found} == {"approve", "delete"} and 'src="cid:pixshare-review-0"' in html
    assert any(part.get_content_type() == "image/jpeg" for part in msg.walk())


def test_link_shows_page_but_acts_only_after_confirmation(mail, admin):
    app, client, file_id = _review_image(admin)
    _html, found = links(wait_mail())
    path = found[0][0]
    outsider = app.test_client()  # pas connecté en admin
    page = outsider.get(path + "?a=approve")
    assert page.status_code == 200 and "Confirmer" in page.get_data(as_text=True)
    assert outsider.get(path + "/image").status_code == 200
    with app.app_context():
        assert json_services.load_db()[file_id]["status"] == "pending"  # un simple clic (ou un robot) ne décide rien
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    done = outsider.post(path, data={"csrf_token": token, "action": "approve"})
    assert "approuvée" in done.get_data(as_text=True)
    with app.app_context():
        assert json_services.load_db()[file_id]["status"] == "active"
    again = outsider.get(path).get_data(as_text=True)
    assert "déjà été traitée" in again
    assert outsider.get(path + "/image").status_code == 404


def test_delete_with_block_from_mail(mail, admin):
    app, client, file_id = _review_image(admin)
    with app.app_context():
        db = json_services.load_db()
        db[file_id].update(ip="203.0.113.9", by_admin=False)
        json_services.save_db(db)
    path = links(wait_mail())[1][0][0]
    outsider = app.test_client()
    token = csrf(outsider, path)
    outsider.post(path, data={"csrf_token": token, "action": "delete", "notify": "1", "block": "1", "hours": "168"})
    with app.app_context():
        assert json_services.load_db()[file_id]["status"] == "deleted"
        assert "203.0.113.9" in json_services.load_blocked()


def test_forged_or_expired_links_are_refused(admin, monkeypatch):
    app, client, file_id = _review_image(admin)
    outsider = app.test_client()
    assert "Lien invalide" in outsider.get("/moderation/faux-jeton").get_data(as_text=True)
    assert outsider.get("/moderation/faux-jeton/image").status_code == 404
    with app.app_context():
        token = review_link_service.make_token(file_id)
    monkeypatch.setattr(review_link_service, "MAX_AGE", -1)
    assert "expiré" in outsider.get(f"/moderation/{token}").get_data(as_text=True)


def test_blurred_or_no_image_options(admin, monkeypatch):
    app, client, file_id = _review_image(admin)
    with app.app_context():
        meta = json_services.load_db()[file_id]
        assert review_link_service.mail_thumbnail(meta, "net") and review_link_service.mail_thumbnail(meta, "flou")
        assert review_link_service.mail_thumbnail(meta, "aucune") is None
