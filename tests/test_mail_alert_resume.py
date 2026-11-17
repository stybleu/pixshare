"""Alerte mail « image à vérifier » : jamais perdue au redémarrage, réessayée en cas d'échec, sans doublon."""
import io
import os
import time

from PIL import Image

from conftest import csrf, login
from pixshare.services import json_services, mail_service


def _setup(make_app, monkeypatch, ok=True):
    monkeypatch.setenv("MAIL_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("MAIL_TO", "admin@example.test")
    monkeypatch.setattr(mail_service, "DELAY", 0.2)
    monkeypatch.setattr(mail_service, "RETRY_DELAY", 0.2)
    monkeypatch.setattr(mail_service, "_timer", None)
    monkeypatch.setattr(mail_service, "_last_sent", None)
    sent = []

    def fake(subject, body, html=None, images=None, cfg=None):
        sent.append(subject)
        return (True, "") if ok else (False, "SMTPAuthenticationError: refusé")

    monkeypatch.setattr(mail_service, "send_mail_now", fake)
    app = make_app(MODERATION_PENDING_IMAGES=True)
    client = app.test_client()
    buf = io.BytesIO()
    Image.new("RGB", (9, 9)).save(buf, "PNG")
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(buf.getvalue()), "a.png")},
                content_type="multipart/form-data")
    return app, sent


def _review(app):
    from pixshare.services.moderation_service import mark_image_for_review
    with app.app_context():
        db = json_services.load_db()
        file_id, meta = next(iter(db.items()))
        mark_image_for_review(db, file_id, meta, "nudenet", 0.7, "FEMALE_BREAST_EXPOSED")


def test_alert_sent_once_even_with_restart(make_app, monkeypatch):
    app, sent = _setup(make_app, monkeypatch)
    _review(app)
    time.sleep(0.6)
    assert sent == ["PixShare : 1 image à vérifier"]
    mail_service.resume_pending_alert(app)  # redémarrage : déjà annoncée, pas de doublon
    time.sleep(0.5)
    assert len(sent) == 1


def test_lost_alert_is_resent_after_restart(make_app, monkeypatch):
    app, sent = _setup(make_app, monkeypatch)
    monkeypatch.setattr(mail_service, "notify_review", lambda: None)  # le mail prévu est « perdu » (worker arrêté)
    _review(app)
    time.sleep(0.4)
    assert sent == []
    mail_service.resume_pending_alert(app)
    time.sleep(0.5)
    assert sent == ["PixShare : 1 image à vérifier"]


def test_failed_alert_is_retried_and_shown_in_admin(make_app, monkeypatch):
    app, sent = _setup(make_app, monkeypatch, ok=False)
    _review(app)
    time.sleep(1.2)
    assert len(sent) == 3  # 1 envoi + 2 nouveaux essais
    page = login(app.test_client()).get("/admin/settings").get_data(as_text=True)
    assert "Dernier échec" in page and "SMTPAuthenticationError" in page and "pas encore annoncée" in page
