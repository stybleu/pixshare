"""Réglages NudeNet dans l'admin, file « à vérifier » et bouton d'analyse (faux détecteur)."""
import io
import json
import sys
import types

import pytest
from PIL import Image

from conftest import csrf
from pixshare.services import json_services, nsfw_service, settings_service

from test_nsfw_moderation import (  # noqa: F401  (fixtures et helpers partagés)
    FakeDetector, GREEN, ORANGE, RED, fake_nudenet, image_bytes, only_record, upload,
)


@pytest.fixture
def admin(make_app):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    client = app.test_client()
    resp = client.post("/admin/login", data={"csrf_token": csrf(client), "username": "boss", "password": "s3cret-pass"})
    assert resp.status_code in {200, 302}
    return app, client


def post(client, url, **data):
    resp = client.post(url, data={"csrf_token": csrf(client), **data})
    resp.close()  # déclenche les tâches « après la réponse »
    return resp


def records(app):
    with app.app_context():
        return json_services.load_db()


def save_nsfw(client, **overrides):
    values = {"nsfw_auto_moderation": "1", "nsfw_tiling": "1",
              "nsfw_review_threshold": "0.60", "nsfw_block_threshold": "0.85"}
    values.update(overrides)
    return post(client, "/admin/settings/nsfw", **values)


# ------------------------------------------------------------------ page et enregistrement

def test_settings_page_shows_values_from_environment_by_default(admin):
    app, client = admin
    html = client.get("/admin/settings").get_data(as_text=True)
    assert "Modération automatique (NudeNet)" in html
    assert 'name="nsfw_review_threshold"' in html and 'value="0.60"' in html and 'value="0.85"' in html


def test_settings_are_saved_and_shown_again(admin):
    app, client = admin
    resp = save_nsfw(client, nsfw_review_threshold="0,5", nsfw_block_threshold="0.9", nsfw_tiling="0")
    assert resp.status_code == 302
    with app.app_context():
        stored = settings_service.load_settings()
        eff = nsfw_service.effective_settings()
    assert stored["nsfw_review_threshold"] == 0.5 and stored["nsfw_block_threshold"] == 0.9
    assert stored["nsfw_tiling"] is False
    assert eff["review_threshold"] == 0.5 and eff["block_threshold"] == 0.9 and eff["tiling"] is False
    html = client.get("/admin/settings").get_data(as_text=True)
    assert 'value="0.50"' in html and 'value="0.90"' in html


@pytest.mark.parametrize("review,block", [("abc", "0.85"), ("0.6", ""), ("0", "0.85"), ("0.6", "1.5"), ("0.9", "0.5"), ("nan", "0.85")])
def test_invalid_thresholds_are_refused_and_nothing_changes(admin, review, block):
    app, client = admin
    save_nsfw(client, nsfw_review_threshold="0.5", nsfw_block_threshold="0.9")
    resp = save_nsfw(client, nsfw_review_threshold=review, nsfw_block_threshold=block)
    assert resp.status_code == 302
    with app.app_context():
        stored = settings_service.load_settings()
    assert (stored["nsfw_review_threshold"], stored["nsfw_block_threshold"]) == (0.5, 0.9)


def test_nsfw_endpoints_need_admin_and_csrf(make_app):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    anonymous = app.test_client()
    for url in ("/admin/settings/nsfw", "/admin/moderation/run", "/admin/review/approve"):
        assert anonymous.post(url, data={"csrf_token": csrf(anonymous)}).status_code in {302, 401, 403}
    assert anonymous.get("/admin/review/whatever").status_code in {302, 401, 403, 404}


def test_csrf_is_required(admin):
    app, client = admin
    csrf(client)
    resp = client.post("/admin/settings/nsfw", data={"nsfw_review_threshold": "0.1", "nsfw_block_threshold": "0.2"})
    assert resp.status_code in {400, 403}
    with app.app_context():
        assert settings_service.load_settings()["nsfw_review_threshold"] is None


def test_other_settings_form_keeps_nsfw_values(admin):
    app, client = admin
    save_nsfw(client, nsfw_review_threshold="0.4", nsfw_block_threshold="0.7", nsfw_auto_moderation="0")
    post(client, "/admin/settings", upload_service_enabled="1", max_upload_size_mb="50", allow_permanent_files="1",
         default_lifetime_minutes="10", keep_thumbnails="1", thumbnail_retention_hours="24")
    with app.app_context():
        stored = settings_service.load_settings()
    assert stored["max_upload_size_mb"] == 50
    assert stored["nsfw_review_threshold"] == 0.4 and stored["nsfw_auto_moderation"] is False


def test_old_settings_file_without_nsfw_keys_still_loads(admin):
    app, client = admin
    with app.app_context():
        json_services.save_json("settings.json", {"max_upload_size_mb": 20})
        stored = settings_service.load_settings()
        eff = nsfw_service.effective_settings()
    assert stored["max_upload_size_mb"] == 20 and stored["nsfw_review_threshold"] is None
    assert eff["enabled"] is True and eff["review_threshold"] == 0.6 and eff["block_threshold"] == 0.85


# ------------------------------------------------------------------ effet sur les décisions

def test_lower_review_threshold_sends_more_images_to_review(admin):
    app, client = admin
    save_nsfw(client, nsfw_review_threshold="0.5", nsfw_block_threshold="0.6")  # orange = 0.70 -> supprimé
    upload(client, "x.png", image_bytes("PNG", [ORANGE]))
    _id, meta = only_record(app)
    assert meta["status"] == "deleted"


def test_higher_thresholds_publish_what_default_would_review(admin):
    app, client = admin
    save_nsfw(client, nsfw_review_threshold="0.8", nsfw_block_threshold="0.99")  # orange 0.70 -> publié, rouge 0.95 -> revue
    upload(client, "o.png", image_bytes("PNG", [ORANGE]))
    _id, meta = only_record(app)
    assert meta["status"] == "active"
    upload(client, "r.png", image_bytes("PNG", [RED]))
    decisions = {m["original_name"]: m for m in records(app).values()}
    assert decisions["r.png"]["moderation_decision"] == "manual_review"


def test_admin_can_disable_auto_moderation(admin):
    app, client = admin
    save_nsfw(client, nsfw_auto_moderation="0")
    upload(client, "a.png", image_bytes("PNG", [GREEN]))
    _id, meta = only_record(app)
    assert meta["status"] == "pending" and meta["moderation_decision"] == "pending"
    assert FakeDetector.calls == 0


def test_admin_setting_overrides_environment_flag(make_app):
    app = make_app(MODERATION_PENDING_IMAGES=True, NSFW_AUTO_MODERATION=False)
    client = app.test_client()
    client.post("/admin/login", data={"csrf_token": csrf(client), "username": "boss", "password": "s3cret-pass"})
    save_nsfw(client, nsfw_auto_moderation="1")
    upload(client, "a.png", image_bytes("PNG", [GREEN]))
    _id, meta = only_record(app)
    assert meta["status"] == "active"


def test_tiling_can_be_turned_off(admin):
    app, client = admin
    save_nsfw(client, nsfw_tiling="0")
    big = io.BytesIO()
    Image.new("RGB", (1600, 1200), GREEN).save(big, "PNG")
    upload(client, "big.png", big.getvalue())
    _id, meta = only_record(app)
    assert meta["status"] == "active"
    assert FakeDetector.calls == 1  # vue d'ensemble seulement (5 avec le découpage)


# ------------------------------------------------------------------ file « à vérifier »

def _review_image(admin):
    app, client = admin
    upload(client, "mid.png", image_bytes("PNG", [ORANGE]))
    file_id, meta = only_record(app)
    assert meta["moderation_decision"] == "manual_review"
    return app, client, file_id


def test_review_image_is_listed_with_actions_not_as_deleted(admin):
    app, client, file_id = _review_image(admin)
    html = client.get("/admin").get_data(as_text=True)
    assert "À vérifier" in html and "Approuver et publier" in html
    assert f"/admin/review/{file_id}" in html
    assert "Supprimé</span>" not in html.split(file_id)[1].split("</div>")[0]
    assert "1 image à vérifier" in html


def test_admin_can_preview_private_image_but_the_public_cannot(admin):
    app, client, file_id = _review_image(admin)
    resp = client.get(f"/admin/review/{file_id}")
    assert resp.status_code == 200 and resp.mimetype == "image/png"
    assert resp.headers["Cache-Control"] == "private, no-store"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    resp.close()
    anonymous = app.test_client()
    assert anonymous.get(f"/admin/review/{file_id}").status_code in {302, 401, 403, 404}
    assert anonymous.get(f"/view/{file_id}").status_code in {403, 404}


def test_preview_refuses_public_unknown_and_traversal_ids(admin):
    app, client = admin
    upload(client, "ok.png", image_bytes("PNG", [GREEN]))
    file_id, meta = only_record(app)
    assert meta["status"] == "active"
    assert client.get(f"/admin/review/{file_id}").status_code == 404  # déjà publique : pas d'aperçu admin dédié
    assert client.get("/admin/review/inconnu").status_code == 404
    assert client.get("/admin/review/..%2F..%2Fsettings.json").status_code == 404


def test_approve_publishes_the_image(admin):
    app, client, file_id = _review_image(admin)
    resp = post(client, "/admin/review/approve", file_id=file_id)
    assert resp.status_code == 302
    meta = records(app)[file_id]
    assert meta["status"] == "active" and meta["moderation_decision"] == "approved" and meta["moderation_detector"] == "admin"
    assert client.get(f"/view/{file_id}").status_code == 200


def test_approve_only_works_on_manual_review_images(admin):
    app, client = admin
    save_nsfw(client, nsfw_auto_moderation="0")
    upload(client, "a.png", image_bytes("PNG", [GREEN]))  # en attente d'analyse, pas en revue
    file_id, _meta = only_record(app)
    post(client, "/admin/review/approve", file_id=file_id)
    assert records(app)[file_id]["status"] == "pending"
    post(client, "/admin/review/approve", file_id="n-existe-pas")


def test_admin_can_delete_a_review_image_and_warn_the_author(admin):
    app, client, file_id = _review_image(admin)
    post(client, "/admin/delete", file_id=file_id, delete_reason="non_respect_cgu", notify_uploader="1")
    assert records(app)[file_id]["status"] == "deleted"
    with app.app_context():
        assert len(json_services.load_moderation_notices()) == 1


# ------------------------------------------------------------------ analyse à la demande

def test_run_now_analyses_waiting_images(admin):
    app, client = admin
    save_nsfw(client, nsfw_auto_moderation="0")
    upload(client, "a.png", image_bytes("PNG", [GREEN]))
    upload(client, "b.png", image_bytes("PNG", [RED]))
    assert {m["status"] for m in records(app).values()} == {"pending"}
    html = client.get("/admin/settings").get_data(as_text=True)
    assert "2 en attente d'analyse" in html

    save_nsfw(client, nsfw_auto_moderation="1")
    resp = post(client, "/admin/moderation/run")
    assert resp.status_code == 302
    states = sorted(m["status"] for m in records(app).values())
    assert states == ["active", "deleted"]


def test_run_now_does_nothing_when_disabled_or_empty(admin):
    app, client = admin
    save_nsfw(client, nsfw_auto_moderation="0")
    upload(client, "a.png", image_bytes("PNG", [GREEN]))
    post(client, "/admin/moderation/run")
    assert FakeDetector.calls == 0
    save_nsfw(client, nsfw_auto_moderation="1")
    post(client, "/admin/moderation/run")  # lance l'analyse
    FakeDetector.calls = 0
    post(client, "/admin/moderation/run")  # plus rien en attente
    assert FakeDetector.calls == 0


def test_status_flags_missing_nudenet(admin, monkeypatch):
    app, client = admin
    monkeypatch.setitem(sys.modules, "nudenet", None)
    monkeypatch.setattr(nsfw_service, "_detector", None)
    monkeypatch.setattr(nsfw_service.importlib.util, "find_spec", lambda name: None)
    assert "NudeNet non installé" in client.get("/admin/settings").get_data(as_text=True)
