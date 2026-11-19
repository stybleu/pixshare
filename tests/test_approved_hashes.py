"""Images déjà acceptées : le même fichier renvoyé est publié sans nouvelle analyse, avec garde-fous."""
from datetime import datetime, timedelta, timezone

import pytest

from conftest import csrf, login
from pixshare.services import approved_hash_service as approved
from pixshare.services import json_services
from test_accounts import mails, member  # noqa: F401
from test_nsfw_moderation import GREEN, ORANGE, FakeDetector, fake_nudenet, image_bytes, upload  # noqa: F401

PHOTO = image_bytes("PNG", [GREEN])


@pytest.fixture
def app(make_app):
    return make_app(MODERATION_PENDING_IMAGES=True)


def files(app):
    with app.app_context():
        return sorted(json_services.load_db().values(), key=lambda m: m.get("created_at", ""))


def settings(app, **values):
    from pixshare.services import settings_service
    with app.app_context():
        s = settings_service.load_settings()
        s.update(values)
        settings_service.save_settings(s)


def test_same_file_is_published_without_new_analysis(app):
    client = app.test_client()
    upload(client, "a.png", PHOTO)
    calls = FakeDetector.calls
    assert calls >= 1 and files(app)[0]["status"] == "active"
    upload(app.test_client(), "b.png", PHOTO)                     # autre personne, même fichier
    assert FakeDetector.calls == calls                            # aucune analyse
    second = files(app)[1]
    assert second["status"] == "active" and second["moderation_cached"] is True
    with app.app_context():
        assert json_services.load_json("nsfw_stats.json", {})["hash_approved"] == 1
        assert approved.count() == 1


def test_a_single_changed_pixel_is_analysed_again(app):
    upload(app.test_client(), "a.png", PHOTO)
    calls = FakeDetector.calls
    from PIL import Image
    import io
    im = Image.open(io.BytesIO(PHOTO)).convert("RGB")
    im.putpixel((0, 0), (0, 0, 0))
    buf = io.BytesIO()
    im.save(buf, "PNG")
    upload(app.test_client(), "b.png", buf.getvalue())
    assert FakeDetector.calls > calls


def test_changing_the_filter_settings_forgets_old_acceptances(app):
    upload(app.test_client(), "a.png", PHOTO)
    calls = FakeDetector.calls
    settings(app, nsfw_review_threshold=0.5)
    upload(app.test_client(), "b.png", PHOTO)
    assert FakeDetector.calls > calls                             # réanalysée avec les nouveaux réglages
    with app.app_context():
        assert approved.count() == 1                               # l'ancienne acceptation a été effacée


def test_members_and_visitors_are_separate(app, mails):
    user = member(app.test_client(), mails)
    upload(user, "a.png", PHOTO)
    calls = FakeDetector.calls
    upload(app.test_client(), "b.png", PHOTO)                     # visiteur : le filtre est plus strict
    assert FakeDetector.calls > calls


def test_doubtful_images_are_never_remembered(app):
    login(app.test_client()).get("/admin")                        # admin présent : l'image l'attend
    upload(app.test_client(), "a.png", image_bytes("PNG", [ORANGE]))
    with app.app_context():
        assert approved.count() == 0


def test_admin_deletion_and_reports_forget_the_image(app):
    upload(app.test_client(), "a.png", PHOTO)
    file_id = next(iter(json_services_ids(app)))
    admin = login(app.test_client())
    admin.post("/admin/delete", data={"csrf_token": csrf(admin, "/admin"), "file_id": file_id,
                                      "delete_reason": "admin_delete"})
    with app.app_context():
        assert approved.count() == 0
    calls = FakeDetector.calls
    upload(app.test_client(), "b.png", PHOTO)
    assert FakeDetector.calls > calls                             # réanalysée
    with app.app_context():
        from pixshare.services.moderation_service import mark_image_for_review
        db = json_services.load_db()
        fid, meta = [(k, v) for k, v in db.items() if v["status"] == "active"][0]
        assert approved.count() == 1
        mark_image_for_review(db, fid, meta, "signalement", None, "signalement")  # signalée par des visiteurs
        assert approved.count() == 0


def json_services_ids(app):
    with app.app_context():
        return list(json_services.load_db())


def test_the_memory_stays_small(app, monkeypatch):
    monkeypatch.setattr(approved, "MAX_ENTRIES", 3)
    with app.app_context():
        for i in range(10):
            approved.remember(f"{i:064x}", False, "fp1", 0.1)
        assert approved.count() == 3
        assert approved.known(f"{9:064x}", False, "fp1")         # les plus récentes sont gardées
        assert not approved.known(f"{0:064x}", False, "fp1")
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat(timespec="seconds")
        from pixshare.services import sqlite_store
        sqlite_store.approved_put(json_services._get_data_dir(), "visiteur:" + "f" * 64, "fp1", 0, old, "visiteur:", 100)
        assert approved.purge_old() >= 1                          # 6 mois sans resservir : effacée


def test_admin_sees_and_can_clear_the_memory(app):
    upload(app.test_client(), "a.png", PHOTO)
    admin = login(app.test_client())
    page = admin.get("/admin/settings").get_data(as_text=True)
    assert "Images déjà acceptées en mémoire : <strong>1</strong>" in page
    admin.post("/admin/nudenet/memoire", data={"csrf_token": csrf(admin, "/admin/settings")})
    with app.app_context():
        assert approved.count() == 0
    assert app.test_client().post("/admin/nudenet/memoire").status_code in (302, 400, 403)


def test_json_fallback(make_app, monkeypatch):
    monkeypatch.setenv("PIXSHARE_STORAGE", "json")
    app = make_app(MODERATION_PENDING_IMAGES=True)
    upload(app.test_client(), "a.png", PHOTO)
    calls = FakeDetector.calls
    upload(app.test_client(), "b.png", PHOTO)
    assert FakeDetector.calls == calls
