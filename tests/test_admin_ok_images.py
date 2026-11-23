"""« Cette photo est bonne » : une fausse alerte de NudeNet validée par l'admin est mémorisée."""
import io

import pytest
from PIL import Image, ImageDraw

from conftest import csrf, login
from pixshare.services import json_services
from test_nsfw_moderation import FakeDetector, fake_nudenet, upload  # noqa: F401

ORANGE = (230, 110, 10)


def photo(size=(240, 160), fmt="JPEG"):
    """Photo « à vérifier » pour la fausse détection (orange à 60 %), avec assez de détails pour une empreinte visuelle."""
    im = Image.new("RGB", (240, 160), ORANGE)
    d = ImageDraw.Draw(im)
    for i in range(6):
        d.rectangle([150 + i * 15, 0, 157 + i * 15, 160], fill=(30 + i * 30, 60, 200 - i * 25))
    d.ellipse([20, 30, 80, 90], fill=(250, 240, 200))
    im = im.resize(size)
    buf = io.BytesIO()
    im.save(buf, fmt, quality=90)
    return buf.getvalue()


@pytest.fixture
def app(make_app):
    return make_app(MODERATION_PENDING_IMAGES=True)


def by_name(app, name):
    with app.app_context():
        return next((k, m) for k, m in json_services.load_db().items() if m.get("original_name") == name)


def approve(admin, file_id):
    return admin.post("/admin/review/approve", data={"csrf_token": csrf(admin, "/admin"), "file_id": file_id})


def test_admin_approval_is_remembered_and_same_photo_passes(app):
    upload(app.test_client(), "plage.jpg", photo())
    fid, meta = by_name(app, "plage.jpg")
    assert meta["status"] == "pending"                                  # fausse alerte : à vérifier
    admin = login(app.test_client())
    approve(admin, fid)
    page = admin.get("/admin/blocked-ips").get_data(as_text=True)
    assert "Photos validées par toi (1)" in page and "plage.jpg" in page

    calls = FakeDetector.calls
    upload(app.test_client(), "plage-encore.jpg", photo())             # même fichier, autre personne
    _, again = by_name(app, "plage-encore.jpg")
    assert again["status"] == "active" and again["moderation_admin_ok"] == "exact"
    assert FakeDetector.calls == calls                                  # pas de nouvelle analyse


def test_close_copy_passes_when_nudenet_hesitates(app):
    upload(app.test_client(), "plage.jpg", photo())
    fid, _ = by_name(app, "plage.jpg")
    approve(login(app.test_client()), fid)
    upload(app.test_client(), "copie.jpg", photo(size=(180, 120)))     # redimensionnée = autre fichier
    _, copy = by_name(app, "copie.jpg")
    assert copy["status"] == "active" and copy["moderation_admin_ok"] == "similar"


def test_unrelated_photo_is_still_checked(app):
    upload(app.test_client(), "plage.jpg", photo())
    fid, _ = by_name(app, "plage.jpg")
    approve(login(app.test_client()), fid)
    other = Image.new("RGB", (240, 160), ORANGE)
    ImageDraw.Draw(other).rectangle([0, 100, 240, 160], fill=(10, 10, 10))
    buf = io.BytesIO()
    other.save(buf, "JPEG")
    upload(app.test_client(), "autre.jpg", buf.getvalue())
    _, meta = by_name(app, "autre.jpg")
    assert meta["status"] == "pending"                                 # rien à voir : toujours vérifiée


def test_forget_and_ban_win(app):
    upload(app.test_client(), "plage.jpg", photo())
    fid, _ = by_name(app, "plage.jpg")
    admin = login(app.test_client())
    approve(admin, fid)
    from pixshare.services import admin_ok_service
    with app.app_context():
        sha = admin_ok_service.list_ok()[0]["sha256"]
    admin.post("/admin/ok-images/remove", data={"csrf_token": csrf(admin, "/admin/blocked-ips"), "sha256": sha})
    with app.app_context():
        assert admin_ok_service.count() == 0

    upload(app.test_client(), "plage2.jpg", photo())                   # plus mémorisée : de nouveau à vérifier
    fid2, meta2 = by_name(app, "plage2.jpg")
    assert meta2["status"] == "pending"
    approve(admin, fid2)
    with app.app_context():
        assert admin_ok_service.count() == 1
        from flask import current_app
        import os
        from pixshare.services.image_ban_service import ban_file
        path = os.path.join(current_app.config["UPLOAD_FOLDER"], meta2["server_name"])
        ban_file(path, "non_respect_cgu", file_id=fid2)                # l'admin l'interdit finalement
        assert admin_ok_service.count() == 0                           # l'interdiction gagne
