"""Image supprimée par son auteur pendant la vérification : l'admin voit ce qu'en pense le filtre."""
import importlib.machinery
import io
import sys
import types

import numpy as np
import pytest
from PIL import Image

from conftest import csrf, login
from pixshare.services import json_services, nsfw_service


class FakeDetector:
    def detect(self, path):
        with Image.open(path) as im:
            r, g, _b = (int(v) for v in np.asarray(im.convert("RGB")).reshape(-1, 3).mean(axis=0))
        if r > 200 and g < 60:
            return [{"class": "FEMALE_GENITALIA_EXPOSED", "score": 0.95, "box": [0, 0, 1, 1]}]
        return [{"class": "FACE_FEMALE", "score": 0.99, "box": [0, 0, 1, 1]}]


@pytest.fixture
def nudenet(monkeypatch):
    module = types.ModuleType("nudenet")
    module.__spec__ = importlib.machinery.ModuleSpec("nudenet", None)
    module.NudeDetector = FakeDetector
    monkeypatch.setitem(sys.modules, "nudenet", module)
    monkeypatch.setattr(nsfw_service, "_detector", None)
    monkeypatch.setattr(nsfw_service, "_detector_failed", False)


def _app(make_app, monkeypatch):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    with app.app_context():
        from pixshare.services import settings_service
        s = settings_service.load_settings(); s["nsfw_auto_moderation"] = True; settings_service.save_settings(s)
    return app


def _upload_without_analysis(app, client, monkeypatch, color, name):
    # l'analyse automatique n'a pas encore eu lieu au moment où l'auteur supprime
    monkeypatch.setattr(nsfw_service, "run_auto_moderation", lambda limit=10: {})
    buf = io.BytesIO()
    Image.new("RGB", (40, 40), color).save(buf, "PNG")
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(buf.getvalue()), name)},
                content_type="multipart/form-data").close()
    with app.app_context():
        return next(fid for fid, m in json_services.load_db().items() if m["original_name"] == name)


def test_deleted_during_review_is_still_analysed(make_app, monkeypatch, nudenet):
    app = _app(make_app, monkeypatch)
    owner = app.test_client()
    bad = _upload_without_analysis(app, owner, monkeypatch, (250, 10, 10), "nu.png")
    good = _upload_without_analysis(app, owner, monkeypatch, (20, 120, 200), "chat.png")
    for file_id in (bad, good):
        owner.post(f"/delete/{file_id}", data={"csrf_token": csrf(owner)}).close()
    with app.app_context():
        db = json_services.load_db()
    assert db[bad]["status"] == "deleted" and db[bad]["status_before_delete"] == "pending"
    assert db[bad]["late_check"] == "reject" and db[bad]["late_check_label"] == "FEMALE_GENITALIA_EXPOSED"
    assert db[good]["late_check"] == "ok"
    assert not list(__import__("os").scandir(nsfw_service.late_check_dir()))  # copies effacées

    page = login(app.test_client()).get("/admin").get_data(as_text=True)
    assert "pendant la vérification" in page and "aurait été supprimée" in page and "rien de suspect" in page
    thumbs = login(app.test_client()).get("/admin/thumbnails").get_data(as_text=True)
    assert "dont 2 pendant la vérification" in thumbs


def test_banned_after_late_check(make_app, monkeypatch, nudenet):
    app = _app(make_app, monkeypatch)
    owner = app.test_client()
    bad = _upload_without_analysis(app, owner, monkeypatch, (250, 10, 10), "nu.png")
    owner.post(f"/delete/{bad}", data={"csrf_token": csrf(owner)}).close()
    buf = io.BytesIO()
    Image.new("RGB", (40, 40), (250, 10, 10)).save(buf, "PNG")
    resp = owner.post("/", data={"csrf_token": csrf(owner), "file": (io.BytesIO(buf.getvalue()), "retour.png")},
                      content_type="multipart/form-data")
    resp.close()
    with app.app_context():
        names = [m["original_name"] for m in json_services.load_db().values() if m.get("status") in ("active", "pending")]
    assert "retour.png" not in names  # renvoi refusé (empreinte)


def test_without_nudenet_it_says_never_analysed(make_app):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    owner = app.test_client()
    buf = io.BytesIO()
    Image.new("RGB", (40, 40), (1, 2, 3)).save(buf, "PNG")
    owner.post("/", data={"csrf_token": csrf(owner), "file": (io.BytesIO(buf.getvalue()), "a.png")},
               content_type="multipart/form-data").close()
    with app.app_context():
        db = json_services.load_db()
        file_id, meta = next(iter(db.items()))
        meta.update(status="pending", moderation_decision="pending")
        json_services.save_db(db)
    owner.post(f"/delete/{file_id}", data={"csrf_token": csrf(owner)}).close()
    page = login(app.test_client()).get("/admin").get_data(as_text=True)
    assert "pendant la vérification" in page and "jamais analysée" in page
