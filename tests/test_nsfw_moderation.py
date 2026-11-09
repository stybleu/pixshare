"""NudeNet intégré au site : décision automatique des images en attente (faux détecteur par couleur)."""
import io
import sys
import types

import numpy as np
import pytest
from PIL import Image

from conftest import csrf
from pixshare.services import json_services, nsfw_service

GREEN, RED, ORANGE = (20, 160, 40), (230, 20, 20), (230, 110, 10)


class FakeDetector:
    """Explicite (0.95) si >= 40 % de pixels rouge vif ; 0.70 si >= 40 % d'orange ; sinon un simple visage.
    Compte les appels (= nombre de vues analysées)."""

    calls = 0

    def detect(self, path):
        FakeDetector.calls += 1
        with Image.open(path) as im:
            arr = np.asarray(im.convert("RGB").resize((64, 64)), dtype=int)
        r, g = arr[..., 0], arr[..., 1]
        red = ((r > 200) & (g < 60)).mean()
        orange = ((r > 200) & (g >= 60) & (g < 160)).mean()
        if red >= 0.4:
            return [{"class": "FEMALE_BREAST_EXPOSED", "score": 0.95, "box": [0, 0, 1, 1]}]
        if orange >= 0.4:
            return [{"class": "BUTTOCKS_EXPOSED", "score": 0.70, "box": [0, 0, 1, 1]}]
        return [{"class": "FACE_FEMALE", "score": 0.99, "box": [0, 0, 1, 1]}]


@pytest.fixture(autouse=True)
def fake_nudenet(monkeypatch):
    module = types.ModuleType("nudenet")
    module.NudeDetector = FakeDetector
    monkeypatch.setitem(sys.modules, "nudenet", module)
    monkeypatch.setattr(nsfw_service, "_detector", None)
    monkeypatch.setattr(nsfw_service, "_detector_failed", False)
    FakeDetector.calls = 0


def image_bytes(fmt, colors, **kw):
    frames = [Image.new("RGB", (40, 40), c) for c in colors]
    buf = io.BytesIO()
    if len(frames) > 1:
        frames[0].save(buf, fmt, save_all=True, append_images=frames[1:], **kw)
    else:
        frames[0].save(buf, fmt, **kw)
    return buf.getvalue()


@pytest.fixture
def moderated(make_app):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    return app, app.test_client()


def upload(client, name, data):
    resp = client.post(
        "/",
        data={"csrf_token": csrf(client), "file": (io.BytesIO(data), name)},
        content_type="multipart/form-data",
    )
    resp.close()  # déclenche l'analyse « après la réponse », comme le ferait le serveur WSGI
    return resp


def only_record(app):
    with app.app_context():
        db = json_services.load_db()
    assert len(db) == 1
    return next(iter(db.items()))


def test_safe_image_is_published_after_upload(moderated):
    app, client = moderated
    upload(client, "a.png", image_bytes("PNG", [GREEN]))
    _id, meta = only_record(app)
    assert meta["status"] == "active"
    assert meta["moderation_decision"] == "approved"
    assert meta["moderation_detector"] == "nudenet-3.4.2"


def test_explicit_image_is_deleted_and_author_is_warned(moderated):
    app, client = moderated
    upload(client, "bad.png", image_bytes("PNG", [RED]))
    _id, meta = only_record(app)
    assert meta["status"] == "deleted"
    with app.app_context():
        notices = json_services.load_moderation_notices()
    assert len(notices) == 1 and notices[0]["reason"] == "non_respect_cgu"


def test_borderline_image_goes_to_manual_review_and_stays_private(moderated):
    app, client = moderated
    upload(client, "mid.png", image_bytes("PNG", [ORANGE]))
    _id, meta = only_record(app)
    assert meta["status"] == "pending"
    assert meta["moderation_decision"] == "manual_review"
    assert client.get(f"/view/{_id}").status_code in {403, 404}


@pytest.mark.parametrize("name,fmt,kw", [
    ("anim.gif", "GIF", {"duration": 100, "loop": 0}),
    ("anim.apng", "PNG", {"duration": 100}),
    ("anim.webp", "WEBP", {"duration": 100}),
])
def test_explicit_frame_hidden_after_a_clean_first_frame_is_caught(moderated, name, fmt, kw):
    app, client = moderated
    upload(client, name, image_bytes(fmt, [GREEN, GREEN, RED], **kw))
    _id, meta = only_record(app)
    assert meta["status"] == "deleted"


@pytest.mark.parametrize("name,fmt", [("a.tif", "TIFF"), ("a.bmp", "BMP"), ("a.jfif", "JPEG"), ("a.jpe", "JPEG")])
def test_other_formats_are_analysed_too(moderated, name, fmt):
    app, client = moderated
    upload(client, name, image_bytes(fmt, [GREEN]))
    _id, meta = only_record(app)
    assert meta["status"] == "active"
    assert FakeDetector.calls == 1


def test_without_nudenet_images_stay_pending(moderated, monkeypatch):
    app, client = moderated
    monkeypatch.setitem(sys.modules, "nudenet", None)  # import impossible
    upload(client, "a.png", image_bytes("PNG", [GREEN]))
    _id, meta = only_record(app)
    assert meta["status"] == "pending" and meta["moderation_decision"] == "pending"


def test_disabled_by_config_leaves_images_pending(make_app):
    app = make_app(MODERATION_PENDING_IMAGES=True, NSFW_AUTO_MODERATION=False)
    client = app.test_client()
    upload(client, "a.png", image_bytes("PNG", [GREEN]))
    _id, meta = only_record(app)
    assert meta["status"] == "pending"
    assert FakeDetector.calls == 0


def test_unreadable_image_goes_to_review_after_three_failures(moderated):
    app, client = moderated
    upload(client, "a.png", image_bytes("PNG", [GREEN]))
    file_id, meta = only_record(app)
    # on remet l'image en attente avec un contenu illisible
    with app.app_context():
        import os

        path = os.path.join(app.config["UPLOAD_FOLDER"], meta["server_name"])
        with open(path, "wb") as f:
            f.write(b"ceci n'est pas une image")
        db = json_services.load_db()
        db[file_id].update(status="pending", moderation_decision="pending")
        json_services.save_db(db)

        for expected in ("pending", "pending", "pending"):
            nsfw_service.run_auto_moderation()
            meta = json_services.load_db()[file_id]
            if meta["moderation_decision"] == "manual_review":
                break
    assert meta["status"] == "pending"
    assert meta["moderation_decision"] == "manual_review"
    assert meta["moderation_label"] == "analyse_impossible"
    assert meta["moderation_attempts"] == 3


def test_16bit_tiff_is_not_approved_blindly(moderated):
    app, client = moderated
    buf = io.BytesIO()
    Image.new("I;16", (20, 20), 40000).save(buf, "TIFF")
    upload(client, "deep.tif", buf.getvalue())
    file_id, meta = only_record(app)
    assert meta["status"] == "pending"  # 1er échec : réessayé plus tard, jamais publié
    with app.app_context():
        nsfw_service.run_auto_moderation()
        nsfw_service.run_auto_moderation()
        meta = json_services.load_db()[file_id]
    assert meta["moderation_decision"] == "manual_review"


def test_only_upload_requests_trigger_the_analysis(moderated, monkeypatch):
    app, client = moderated
    calls = []
    monkeypatch.setattr("pixshare.run_after_response", lambda a: calls.append(1))
    resp = client.post("/contact", data={"csrf_token": csrf(client)})
    resp.close()
    assert calls == []
    upload(client, "a.png", image_bytes("PNG", [GREEN]))
    assert calls == [1]


def test_decision_thresholds():
    assert nsfw_service.decide(None, 0.0, 0.6, 0.85) == "approve"
    assert nsfw_service.decide("X", 0.59, 0.6, 0.85) == "approve"
    assert nsfw_service.decide("X", 0.60, 0.6, 0.85) == "review"
    assert nsfw_service.decide("X", 0.85, 0.6, 0.85) == "reject"


def test_batch_is_limited_and_backlog_is_cleared_progressively(moderated):
    app, client = moderated
    for i in range(3):
        upload(client, f"a{i}.png", image_bytes("PNG", [GREEN]))
    with app.app_context():
        db = json_services.load_db()
        for meta in db.values():  # on simule un arriéré d'images restées en attente
            meta.update(status="pending", moderation_decision="pending")
        json_services.save_db(db)
        stats = nsfw_service.run_auto_moderation(limit=2)
        assert stats["approved"] == 2
        stats = nsfw_service.run_auto_moderation(limit=2)
        assert stats["approved"] == 1


def photo_with_patch(size, patch):
    """Grande photo verte avec un rectangle rouge (x0, y0, x1, y1)."""
    img = Image.new("RGB", size, GREEN)
    img.paste(Image.new("RGB", (patch[2] - patch[0], patch[3] - patch[1]), RED), patch[:2])
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def test_small_detail_in_a_large_photo_is_caught_by_tiles(moderated):
    """Le rouge ne couvre que 18 % de la photo (vue d'ensemble : pas de détection) mais 59 % du
    morceau en haut à gauche : seul le découpage le voit."""
    app, client = moderated
    upload(client, "big.png", photo_with_patch((1600, 1200), (0, 0, 700, 500)))
    _id, meta = only_record(app)
    assert meta["status"] == "deleted"
    assert FakeDetector.calls <= 5  # vue d'ensemble + 4 morceaux, jamais plus


def test_same_detail_in_a_small_photo_is_not_tiled(moderated):
    app, client = moderated
    upload(client, "small.png", photo_with_patch((400, 300), (0, 0, 175, 125)))
    _id, meta = only_record(app)
    assert meta["status"] == "active"  # même proportion, mais pas de découpage sous 800 px
    assert FakeDetector.calls == 1


def test_large_clean_photo_costs_five_analyses_and_is_published(moderated):
    app, client = moderated
    upload(client, "big.png", photo_with_patch((1600, 1200), (0, 0, 10, 10)))
    _id, meta = only_record(app)
    assert meta["status"] == "active"
    assert FakeDetector.calls == 5


def test_animations_are_not_tiled(moderated):
    app, client = moderated
    frames = [Image.new("RGB", (900, 900), c) for c in (GREEN, (30, 30, 200), (120, 120, 120))]
    buf = io.BytesIO()
    frames[0].save(buf, "GIF", save_all=True, append_images=frames[1:], duration=100, loop=0)
    upload(client, "anim.gif", buf.getvalue())
    assert FakeDetector.calls == 3  # 3 images, une vue d'ensemble chacune


def test_tile_boxes_cover_the_whole_image_with_overlap():
    boxes = nsfw_service.tile_boxes((1600, 1200))
    assert len(boxes) == 4
    assert min(b[0] for b in boxes) == 0 and max(b[2] for b in boxes) == 1600
    assert min(b[1] for b in boxes) == 0 and max(b[3] for b in boxes) == 1200
    left, right = boxes[0], boxes[1]
    assert right[0] < left[2]  # les morceaux voisins se recouvrent
