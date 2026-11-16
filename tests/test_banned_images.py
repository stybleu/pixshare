"""Images interdites (refus permanent par empreinte) et blocages de plus en plus longs."""
import io
from datetime import datetime, timezone

from PIL import Image, ImageDraw

from conftest import csrf, login
from pixshare.services import abuse_service, image_ban_service, json_services
from test_nsfw_moderation import FakeDetector, fake_nudenet  # noqa: F401

VISITOR = {"REMOTE_ADDR": "203.0.113.50"}


def explicit_png(size=(400, 300)):
    """Image « explicite » pour le faux NudeNet (≥ 40 % de rouge vif) avec des détails pour l'empreinte visuelle."""
    im = Image.new("RGB", size, (230, 20, 20))
    d = ImageDraw.Draw(im)
    w, h = size
    for i in range(6):
        d.rectangle([i * w // 6, int(h * 0.65), i * w // 6 + w // 12, h], fill=(20 + 40 * i, 200 - 30 * i, 60))
    d.ellipse([w // 8, h // 8, w // 3, h // 2], fill=(250, 240, 230))
    return im


def png(im):
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


def send(client, data, name="a.png"):
    resp = client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(data), name)},
                       content_type="multipart/form-data", environ_overrides=VISITOR)
    resp.close()  # analyse NudeNet « après la réponse »
    return resp


def records(app):
    with app.app_context():
        return json_services.load_db()


def test_rejected_image_is_refused_forever_without_nudenet(make_app):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    client = app.test_client()
    data = png(explicit_png())
    send(client, data)
    assert [m["status"] for m in records(app).values()] == ["deleted"]
    with app.app_context():
        assert len(image_ban_service.list_banned()) == 1
    calls = FakeDetector.calls
    resp = send(client, data)
    page = client.get(resp.headers["Location"]).get_data(as_text=True)
    assert "déjà été refusée" in page
    assert len(records(app)) == 1 and FakeDetector.calls == calls  # rien d'enregistré, NudeNet pas sollicité


def test_retouched_copy_goes_to_review_without_nudenet(make_app):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    client = app.test_client()
    send(client, png(explicit_png()))
    calls = FakeDetector.calls
    smaller = explicit_png().resize((200, 150))
    buf = io.BytesIO()
    smaller.save(buf, "JPEG", quality=70)
    send(client, buf.getvalue(), "copie.jpg")
    copy = [m for m in records(app).values() if m["original_name"] == "copie.jpg"][0]
    assert copy["status"] == "pending" and copy["moderation_decision"] == "manual_review"
    assert copy["moderation_label"] == "deja_refusee" and FakeDetector.calls == calls


def test_admin_cgu_deletion_bans_but_user_deletion_does_not(make_app):
    app = make_app(NSFW_AUTO_MODERATION=False)
    client = app.test_client()
    send(client, png(explicit_png()), "a.png")
    send(client, png(explicit_png((300, 300))), "b.png")
    ids = {m["original_name"]: fid for fid, m in records(app).items()}
    admin = login(app.test_client())
    admin.post("/admin/delete", data={"csrf_token": csrf(admin, "/admin"), "file_id": ids["a.png"], "delete_reason": "non_respect_cgu"})
    admin.post("/admin/delete", data={"csrf_token": csrf(admin, "/admin"), "file_id": ids["b.png"], "delete_reason": "admin_delete"})
    with app.app_context():
        assert len(image_ban_service.list_banned()) == 1
        sha = image_ban_service.list_banned()[0]["sha256"]
    page = admin.get("/admin/blocked-ips").get_data(as_text=True)
    assert "Images interdites (1)" in page
    admin.post("/admin/banned-images/remove", data={"csrf_token": csrf(admin, "/admin/blocked-ips"), "sha256": sha})
    with app.app_context():
        assert image_ban_service.list_banned() == []


def test_uniform_images_never_match_visually(tmp_path):
    p = tmp_path / "blanc.png"
    Image.new("RGB", (50, 50), "white").save(p)
    assert image_ban_service.visual_hash(str(p)) is None


def test_repeat_offenders_get_longer_blocks(make_app):
    app = make_app()
    ip = "198.51.100.66"
    hours = []
    with app.app_context():
        for _round in range(3):
            for _ in range(3):
                abuse_service.record_rejection(ip)
            until = datetime.fromisoformat(json_services.load_blocked_info()[ip]["until"])
            hours.append(round((until - datetime.now(timezone.utc)).total_seconds() / 3600))
            json_services.save_blocked([])  # fin du blocage
    assert hours == [24, 168, 720]
