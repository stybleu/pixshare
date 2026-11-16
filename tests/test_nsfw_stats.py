"""Statistiques de fiabilité NudeNet affichées dans Paramètres."""
from pixshare.services import nsfw_stats_service
from test_nsfw_admin import _review_image, admin, post, save_nsfw, upload  # noqa: F401
from test_nsfw_moderation import GREEN, RED, fake_nudenet, image_bytes  # noqa: F401


def stats(app):
    with app.app_context():
        return nsfw_stats_service.load_stats()


def test_automatic_decisions_are_counted(admin):
    app, client = admin
    save_nsfw(client)
    upload(client, "a.png", image_bytes("PNG", [GREEN]))
    upload(client, "b.png", image_bytes("PNG", [RED]))
    st = stats(app)
    assert (st["auto_approved"], st["auto_rejected"], st["analysed"]) == (1, 1, 2)


def test_admin_decisions_measure_false_alarms(admin):
    app, client, file_id = _review_image(admin)
    post(client, "/admin/review/approve", file_id=file_id)
    st = stats(app)
    assert st["auto_review"] == 1 and st["review_approved"] == 1 and st["false_alarm_pct"] == 100
    html = client.get("/admin/settings").get_data(as_text=True)
    assert "Fiabilité" in html and "100 % de fausses alertes" in html


def test_deleting_a_review_image_counts_as_confirmed(admin):
    app, client, file_id = _review_image(admin)
    post(client, "/admin/delete", file_id=file_id, delete_reason="non_respect_cgu")
    assert stats(app)["review_deleted"] == 1
    post(client, "/admin/moderation/stats/reset")
    assert stats(app)["review_deleted"] == 0
