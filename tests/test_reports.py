"""Signalement en un clic : masquage après plusieurs visiteurs différents, puis décision de l'admin."""
import io

from PIL import Image

from conftest import csrf, login
from pixshare.services import json_services, nsfw_stats_service


def setup(make_app):
    app = make_app(NSFW_AUTO_MODERATION=False)
    client = app.test_client()
    buf = io.BytesIO()
    Image.new("RGB", (20, 20), "blue").save(buf, "PNG")
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(buf.getvalue()), "a.png")},
                content_type="multipart/form-data")
    with app.app_context():
        (file_id,) = json_services.load_db()
    return app, file_id


def report(app, file_id, ip, reason="violence"):
    client = app.test_client()
    env = {"REMOTE_ADDR": ip}
    token = csrf(client, f"/image/{file_id}") if client.get(f"/image/{file_id}", environ_overrides=env).status_code == 200 else csrf(client)
    return client.post(f"/report/{file_id}", data={"csrf_token": token, "reason": reason}, environ_overrides=env)


def meta(app, file_id):
    with app.app_context():
        return json_services.load_db()[file_id]


def test_report_button_is_on_the_image_page(make_app):
    app, file_id = setup(make_app)
    html = app.test_client().get(f"/image/{file_id}").get_data(as_text=True)
    assert f"/report/{file_id}" in html and "Données personnelles" in html


def test_same_visitor_counts_once_and_ip_is_not_stored(make_app):
    app, file_id = setup(make_app)
    report(app, file_id, "198.51.100.1")
    report(app, file_id, "198.51.100.1")
    m = meta(app, file_id)
    assert len(m["reports"]) == 1 and m["status"] == "active"
    assert "198.51.100.1" not in str(m["reports"])


def test_three_visitors_hide_the_image_until_admin_decides(make_app):
    app, file_id = setup(make_app)
    for i in range(3):
        resp = report(app, file_id, f"198.51.100.{i + 1}", "haine")
    assert resp.status_code == 302
    m = meta(app, file_id)
    assert m["status"] == "pending" and m["moderation_decision"] == "manual_review" and m["moderation_label"] == "signalement"
    assert app.test_client().get(f"/view/{file_id}").status_code == 404
    admin = login(app.test_client())
    page = admin.get("/admin").get_data(as_text=True)
    assert "Signalée par des visiteurs" in page and "Signalements : <strong>3</strong>" in page
    admin.post("/admin/review/approve", data={"csrf_token": csrf(admin, "/admin"), "file_id": file_id})
    m = meta(app, file_id)
    assert m["status"] == "active" and m["reports"] == []
    with app.app_context():
        assert nsfw_stats_service.load_stats()["review_approved"] == 0  # pas une erreur de NudeNet


def test_threshold_zero_never_hides(make_app, monkeypatch):
    monkeypatch.setenv("REPORT_HIDE_THRESHOLD", "0")
    app, file_id = setup(make_app)
    for i in range(5):
        report(app, file_id, f"198.51.100.{i + 1}")
    assert meta(app, file_id)["status"] == "active"
