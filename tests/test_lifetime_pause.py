"""Le délai d'une image ne commence qu'une fois la vérification terminée."""
import io
from datetime import timedelta

from PIL import Image

from conftest import csrf, login
from pixshare.services import json_services
from pixshare.services.time_service import parse_dt, utcnow


def _pending_image(make_app, minutes_ago=30, lifetime=5):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    with app.app_context():
        from pixshare.services import settings_service
        s = settings_service.load_settings(); s["nsfw_auto_moderation"] = True; settings_service.save_settings(s)
    client = app.test_client()
    buf = io.BytesIO()
    Image.new("RGB", (20, 20), (9, 9, 9)).save(buf, "PNG")
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(buf.getvalue()), "a.png"), "lifetime": str(lifetime)},
                content_type="multipart/form-data")
    with app.app_context():
        db = json_services.load_db()
        file_id, meta = next(iter(db.items()))
        past = utcnow() - timedelta(minutes=minutes_ago)
        meta.update(status="pending", moderation_decision="manual_review",
                    uploaded_at=past.isoformat(timespec="seconds"), moderation_requested_at=past.isoformat(timespec="seconds"),
                    expires_at=(past + timedelta(minutes=lifetime)).isoformat(timespec="seconds"))
        json_services.save_db(db)
    return app, client, file_id


def test_pending_image_does_not_expire_and_timer_starts_at_approval(make_app):
    app, owner, file_id = _pending_image(make_app, minutes_ago=30, lifetime=5)
    with app.app_context():
        from pixshare.services.file_service import cleanup_expired
        cleanup_expired()
        assert json_services.load_db()[file_id]["status"] == "pending"  # 30 min d'attente, délai de 5 min : pas expirée
    assert "délai en pause" in owner.get("/").get_data(as_text=True)

    admin = login(app.test_client())
    admin.post("/admin/review/approve", data={"csrf_token": csrf(admin, "/admin"), "file_id": file_id})
    with app.app_context():
        meta = json_services.load_db()[file_id]
    assert meta["status"] == "active"
    left = (parse_dt(meta["expires_at"]) - utcnow()).total_seconds() / 60
    assert 4.5 < left <= 5.01  # les 5 minutes commencent maintenant
    assert app.test_client().get(f"/view/{file_id}").status_code == 200


def test_never_reviewed_image_is_removed_after_30_days(make_app):
    app, _owner, file_id = _pending_image(make_app, minutes_ago=31 * 24 * 60)
    with app.app_context():
        from pixshare.services.file_service import cleanup_expired
        cleanup_expired()
        assert json_services.load_db().get(file_id, {}).get("status", "expired") != "pending"
