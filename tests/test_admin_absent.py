"""Admin absent : le filtre prend le relais et supprime seul les images douteuses. Admin présent : il décide."""
from datetime import datetime, timedelta, timezone

import pytest

from conftest import REAL_IS_PRESENT, csrf, login
from pixshare.services import account_service, admin_presence_service, json_services, nsfw_service
from test_accounts import fake_nudenet as _accounts_fake_nudenet  # noqa: F401  (détecteur des comptes)
from test_accounts import mails, member, png, records  # noqa: F401
from test_nsfw_moderation import GREEN, ORANGE, RED, fake_nudenet, image_bytes, upload  # noqa: F401


@pytest.fixture(autouse=True)
def real_presence(monkeypatch):
    monkeypatch.setattr(admin_presence_service, "is_present", REAL_IS_PRESENT)
    monkeypatch.setattr(admin_presence_service, "_last_write", 0.0)


@pytest.fixture
def app(make_app):
    return make_app(MODERATION_PENDING_IMAGES=True)


def settings(app, **values):
    from pixshare.services import settings_service
    with app.app_context():
        s = settings_service.load_settings()
        s.update(values)
        settings_service.save_settings(s)


def by_name(app):
    return {m["original_name"]: m for m in records(app).values()}


def test_absent_admin_doubtful_image_is_deleted_by_the_filter(app):
    client = app.test_client()
    upload(client, "doute.png", image_bytes("PNG", [ORANGE]))
    upload(client, "ok.png", image_bytes("PNG", [GREEN]))
    files = by_name(app)
    meta = files["doute.png"]
    assert meta["status"] == "deleted" and meta["delete_reason"] == "auto:admin_absent"
    assert meta["moderation_decision"] == "rejected_absent" and meta["moderation_label"]
    assert files["ok.png"]["status"] == "active"                     # le reste ne change pas
    with app.app_context():
        notices = json_services.load_moderation_notices()
        assert [n["reason"] for n in notices] == ["filtre_absent"]
        assert json_services.load_json("nsfw_stats.json", {}).get("absent_deleted") == 1
        assert not json_services.load_json("auto_block_offenses.json", {})    # un doute ne bloque pas l'IP


def test_present_admin_decides_himself(app):
    admin = login(app.test_client())
    admin.get("/admin")
    upload(app.test_client(), "doute.png", image_bytes("PNG", [ORANGE]))
    meta = by_name(app)["doute.png"]
    assert meta["status"] == "pending" and meta["moderation_decision"] == "manual_review"


def test_logout_hands_over_to_the_filter_and_admin_is_told_on_return(app):
    admin = login(app.test_client())
    upload(app.test_client(), "doute.png", image_bytes("PNG", [ORANGE]))
    assert by_name(app)["doute.png"]["status"] == "pending"           # en attente de l'admin
    admin.post("/admin/logout", data={"csrf_token": csrf(admin, "/admin")})
    upload(app.test_client(), "ok.png", image_bytes("PNG", [GREEN]))  # prochaine activité du site
    assert by_name(app)["doute.png"]["delete_reason"] == "auto:admin_absent"
    back = login(app.test_client())
    page = back.get("/admin", follow_redirects=True).get_data(as_text=True)
    assert "le filtre a supprimé 1 image(s) douteuse(s)" in page
    assert "par le filtre (admin absent" in page
    assert "le filtre a supprimé" not in back.get("/admin").get_data(as_text=True)  # dit une seule fois


def test_inactivity_makes_the_admin_absent(app):
    login(app.test_client()).get("/admin")
    with app.app_context():
        assert admin_presence_service.is_present()
        old = (datetime.now(timezone.utc) - timedelta(minutes=16)).isoformat(timespec="seconds")
        data = json_services.load_json("admin_presence.json", {})
        data["last_seen"] = old
        json_services.save_json("admin_presence.json", data)
        assert not admin_presence_service.is_present()               # 15 min par défaut
    settings(app, admin_absent_after_minutes=30)
    with app.app_context():
        assert admin_presence_service.is_present()


def test_absent_mode_off_everything_waits_for_the_admin(app):
    settings(app, admin_absent_mode=False)
    upload(app.test_client(), "doute.png", image_bytes("PNG", [ORANGE]))
    assert by_name(app)["doute.png"]["status"] == "pending"


def test_reports_and_failed_analyses_still_wait_for_the_admin(app):
    upload(app.test_client(), "doute.png", image_bytes("PNG", [GREEN]))
    with app.app_context():
        db = json_services.load_db()
        for i, (fid, meta) in enumerate(list(db.items())):
            meta.update(status="pending", moderation_decision="manual_review", moderation_detector="nudenet-3.4.2",
                        moderation_label="signalement")
        json_services.save_db(db)
        assert nsfw_service.apply_absent_decisions() == 0
    assert by_name(app)["doute.png"]["status"] == "pending"


def test_members_doubtful_images(make_app, mails, _accounts_fake_nudenet):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    settings(app, nsfw_auto_moderation=True, admin_absent_members=False)
    user = member(app.test_client(), mails)
    upload(user, "nu1.png", png((250, 10, 10)))
    assert by_name(app)["nu1.png"]["status"] == "pending"            # gardée pour le retour de l'admin
    settings(app, admin_absent_members=True)
    upload(user, "nu2.png", png((250, 10, 10)))
    files = by_name(app)
    assert files["nu2.png"]["delete_reason"] == "auto:admin_absent"
    assert files["nu1.png"]["delete_reason"] == "auto:admin_absent"  # l'ancienne aussi, l'admin n'étant pas là
    with app.app_context():
        acc = account_service.find_by_email("alice@example.com")
    assert not acc.get("strikes") and acc.get("status") != "suspended"  # un doute n'est pas un avertissement


def test_presence_is_internal(app):
    client = app.test_client()
    assert client.get("/admin/presence").status_code in (302, 401, 403)
    for page in ("/", "/cgu", "/healthz"):
        text = client.get(page).get_data(as_text=True).lower()
        assert "admin absent" not in text and "admin_presence" not in text
    admin = login(app.test_client())
    assert admin.get("/admin/presence").status_code == 204
    assert "presence" in admin.get("/admin/settings").get_data(as_text=True)  # signal envoyé par les pages admin


def test_settings_form(app):
    admin = login(app.test_client())
    page = admin.get("/admin/settings").get_data(as_text=True)
    assert "Quand tu es absent" in page
    resp = admin.post("/admin/settings/absent", data={"csrf_token": csrf(admin, "/admin/settings"),
                      "admin_absent_mode": "1", "admin_absent_after_minutes": "30", "admin_absent_members": "0"})
    assert resp.status_code == 302
    from pixshare.services import settings_service
    with app.app_context():
        s = settings_service.load_settings()
    assert s["admin_absent_after_minutes"] == 30 and s["admin_absent_members"] is False
    admin.post("/admin/settings/absent", data={"csrf_token": csrf(admin, "/admin/settings"),
               "admin_absent_mode": "1", "admin_absent_after_minutes": "99999"})
    with app.app_context():
        assert settings_service.load_settings()["admin_absent_after_minutes"] == 15  # valeur refusée
