"""Filtre des membres : moins de restrictions par défaut, mais réglable par l'admin (et suivi par le mode absent)."""
from conftest import csrf, login
from pixshare.services import account_service, json_services, nsfw_service, settings_service
from test_accounts import mails, member  # noqa: F401
from test_nsfw_moderation import GREEN, ORANGE, RED, fake_nudenet, image_bytes, upload  # noqa: F401

ORANGE_PNG = image_bytes("PNG", [ORANGE])   # FakeDetector : BUTTOCKS_EXPOSED à 0,70
RED_PNG = image_bytes("PNG", [RED])         # FakeDetector : FEMALE_BREAST_EXPOSED à 0,95


def setup(app, **values):
    with app.app_context():
        s = settings_service.load_settings()
        s.update(nsfw_auto_moderation=True, admin_absent_mode=False, **values)
        settings_service.save_settings(s)


def by_name(app):
    with app.app_context():
        return {m["original_name"]: m for m in json_services.load_db().values()}


def test_default_member_rules_are_softer_but_same_thresholds(make_app):
    app = make_app()
    with app.app_context():
        cfg = nsfw_service.effective_settings()
    m = cfg["member"]
    assert m["review_threshold"] == cfg["review_threshold"] and m["block_threshold"] == cfg["block_threshold"]
    assert set(m["classes"]) <= nsfw_service.EXPLICIT_CLASSES and not m["reject_direct"] and not m["customized"]


def test_member_thresholds_can_be_raised(make_app, mails):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    setup(app, nsfw_review_threshold=0.60, nsfw_block_threshold=0.85,
          nsfw_member_review_threshold=0.80, nsfw_member_block_threshold=0.97)
    user = member(app.test_client(), mails)
    guest = app.test_client()
    upload(user, "membre-070.png", ORANGE_PNG)
    upload(guest, "invite-070.png", ORANGE_PNG)
    upload(user, "membre-095.png", RED_PNG)
    files = by_name(app)
    assert files["membre-070.png"]["status"] == "active"                  # 0,70 < 0,80 : passe pour un membre
    assert files["invite-070.png"]["moderation_decision"] == "manual_review"  # 0,70 >= 0,60 : vérifiée pour un visiteur
    assert files["membre-095.png"]["moderation_decision"] == "manual_review"  # 0,95 < 0,97 : vérification


def test_member_can_be_rejected_directly_if_admin_wants(make_app, mails):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    setup(app, nsfw_member_reject_direct=True)
    user = member(app.test_client(), mails)
    upload(user, "nu.png", RED_PNG)
    assert by_name(app)["nu.png"]["status"] == "deleted"


def test_member_zones_are_separate(make_app, mails):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    setup(app, nsfw_classes=["FEMALE_BREAST_EXPOSED", "BUTTOCKS_EXPOSED"], nsfw_member_classes=["FEMALE_BREAST_EXPOSED"])
    user = member(app.test_client(), mails)
    guest = app.test_client()
    upload(user, "fesses-membre.png", ORANGE_PNG)
    upload(guest, "fesses-invite.png", ORANGE_PNG)
    files = by_name(app)
    assert files["fesses-membre.png"]["status"] == "active"
    assert files["fesses-invite.png"]["status"] == "pending"


def test_absent_mode_follows_member_rules(make_app, mails, monkeypatch):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    setup(app, nsfw_member_review_threshold=0.80, nsfw_member_block_threshold=0.97)
    with app.app_context():
        s = settings_service.load_settings()
        s.update(admin_absent_mode=True, admin_absent_members=True, admin_absent_after_minutes=5)
        settings_service.save_settings(s)
    from pixshare.services import admin_presence_service
    monkeypatch.setattr(admin_presence_service, "is_present", lambda: False)   # l'admin n'est pas là
    user = member(app.test_client(), mails)
    upload(user, "doute-070.png", ORANGE_PNG)
    upload(user, "nu-095.png", RED_PNG)
    files = by_name(app)
    assert files["doute-070.png"]["status"] == "active"                     # sous le seuil des membres : rien à trancher
    assert files["nu-095.png"]["delete_reason"] == "auto:admin_absent"      # douteuse pour un membre : le filtre tranche


def test_admin_form_saves_validates_and_resets(make_app):
    app = make_app()
    admin = login(app.test_client())
    page = admin.get("/admin/settings").get_data(as_text=True)
    assert "Filtre des membres" in page and "Réglage par défaut en cours" in page
    t = csrf(admin, "/admin/settings")
    r = admin.post("/admin/settings/nsfw/membres", data={"csrf_token": t, "nsfw_member_review_threshold": "0.9",
                                                         "nsfw_member_block_threshold": "0.8", "nsfw_member_classes": ["BUTTOCKS_EXPOSED"]})
    assert r.status_code == 302
    with app.app_context():
        assert nsfw_service.effective_settings()["member"]["customized"] is False   # refusé : vérification > refus
    admin.post("/admin/settings/nsfw/membres", data={"csrf_token": t, "nsfw_member_review_threshold": "0.75",
                                                     "nsfw_member_block_threshold": "0.95", "nsfw_member_reject_direct": "1",
                                                     "nsfw_member_classes": ["BUTTOCKS_EXPOSED", "FEMALE_GENITALIA_EXPOSED"]})
    with app.app_context():
        m = nsfw_service.effective_settings()["member"]
    assert (m["review_threshold"], m["block_threshold"], m["reject_direct"]) == (0.75, 0.95, True)
    assert m["classes"] == ["BUTTOCKS_EXPOSED", "FEMALE_GENITALIA_EXPOSED"]
    admin.post("/admin/settings/nsfw/membres", data={"csrf_token": t, "reset": "1"})
    with app.app_context():
        assert not nsfw_service.effective_settings()["member"]["customized"]
    guest = app.test_client()
    assert guest.post("/admin/settings/nsfw/membres", data={"csrf_token": csrf(guest), "reset": "1"}).status_code in (302, 403)
