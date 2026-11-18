"""Formules personnalisées par compte et options d'admin : avertissements, blocage automatique, testeur NudeNet."""
import io

from conftest import csrf, login
from pixshare.services import abuse_service, account_service
from test_accounts import mails, member, png, upload  # noqa: F401
from test_extension import new_key
from test_nsfw_moderation import GREEN, ORANGE, RED, fake_nudenet, image_bytes  # noqa: F401


def alice(app):
    with app.app_context():
        return account_service.find_by_email("alice@example.com")


def set_plan(admin, account_id, **fields):
    data = {"csrf_token": csrf(admin, "/admin/comptes"), "account_id": account_id, "do": "save",
            "name": "", "life": "", "mb": "", "per_hour": "", "no_ads": "0", "until": ""}
    data.update(fields)
    return admin.post("/admin/comptes/formule", data=data)


def test_custom_plan_applies_everywhere(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    rec = alice(app)
    admin = login(app.test_client())
    resp = set_plan(admin, rec["id"], name="Donateur", life="2880", mb="50", per_hour="1", no_ads="1",
                    until="2099-12-31")
    assert resp.status_code == 302
    page = user.get("/compte").get_data(as_text=True)
    assert "Votre formule : Donateur" in page and "31/12/2099" in page and "50 Mo" in page and "aucune publicité" in page
    home = user.get("/").get_data(as_text=True)
    assert 'value="2880"' in home and 'value="10080"' not in home      # durées : jusqu'à 2 jours seulement
    upload(user, "a.png")
    assert upload(user, "b.png").status_code == 429                    # 1 envoi par heure
    key = new_key(user)
    me = app.test_client().get("/extension/moi", headers={"Authorization": f"Bearer {key}"}).get_json()
    assert me["max_mb"] == 50 and max(c["minutes"] for c in me["lifetimes"]) == 2880
    admin_page = admin.get("/admin/comptes").get_data(as_text=True)
    assert "Formule « Donateur » jusqu&#39;au 31/12/2099" in admin_page or "Formule « Donateur » jusqu'au 31/12/2099" in admin_page


def test_expired_plan_falls_back_to_member_settings(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    admin = login(app.test_client())
    set_plan(admin, alice(app)["id"], name="Ancien", mb="999", until="2020-01-01")
    assert "Votre formule" not in user.get("/compte").get_data(as_text=True)
    assert "expirée le 01/01/2020" in admin.get("/admin/comptes").get_data(as_text=True)
    with app.test_request_context():
        from pixshare.services.settings_service import get_max_upload_size_mb
        assert get_max_upload_size_mb(alice(app)) == get_max_upload_size_mb(True)


def test_plan_without_ads(make_app, mails):
    from test_ads import CLIENT, configure
    app = make_app()
    admin = login(app.test_client())
    configure(admin, adsense_client=CLIENT, auto_ads="1", hide_for_members="0")
    user = member(app.test_client(), mails)
    assert "adsbygoogle" in user.get("/").get_data(as_text=True)
    set_plan(admin, alice(app)["id"], no_ads="1")
    assert "adsbygoogle" not in user.get("/").get_data(as_text=True)


def test_plan_input_is_checked_and_can_be_cleared(make_app, mails):
    app = make_app()
    member(app.test_client(), mails)
    admin = login(app.test_client())
    rec = alice(app)
    resp = set_plan(admin, rec["id"], name="<b>Pro</b>", mb="999999", per_hour="-5", life="7", until="demain")
    assert resp.status_code == 302
    plan = alice(app)["plan"]
    assert plan == {"name": "bPro/b"}                              # rien d'invalide n'est gardé
    flashes = admin.get("/admin/comptes").get_data(as_text=True)
    assert "Valeur refusée" in flashes
    admin.post("/admin/comptes/formule", data={"csrf_token": csrf(admin, "/admin/comptes"), "account_id": rec["id"],
                                               "do": "clear"})
    assert alice(app)["plan"] == {}
    assert app.test_client().post("/admin/comptes/formule", data={"account_id": rec["id"]}).status_code in (302, 400, 403)


def test_strikes_before_suspension_are_adjustable(make_app, mails):
    app = make_app()
    member(app.test_client(), mails)
    admin = login(app.test_client())
    admin.post("/admin/comptes/reglages", data={"csrf_token": csrf(admin, "/admin/comptes"), "accounts_enabled": "1",
                                                "guest_max_lifetime_minutes": "120", "guest_max_upload_size_mb": "10",
                                                "guest_uploads_per_hour": "10", "member_uploads_per_hour": "100",
                                                "member_strikes_max": "1"})
    with app.app_context():
        assert account_service.strikes_max() == 1
        assert account_service.add_strike(alice(app)["id"])["status"] == "suspended"
        account_service.set_status(alice(app)["id"], "active")
        from pixshare.services.settings_service import load_settings, save_settings
        s = load_settings()
        s["member_strikes_max"] = 0
        save_settings(s)
        for _ in range(5):
            rec = account_service.add_strike(alice(app)["id"])
        assert rec["status"] == "active"                             # 0 = jamais de suspension


def test_auto_block_settings_from_admin(make_app, monkeypatch):
    monkeypatch.setenv("AUTO_BLOCK_REJECTIONS", "3")
    app = make_app()
    admin = login(app.test_client())
    page = admin.get("/admin/blocked-ips").get_data(as_text=True)
    assert "Blocage automatique" in page and 'name="auto_block_rejections"' in page
    admin.post("/admin/blocked-ips/auto", data={"csrf_token": csrf(admin, "/admin/blocked-ips"),
                                                "auto_block_rejections": "5", "auto_block_hours": "48"})
    with app.app_context():
        cfg = abuse_service.auto_block_settings()
    assert cfg["rejections"] == 5 and cfg["hours"] == 48 and cfg["from_admin"]
    admin.post("/admin/blocked-ips/auto", data={"csrf_token": csrf(admin, "/admin/blocked-ips"), "reset": "1"})
    with app.app_context():
        cfg = abuse_service.auto_block_settings()
    assert cfg["rejections"] == 3 and not cfg["from_admin"]


def test_nudenet_tester_shows_detections_without_saving(make_app):
    app = make_app()
    admin = login(app.test_client())
    assert "Tester une image" in admin.get("/admin/settings").get_data(as_text=True)
    resp = admin.post("/admin/nudenet/test", data={"csrf_token": csrf(admin, "/admin/nudenet/test"),
                                                   "image": (io.BytesIO(image_bytes("PNG", [ORANGE])), "t.png")},
                      content_type="multipart/form-data")
    page = resp.get_data(as_text=True)
    assert resp.status_code == 200 and "Mise de côté (douteuse)" in page and "70 %" in page
    assert "data:image/jpeg;base64," in page and "blur(18px)" in page
    with app.app_context():
        from pixshare.services.json_services import load_db
        assert load_db() == {}                                      # rien d'enregistré
    red = admin.post("/admin/nudenet/test", data={"csrf_token": csrf(admin, "/admin/nudenet/test"),
                                                  "image": (io.BytesIO(image_bytes("PNG", [RED])), "r.png")},
                     content_type="multipart/form-data").get_data(as_text=True)
    assert "Visiteur sans compte : <span class=\"badge text-bg-danger\">Supprimée" in red
    assert "Membre : <span class=\"badge text-bg-warning\">Mise de côté" in red
    bad = admin.post("/admin/nudenet/test", data={"csrf_token": csrf(admin, "/admin/nudenet/test"),
                                                  "image": (io.BytesIO(b"pas une image"), "x.png")},
                     content_type="multipart/form-data").get_data(as_text=True)
    assert "Analyse impossible" in bad
    assert app.test_client().get("/admin/nudenet/test").status_code == 302
