"""Comptes : inscription par mail, connexion, limites avec/sans compte, « Mes images » partout,
aperçu privé, remplacement en gardant le lien, NudeNet plus souple, avertissements, suppression."""
import importlib.machinery
import io
import re
import sys
import types

import numpy as np
import pytest
from PIL import Image

from conftest import csrf, login as admin_login
from pixshare.services import account_service, json_services, mail_service, nsfw_service

PASSWORD = "mot-de-passe-solide"


@pytest.fixture
def mails(monkeypatch):
    sent = []
    monkeypatch.setenv("MAIL_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("MAIL_FROM", "pixshare@example.test")
    monkeypatch.setattr(mail_service, "send_mail_now", lambda subject, body, html=None, images=None, cfg=None:
                        (sent.append({"to": (cfg or {}).get("to"), "subject": subject, "body": body}) or (True, "")))
    return sent


def png(color=(20, 160, 40), size=(40, 40)):
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, "PNG")
    return buf.getvalue()


def link_in(mail, path):
    match = re.search(r"https?://[^/\s]+(" + path + r"[^\s]+)", mail["body"])
    assert match, mail["body"]
    return match.group(1)


def form_post(client, url, page=None, **data):
    return client.post(url, data={"csrf_token": csrf(client, page or url), **data})


def signup(client, mails, email="alice@example.com", password=PASSWORD):
    resp = form_post(client, "/inscription", email=email, password=password, password2=password, accept_cgu="1")
    assert resp.status_code == 200 and "Vérifiez votre boîte mail" in resp.get_data(as_text=True)
    return mails[-1]


def member(client, mails, email="alice@example.com"):
    mail = signup(client, mails, email)
    url = link_in(mail, "/inscription/confirmer/")
    resp = form_post(client, url)
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/compte")
    return client


def login_new_device(client, mails, email="alice@example.com", password=PASSWORD):
    """Connexion depuis un autre appareil : mot de passe, puis code reçu par mail."""
    resp = form_post(client, "/connexion", email=email, password=password)
    assert resp.status_code == 302 and "/connexion/verification" in resp.headers["Location"], resp.status_code
    code = re.search(r"Votre code : (\d{6})", mails[-1]["body"]).group(1)
    resp = form_post(client, "/connexion/verification", code=code)
    assert resp.status_code == 302, resp.status_code
    return client


def upload(client, name="a.png", data=None, **extra):
    resp = client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(data or png()), name), **extra},
                       content_type="multipart/form-data")
    resp.close()
    return resp


def records(app):
    with app.app_context():
        return json_services.load_db()


def test_signup_closed_without_mail(make_app):
    page = make_app().test_client().get("/inscription")
    html = page.get_data(as_text=True)
    assert page.status_code == 200 and "indisponibles pour le moment" in html
    assert html.count("<h1") == 1 and "noindex" in page.headers["X-Robots-Tag"]


def test_signup_confirm_login_logout(make_app, mails):
    app = make_app()
    client = app.test_client()
    mail = signup(client, mails)
    assert mail["to"] == "alice@example.com" and "confirme" in mail["subject"]
    # Pas encore confirmé : connexion refusée, renvoi vers « renvoyer le lien ».
    resp = form_post(client, "/connexion", email="alice@example.com", password=PASSWORD)
    assert resp.status_code == 302 and "/inscription/renvoyer" in resp.headers["Location"]
    url = link_in(mail, "/inscription/confirmer/")
    assert "Confirmer et activer" in client.get(url).get_data(as_text=True)  # un simple GET ne confirme rien
    form_post(client, url)
    page = client.get("/compte").get_data(as_text=True)
    assert "alice@example.com" in page and "Mon compte" in page

    form_post(client, "/deconnexion", page="/compte")
    assert client.get("/compte").status_code == 302
    bad = form_post(client, "/connexion", email="alice@example.com", password="mauvais-mot")
    assert bad.status_code == 401
    ok = form_post(client, "/connexion", email="ALICE@example.com", password=PASSWORD)
    assert ok.status_code == 302 and client.get("/compte").status_code == 200


def test_same_answer_for_existing_email(make_app, mails):
    app = make_app()
    member(app.test_client(), mails)
    other = app.test_client()
    mail = signup(other, mails)  # même message à l'écran ; le mail dit « tu as déjà un compte »
    assert "déjà un compte" in mail["subject"]
    with app.app_context():
        assert len(account_service.all_accounts()) == 1


def test_password_rules(make_app, mails):
    client = make_app().test_client()
    resp = form_post(client, "/inscription", email="bob@example.com", password="court", password2="court", accept_cgu="1")
    assert "au moins 8" in resp.get_data(as_text=True) and not mails
    resp = form_post(client, "/inscription", email="pas-une-adresse", password=PASSWORD, password2=PASSWORD, accept_cgu="1")
    assert "Adresse e-mail invalide" in resp.get_data(as_text=True)
    resp = form_post(client, "/inscription", email="bob@example.com", password=PASSWORD, password2=PASSWORD)
    assert "accepter les conditions" in resp.get_data(as_text=True)


def test_guest_and_member_limits(make_app, mails):
    app = make_app()
    guest = app.test_client()
    html = guest.get("/").get_data(as_text=True)
    values = [int(v) for v in re.findall(r'<option value="(\d+)"', html.split('id="lifetimeSelect"')[1].split("</select>")[0])]
    assert values[0] == 2 and max(values) == 120  # 2 min à 2 h sans compte
    assert "Compte gratuit : plus de temps" in html

    user = member(app.test_client(), mails)
    html = user.get("/").get_data(as_text=True)
    values = [int(v) for v in re.findall(r'<option value="(\d+)"', html.split('id="lifetimeSelect"')[1].split("</select>")[0])]
    assert values[0] == 2 and max(values) == 525600  # 2 min à 1 an avec un compte

    upload(guest, lifetime="525600")
    upload(user, lifetime="525600")
    lifetimes = {}
    for meta in records(app).values():
        lifetimes[bool(meta.get("account_id"))] = meta
    from pixshare.services.time_service import parse_dt
    def minutes(meta):
        return round((parse_dt(meta["expires_at"]) - parse_dt(meta["uploaded_at"])).total_seconds() / 60)
    assert minutes(lifetimes[False]) == 120 and minutes(lifetimes[True]) == 525600


def test_guest_size_and_rate_limits(make_app, mails):
    app = make_app()
    with app.app_context():
        from pixshare.services import settings_service
        settings = settings_service.load_settings()
        settings.update(guest_max_upload_size_mb=1, guest_uploads_per_hour=2)
        settings_service.save_settings(settings)
    big = png(size=(1, 1)) + b"\0" * (1024 * 1024 + 10)
    guest = app.test_client()
    resp = upload(guest, "big.png", big)
    assert len(records(app)) == 0
    upload(guest)
    upload(guest)
    resp = upload(guest)
    assert resp.status_code == 429 and "compte gratuit" in resp.get_data(as_text=True)

    user = member(app.test_client(), mails)
    for _ in range(3):
        upload(user)
    assert sum(1 for m in records(app).values() if m.get("account_id")) == 3


def test_my_images_on_every_device_with_private_preview(make_app, mails):
    app = make_app()
    phone = app.test_client()
    upload(phone, "avant.png")                       # envoyé sans compte, sur le téléphone
    member(phone, mails)                             # à l'inscription, il rejoint le compte
    upload(phone, "apres.png")
    pc = app.test_client()
    login_new_device(pc, mails)
    html = pc.get("/").get_data(as_text=True)
    assert "avant.png" in html and "apres.png" in html and "tous vos appareils" in html
    file_id = next(fid for fid, m in records(app).items() if m["original_name"] == "apres.png")
    preview = re.search(r'src="(/mes-images/' + file_id + r'/apercu[^"]*)"', html).group(1)
    assert pc.get(preview).status_code == 200
    assert app.test_client().get(preview).status_code == 404  # un inconnu ne voit rien


def test_pending_image_preview_for_owner_only(make_app, mails):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    user = member(app.test_client(), mails)
    with app.app_context():
        from pixshare.services import settings_service
        s = settings_service.load_settings(); s["nsfw_auto_moderation"] = False; settings_service.save_settings(s)
    # sans NudeNet installé, on simule une image restée en vérification manuelle
    upload(user)
    file_id, meta = next(iter(records(app).items()))
    with app.app_context():
        db = json_services.load_db()
        db[file_id].update(status="pending", moderation_decision="manual_review")
        json_services.save_db(db)
    html = user.get("/").get_data(as_text=True)
    assert f"/mes-images/{file_id}/apercu" in html
    assert user.get(f"/mes-images/{file_id}/apercu").status_code == 200
    assert app.test_client().get(f"/view/{file_id}").status_code == 404


def test_replace_keeps_link(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    upload(user, "chat.png", png((20, 160, 40)))
    file_id, before = next(iter(records(app).items()))
    resp = user.post(f"/remplacer/{file_id}", data={"csrf_token": csrf(user), "file": (io.BytesIO(png((10, 10, 200))), "chien.jpg")},
                     content_type="multipart/form-data")
    resp.close()
    assert resp.status_code == 302
    after = records(app)[file_id]
    assert after["original_name"] == "chien.jpg" and after["server_name"] == f"{file_id}.jpg"
    assert after["expires_at"] == before["expires_at"] and after["replace_count"] == 1
    assert len(records(app)) == 1
    body = app.test_client().get(f"/view/{file_id}?raw=1").data
    with Image.open(io.BytesIO(body)) as im:
        assert im.convert("RGB").getpixel((5, 5))[2] > 150  # c'est bien la nouvelle image

    guest = app.test_client()
    resp = guest.post(f"/remplacer/{file_id}", data={"csrf_token": csrf(guest), "file": (io.BytesIO(png()), "x.png")},
                      content_type="multipart/form-data")
    assert resp.status_code == 302 and "/connexion" in resp.headers["Location"]
    assert records(app)[file_id]["original_name"] == "chien.jpg"


def test_replace_refuses_banned_image(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    bad = png((200, 30, 30))
    upload(user, "bad.png", bad)
    bad_id = next(iter(records(app)))
    admin = admin_login(app.test_client())
    admin.post("/admin/delete", data={"csrf_token": csrf(admin, "/admin"), "file_id": bad_id, "delete_reason": "non_respect_cgu"})
    upload(user, "ok.png")
    ok_id = next(fid for fid, m in records(app).items() if m["original_name"] == "ok.png")
    user.post(f"/remplacer/{ok_id}", data={"csrf_token": csrf(user), "file": (io.BytesIO(bad), "bad.png")},
              content_type="multipart/form-data").close()
    assert records(app)[ok_id]["original_name"] == "ok.png"


class FakeDetector:
    def detect(self, path):
        with Image.open(path) as im:
            r, g, b = (int(v) for v in np.asarray(im.convert("RGB")).reshape(-1, 3).mean(axis=0))
        if r > 200 and g < 60:
            return [{"class": "FEMALE_GENITALIA_EXPOSED", "score": 0.95, "box": [0, 0, 1, 1]}]
        if b > 200:
            return [{"class": "FEMALE_BREAST_COVERED", "score": 0.95, "box": [0, 0, 1, 1]}]
        return [{"class": "FACE_FEMALE", "score": 0.99, "box": [0, 0, 1, 1]}]


@pytest.fixture
def fake_nudenet(monkeypatch):
    module = types.ModuleType("nudenet")
    module.__spec__ = importlib.machinery.ModuleSpec("nudenet", None)
    module.NudeDetector = FakeDetector
    monkeypatch.setitem(sys.modules, "nudenet", module)
    monkeypatch.setattr(nsfw_service, "_detector", None)
    monkeypatch.setattr(nsfw_service, "_detector_failed", False)


def test_nudenet_is_softer_for_members(make_app, mails, fake_nudenet):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    with app.app_context():
        from pixshare.services import settings_service
        s = settings_service.load_settings()
        s.update(nsfw_auto_moderation=True, nsfw_classes=["FEMALE_GENITALIA_EXPOSED", "FEMALE_BREAST_COVERED"])
        settings_service.save_settings(s)
    guest = app.test_client()
    user = member(app.test_client(), mails)
    upload(user, "maillot-membre.png", png((10, 10, 250)))
    upload(user, "nu-membre.png", png((250, 10, 10)))
    upload(guest, "maillot-invite.png", png((10, 10, 250)))
    upload(guest, "nu-invite.png", png((250, 10, 10)))
    with app.app_context():
        nsfw_service.run_auto_moderation(limit=10)
    by_name = {m["original_name"]: m for m in records(app).values()}
    assert by_name["maillot-membre.png"]["status"] == "active"          # tenue couverte : acceptée pour un membre
    assert by_name["maillot-invite.png"]["status"] != "active"
    assert by_name["nu-invite.png"]["status"] == "deleted"              # invité : supprimée automatiquement
    assert by_name["nu-membre.png"]["status"] == "pending"              # membre : gardée en privé pour l'admin
    assert by_name["nu-membre.png"]["moderation_decision"] == "manual_review"


def test_three_refusals_suspend_the_account(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    admin = admin_login(app.test_client())
    for i in range(3):
        upload(user, f"{i}.png", png((40 * i, 10, 10)))
    for file_id in list(records(app)):
        admin.post("/admin/delete", data={"csrf_token": csrf(admin, "/admin"), "file_id": file_id, "delete_reason": "non_respect_cgu"})
    assert user.get("/compte").status_code == 302  # déconnecté : compte suspendu
    resp = form_post(user, "/connexion", email="alice@example.com", password=PASSWORD)
    assert resp.status_code == 403 and "suspendu" in resp.get_data(as_text=True)
    page = admin.get("/admin/comptes").get_data(as_text=True)
    assert "suspendu" in page and "3/3" in page
    with app.app_context():
        account_id = next(iter(account_service.all_accounts()))
    admin.post("/admin/comptes/action", data={"csrf_token": csrf(admin, "/admin/comptes"), "account_id": account_id, "action": "activate"})
    assert form_post(user, "/connexion", email="alice@example.com", password=PASSWORD).status_code == 302


def test_user_deletion_is_not_a_strike(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    upload(user)
    file_id = next(iter(records(app)))
    user.post(f"/delete/{file_id}", data={"csrf_token": csrf(user)})
    assert records(app)[file_id]["status"] == "deleted"
    with app.app_context():
        assert next(iter(account_service.all_accounts().values()))["strikes"] == 0


def test_forgot_password_link_works_once_and_logs_out_other_devices(make_app, mails):
    app = make_app()
    other_device = member(app.test_client(), mails)
    client = app.test_client()
    form_post(client, "/mot-de-passe-oublie", email="alice@example.com")
    url = link_in(mails[-1], "/mot-de-passe/")
    new = "un-tout-nouveau-mot"
    resp = form_post(client, url, password=new, password2=new)
    assert resp.status_code == 302 and client.get("/compte").status_code == 200
    assert other_device.get("/compte").status_code == 302      # l'autre appareil est déconnecté
    assert client.get(url).status_code == 400                  # le lien ne sert qu'une fois
    unknown = len(mails)
    form_post(app.test_client(), "/mot-de-passe-oublie", email="personne@example.com")
    assert len(mails) == unknown                               # aucune info sur les adresses inconnues


def test_delete_account_removes_files_and_email(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    upload(user)
    file_id = next(iter(records(app)))
    resp = form_post(user, "/compte/supprimer", page="/compte", password=PASSWORD, confirm="1")
    assert resp.status_code == 302
    assert records(app)[file_id]["status"] == "deleted" and "account_id" not in records(app)[file_id]
    with app.app_context():
        assert account_service.all_accounts() == {}
    assert app.test_client().get(f"/view/{file_id}").status_code == 404


def test_admin_limits_settings(make_app, mails):
    app = make_app()
    admin = admin_login(app.test_client())
    resp = admin.post("/admin/comptes/reglages", data={
        "csrf_token": csrf(admin, "/admin/comptes"), "accounts_enabled": "0", "guest_max_lifetime_minutes": "60",
        "guest_max_upload_size_mb": "5", "guest_uploads_per_hour": "3", "member_uploads_per_hour": "50"})
    assert resp.status_code == 302
    with app.app_context():
        from pixshare.services import settings_service
        s = settings_service.load_settings()
    assert (s["accounts_enabled"], s["guest_max_lifetime_minutes"], s["guest_max_upload_size_mb"],
            s["guest_uploads_per_hour"], s["member_uploads_per_hour"]) == (False, 60, 5, 3, 50)
    assert "fermées" in app.test_client().get("/inscription").get_data(as_text=True)
    with app.app_context():
        assert '"guest_max_lifetime_minutes":60' in settings_service.export_settings()


def test_account_pages_are_accessible(make_app, mails):
    client = make_app().test_client()
    for path in ("/inscription", "/connexion", "/mot-de-passe-oublie", "/inscription/renvoyer"):
        resp = client.get(path)
        html = resp.get_data(as_text=True)
        assert resp.status_code == 200 and html.count("<h1") == 1, path
        assert "noindex" in resp.headers.get("X-Robots-Tag", ""), path
        for field in re.findall(r'<input[^>]+type="(?:email|password)"[^>]*>', html):
            field_id = re.search(r'id="([^"]+)"', field).group(1)
            assert f'for="{field_id}"' in html, (path, field_id)


def test_password_and_view_limit_are_for_members_only(make_app, mails):
    app = make_app()
    guest = app.test_client()
    html = guest.get("/").get_data(as_text=True)
    assert 'name="file_password"' not in html and 'name="view_limit_enabled"' not in html
    assert "Mot de passe, limite de vues et amélioration de la photo : avec un" in html
    upload(guest, "invite.png", file_password="secret123", view_limit_enabled="1", max_views="3")

    user = member(app.test_client(), mails)
    assert 'name="file_password"' in user.get("/").get_data(as_text=True)
    upload(user, "membre.png", file_password="secret123", view_limit_enabled="1", max_views="3")

    by_name = {m["original_name"]: m for m in records(app).values()}
    guest_meta, member_meta = by_name["invite.png"], by_name["membre.png"]
    assert not guest_meta.get("password_hash") and not guest_meta.get("view_limit_enabled")
    assert member_meta.get("password_hash") and member_meta.get("view_limit_enabled") and member_meta.get("max_views") == 3


def test_photo_enhancement_is_for_members_only(make_app, mails, monkeypatch):
    from pixshare.services import file_service

    calls = []
    monkeypatch.setattr(file_service, "enhance_image_bytes", lambda data, ext, strength: (calls.append(strength) or data + b""))
    app = make_app()
    guest = app.test_client()
    assert 'name="enhance_quality"' not in guest.get("/").get_data(as_text=True)
    upload(guest, "invite.png", enhance_quality="1", enhance_strength="20")
    assert calls == []  # ignoré sans compte

    user = member(app.test_client(), mails)
    assert 'name="enhance_quality"' in user.get("/").get_data(as_text=True)
    upload(user, "membre.png", enhance_quality="1", enhance_strength="20")
    assert calls == [20]
