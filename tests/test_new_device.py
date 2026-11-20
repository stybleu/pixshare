"""Vérification par mail sur un nouvel appareil : un mot de passe volé ne suffit plus."""
import re

from conftest import csrf
from test_accounts import PASSWORD, form_post, login_new_device, mails, member  # noqa: F401
from pixshare.services import account_service, device_service


def code_in(mail):
    return re.search(r"Votre code : (\d{6})", mail["body"]).group(1)


def accounts_of(app):
    with app.app_context():
        return account_service.find_by_email("alice@example.com")


def test_device_that_created_the_account_is_trusted(make_app, mails):
    app = make_app()
    phone = member(app.test_client(), mails)
    rec = accounts_of(app)
    assert len(rec["devices"]) == 1
    assert "pxs_appareil" in {c.key for c in phone._cookies.values()}
    sent = len(mails)
    phone.post("/deconnexion", data={"csrf_token": csrf(phone, "/compte")})
    resp = form_post(phone, "/connexion", email="alice@example.com", password=PASSWORD)
    assert resp.status_code == 302 and "/verification" not in resp.headers["Location"]   # pas de code ici
    assert len(mails) == sent and phone.get("/compte").status_code == 200


def test_stolen_password_is_not_enough(make_app, mails):
    app = make_app()
    member(app.test_client(), mails)
    thief = app.test_client()
    resp = form_post(thief, "/connexion", email="alice@example.com", password=PASSWORD)
    assert "/connexion/verification" in resp.headers["Location"]
    mail = mails[-1]
    assert mail["to"] == "alice@example.com" and "code de connexion" in mail["subject"] and "Ce n'était pas moi" in mail["body"]
    assert thief.get("/compte").status_code == 302                                       # pas connecté sans le code
    page = thief.get("/connexion/verification").get_data(as_text=True)
    assert "a•••e@example.com" in page and "alice@example.com" not in page               # adresse masquée
    code = code_in(mail)
    assert code not in str(thief._cookies.values())                                      # le code n'est pas dans les cookies
    for guess in ("000000", "111111", "123456", "999999", "424242"):
        if guess != code:
            form_post(thief, "/connexion/verification", page="/connexion/verification", code=guess)
    # 5 erreurs : vérification annulée, même le bon code ne marche plus
    resp = form_post(thief, "/connexion/verification", page="/connexion", code=code)
    assert thief.get("/compte").status_code == 302


def test_good_code_trusts_the_new_device(make_app, mails):
    app = make_app()
    member(app.test_client(), mails)
    tablet = login_new_device(app.test_client(), mails)
    assert tablet.get("/compte").status_code == 200
    assert len(accounts_of(app)["devices"]) == 2
    sent = len(mails)
    tablet.post("/deconnexion", data={"csrf_token": csrf(tablet, "/compte")})
    form_post(tablet, "/connexion", email="alice@example.com", password=PASSWORD)
    assert len(mails) == sent and tablet.get("/compte").status_code == 200              # reconnue : plus de code


def test_code_works_once_and_expires(make_app, mails, monkeypatch):
    app = make_app()
    member(app.test_client(), mails)
    c = app.test_client()
    form_post(c, "/connexion", email="alice@example.com", password=PASSWORD)
    code = code_in(mails[-1])
    from datetime import timedelta
    from pixshare.services import time_service
    real = time_service.utcnow
    monkeypatch.setattr(device_service, "utcnow", lambda: real() + timedelta(minutes=11))
    form_post(c, "/connexion/verification", page="/connexion", code=code)
    assert c.get("/compte").status_code == 302                                           # périmé après 10 min


def test_code_mails_are_limited(make_app, mails):
    app = make_app()
    member(app.test_client(), mails)
    before = len(mails)
    for _ in range(8):
        form_post(app.test_client(), "/connexion", email="alice@example.com", password=PASSWORD)
    assert len(mails) - before == device_service.CODES_PER_HOUR                          # pas de bombardement de mails


def test_removing_a_device_logs_it_out(make_app, mails):
    app = make_app()
    phone = member(app.test_client(), mails)
    tablet = login_new_device(app.test_client(), mails)
    page = phone.get("/compte").get_data(as_text=True)
    assert "Appareils reconnus" in page and "cet appareil" in page
    other = [d for d in accounts_of(app)["devices"]][-1]["id"]
    phone.post("/compte/appareils/retirer", data={"csrf_token": csrf(phone, "/compte"), "device_id": other})
    assert tablet.get("/compte").status_code == 302                                     # déconnectée aussitôt
    assert phone.get("/compte").status_code == 200
    tablet.post("/deconnexion", data={"csrf_token": csrf(tablet, "/")})
    sent = len(mails)
    form_post(tablet, "/connexion", email="alice@example.com", password=PASSWORD)
    assert len(mails) == sent + 1                                                       # elle devra être revérifiée


def test_other_member_cannot_remove_my_devices(make_app, mails):
    app = make_app()
    phone = member(app.test_client(), mails)
    my_device = accounts_of(app)["devices"][0]["id"]
    bob = member(app.test_client(), mails, email="bob@example.com")
    bob.post("/compte/appareils/retirer", data={"csrf_token": csrf(bob, "/compte"), "device_id": my_device})
    assert phone.get("/compte").status_code == 200


def test_not_me_link_locks_everyone_out(make_app, mails):
    app = make_app()
    phone = member(app.test_client(), mails)
    tablet = login_new_device(app.test_client(), mails)
    thief = app.test_client()
    form_post(thief, "/connexion", email="alice@example.com", password=PASSWORD)
    link = re.search(r"https?://[^/\s]+(/compte/pas-moi/[^\s]+)", mails[-1]["body"]).group(1)
    assert "Protéger mon compte" in app.test_client().get(link).get_data(as_text=True)    # un simple clic ne fait rien
    c = app.test_client()
    c.post(link, data={"csrf_token": csrf(c, link)})
    assert phone.get("/compte").status_code == 302 and tablet.get("/compte").status_code == 302
    assert accounts_of(app)["devices"] == []
    assert "nouveau mot de passe" in mails[-1]["subject"]                                 # lien envoyé
    code = re.search(r"Votre code : (\d{6})", [m for m in mails if "code" in m["subject"]][-1]["body"]).group(1)
    form_post(thief, "/connexion/verification", page="/connexion", code=code)
    assert thief.get("/compte").status_code == 302                                       # le code en cours est annulé


def test_password_reset_by_mail_trusts_only_this_device(make_app, mails):
    app = make_app()
    member(app.test_client(), mails)
    login_new_device(app.test_client(), mails)
    assert len(accounts_of(app)["devices"]) == 2
    c = app.test_client()
    form_post(c, "/mot-de-passe-oublie", email="alice@example.com")
    link = re.search(r"https?://[^/\s]+(/mot-de-passe/[^\s]+)", mails[-1]["body"]).group(1)
    form_post(c, link, password="nouveau-mdp-solide", password2="nouveau-mdp-solide")
    assert c.get("/compte").status_code == 200
    assert len(accounts_of(app)["devices"]) == 1


def test_device_label_is_simple():
    ua = ("Mozilla/5.0 (Linux; Android 14; SM-A375B) AppleWebKit/537.36 (KHTML, like Gecko) "
          "SamsungBrowser/25.0 Chrome/121.0 Mobile Safari/537.36")
    assert device_service.label_from_user_agent(ua) == "Samsung Internet sur Android"
    ua = "Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36"
    assert device_service.label_from_user_agent(ua) == "Chrome sur Android"
    ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    assert device_service.label_from_user_agent(ua) == "Safari sur iPhone"
