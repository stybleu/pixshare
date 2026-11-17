"""Extension de navigateur : clé personnelle des membres, envoi sans cookie, téléchargement du .zip."""
import io
import re
import zipfile

from PIL import Image

from conftest import csrf
from pixshare.services import account_service, json_services
from test_accounts import PASSWORD, form_post, mails, member  # noqa: F401  (fixture mails)


def png():
    buf = io.BytesIO()
    Image.new("RGB", (20, 20), (30, 140, 90)).save(buf, "PNG")
    return buf.getvalue()


def new_key(client):
    resp = form_post(client, "/compte/extension/cle", page="/compte")
    assert resp.status_code == 200
    return re.search(r'value="(pxs_[^"]+)"', resp.get_data(as_text=True)).group(1)


def send(app, key, **data):
    client = app.test_client()
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    return client.post("/extension/envoi", headers=headers, data=data, content_type="multipart/form-data")


def test_key_shown_once_and_upload_works(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    key = new_key(user)
    assert key not in user.get("/compte").get_data(as_text=True)  # affichée une seule fois
    me = app.test_client().get("/extension/moi", headers={"Authorization": f"Bearer {key}"}).get_json()
    assert me["ok"] and me["email"] == "alice@example.com" and max(c["minutes"] for c in me["lifetimes"]) == 525600

    resp = send(app, key, file=(io.BytesIO(png()), "capture.png"), lifetime="43200")
    data = resp.get_json()
    assert resp.status_code == 200 and data["ok"] and data["page_url"].endswith(f"/image/{data['id']}")
    assert data["lifetime_minutes"] == 43200  # durée d'un membre (30 jours), impossible sans compte
    with app.app_context():
        meta = json_services.load_db()[data["id"]]
        account_id = next(iter(account_service.all_accounts()))
    assert meta["account_id"] == account_id and meta["original_name"] == "capture.png"
    assert "capture.png" in user.get("/").get_data(as_text=True)  # visible dans « Mes fichiers »


def test_bad_or_revoked_key_is_refused(make_app, mails):
    app = make_app()
    assert send(app, "", file=(io.BytesIO(png()), "a.png")).status_code == 401
    assert send(app, "pxs_inventee", file=(io.BytesIO(png()), "a.png")).status_code == 401
    user = member(app.test_client(), mails)
    key = new_key(user)
    other = new_key(user)  # remplacer la clé désactive l'ancienne
    assert send(app, key, file=(io.BytesIO(png()), "a.png")).status_code == 401
    assert send(app, other, file=(io.BytesIO(png()), "a.png")).status_code == 200
    form_post(user, "/compte/extension/supprimer", page="/compte")
    assert send(app, other, file=(io.BytesIO(png()), "b.png")).status_code == 401


def test_password_change_disables_key(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    key = new_key(user)
    form_post(user, "/compte/mot-de-passe", page="/compte", current_password=PASSWORD,
              password="encore-un-autre", password2="encore-un-autre")
    assert send(app, key, file=(io.BytesIO(png()), "a.png")).status_code == 401


def test_suspended_account_key_is_refused(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    key = new_key(user)
    with app.app_context():
        account_service.set_status(next(iter(account_service.all_accounts())), "suspended")
    assert send(app, key, file=(io.BytesIO(png()), "a.png")).status_code == 401


def test_cookie_alone_cannot_use_the_endpoint(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)  # connecté par cookie, mais sans clé
    resp = user.post("/extension/envoi", data={"file": (io.BytesIO(png()), "a.png")}, content_type="multipart/form-data")
    assert resp.status_code == 401


def test_wrong_format_and_member_rate_limit(make_app, mails):
    app = make_app()
    with app.app_context():
        from pixshare.services import settings_service
        s = settings_service.load_settings(); s["member_uploads_per_hour"] = 2; settings_service.save_settings(s)
    user = member(app.test_client(), mails)
    key = new_key(user)
    assert send(app, key, file=(io.BytesIO(b"MZ..."), "virus.exe")).status_code == 415
    assert send(app, key, file=(io.BytesIO(png()), "a.png")).status_code == 200
    resp = send(app, key, file=(io.BytesIO(png()), "b.png"))
    assert resp.status_code == 429 and "pour ton compte" in resp.get_json()["error"]


def test_extension_zip_download(make_app):
    resp = make_app().test_client().get("/extension/pixshare-extension.zip")
    assert resp.status_code == 200 and resp.mimetype == "application/zip"
    names = zipfile.ZipFile(io.BytesIO(resp.data)).namelist()
    for name in ("manifest.json", "background.js", "popup.html", "options.html", "icons/icon-128.png"):
        assert f"pixshare-extension/{name}" in names, name
