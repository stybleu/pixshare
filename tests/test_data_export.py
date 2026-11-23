"""« Télécharger mes données » : seulement les siennes, sans aucun secret."""
import io
import json
import zipfile

from conftest import csrf
from test_accounts import mails, member, records, upload  # noqa: F401


def export(client):
    r = client.post("/compte/mes-donnees", data={"csrf_token": csrf(client, "/compte")})
    assert r.status_code == 200 and r.mimetype == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.data))
    return json.loads(z.read("mes-donnees.json")), z.read("mes-donnees.txt").decode("utf-8"), r


def test_member_gets_only_own_data_without_secrets(make_app, mails):
    app = make_app()
    alice = member(app.test_client(), mails, email="alice@example.com")
    upload(alice, "alice.png", file_password="secret123")
    bob = member(app.test_client(), mails, email="bob@example.com")
    upload(bob, "bob.png")
    data, text, resp = export(alice)
    assert "attachment" in resp.headers["Content-Disposition"] and resp.headers["Cache-Control"].startswith("private")
    assert data["compte"]["adresse_e_mail"] == "alice@example.com"
    assert [f["nom"] for f in data["fichiers"]] == ["alice.png"]
    assert data["fichiers"][0]["protege_par_mot_de_passe"] is True
    assert any(r["operation"] == "création" for r in data["registre_legal"])
    raw = json.dumps(data) + text
    for secret in ("bob", "password_hash", "pbkdf2", "scrypt", "ext_key_hash", "secret123", '"h"'):
        assert secret not in raw, secret
    assert "VOS DONNÉES SUR PIXSHARE" in text and "alice.png" in text


def test_needs_login_and_csrf(make_app, mails):
    app = make_app()
    guest = app.test_client()
    r = guest.post("/compte/mes-donnees", data={"csrf_token": csrf(guest)})
    assert r.status_code in (302, 303) and "/connexion" in r.headers["Location"]
    user = member(app.test_client(), mails)
    assert user.post("/compte/mes-donnees").status_code in (400, 403)
    assert "Télécharger mes données" in user.get("/compte").get_data(as_text=True)
