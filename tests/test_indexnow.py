"""IndexNow (Bing) : fichier de clé à la racine, envoi des seules pages publiques, une fois par version."""
import json

from conftest import csrf, login
from pixshare.services import indexnow_service as ix


class FakeResp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def capture(monkeypatch, code=200):
    sent = []

    def fake_urlopen(req, timeout=0):
        sent.append(json.loads(req.data))
        r = FakeResp()
        r.status = code
        return r
    monkeypatch.setattr(ix.urllib.request, "urlopen", fake_urlopen)
    return sent


def test_key_file_is_served_at_the_root(make_app):
    app = make_app()
    with app.app_context():
        k = ix.key()
    c = app.test_client()
    r = c.get(f"/{k}.txt")
    assert r.status_code == 200 and r.get_data(as_text=True) == k and r.mimetype == "text/plain"
    assert c.get("/autre-chose.txt").status_code == 404
    assert c.get("/robots.txt").status_code == 200            # pas d'interférence


def test_only_public_pages_are_sent(make_app, monkeypatch):
    app = make_app()
    sent = capture(monkeypatch)
    with app.app_context():
        ok, msg = ix.submit()
        assert ok and "reçu" in msg
        k = ix.key()
    body = sent[0]
    assert body["host"] == "pixshare.fr" and body["key"] == k and body["keyLocation"] == f"https://pixshare.fr/{k}.txt"
    assert "https://pixshare.fr/faq" in body["urlList"] and "https://pixshare.fr/faq?lang=en" in body["urlList"]
    assert not any(p in u for u in body["urlList"] for p in ("/file/", "/album/", "/admin", "/view/", "/download/"))


def test_sent_once_per_deploy(make_app, monkeypatch):
    app = make_app()
    sent = capture(monkeypatch)
    monkeypatch.setenv("RENDER_GIT_COMMIT", "abc1234")
    ix.maybe_submit_after_deploy(app)
    ix.maybe_submit_after_deploy(app)                         # même version : rien de plus
    assert len(sent) == 1
    monkeypatch.setenv("RENDER_GIT_COMMIT", "def5678")
    ix.maybe_submit_after_deploy(app)
    assert len(sent) == 2


def test_admin_button_and_status(make_app, monkeypatch):
    app = make_app()
    sent = capture(monkeypatch, code=202)
    admin = app.test_client()
    login(admin)
    page = admin.get("/admin/system").get_data(as_text=True)
    assert "IndexNow" in page and "Aucun envoi" in page
    admin.post("/admin/indexnow", data={"csrf_token": csrf(admin, "/admin/system")})
    assert len(sent) == 1
    page = admin.get("/admin/system").get_data(as_text=True)
    assert "clé en cours de vérification" in page and "12 page(s)" in page
    assert admin.post("/admin/indexnow").status_code in (400, 403)       # sans jeton CSRF
