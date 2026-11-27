"""Comptage des vues : cookie posé seulement pour une photo à vues limitées, et pour la durée de la photo."""
import io
import re

from PIL import Image

from conftest import csrf
from pixshare.services import json_services


def png():
    buf = io.BytesIO()
    Image.new("RGB", (30, 30), (200, 40, 40)).save(buf, "PNG")
    return buf.getvalue()


def send(client, **extra):
    data = {"csrf_token": csrf(client), "file": (io.BytesIO(png()), "a.png")}
    data.update(extra)
    client.post("/", data=data, content_type="multipart/form-data").close()


def only_file(app):
    with app.app_context():
        db = json_services.load_db()
    assert len(db) == 1
    return next(iter(db.items()))


def cookie_header(resp):
    return " ".join(resp.headers.getlist("Set-Cookie"))


def test_no_cookie_for_a_photo_without_view_limit(make_app):
    app = make_app()
    send(app.test_client())
    file_id, meta = only_file(app)
    assert not meta.get("view_limit_enabled")
    for url in (f"/view/{file_id}?raw=1", f"/file/{file_id}"):
        resp = app.test_client().get(url, headers={"User-Agent": "Mozilla/5.0 Firefox"})
        assert resp.status_code == 200
        assert "visitor_token" not in cookie_header(resp), url


def test_views_are_still_counted_once_without_cookie(make_app):
    app = make_app()
    send(app.test_client())
    file_id, _ = only_file(app)
    visitor = app.test_client()
    headers = {"User-Agent": "Mozilla/5.0 Firefox"}
    for _ in range(3):
        visitor.get(f"/view/{file_id}?raw=1", headers=headers).close()
    other = app.test_client()
    other.get(f"/view/{file_id}?raw=1", headers={"User-Agent": "Mozilla/5.0 Safari"}).close()
    assert only_file(app)[1]["views"] == 2
    with app.app_context():
        tokens = json_services.load_views()[file_id]
    assert len(tokens) == 2 and all(t.startswith("e:") for t in tokens)  # pas de jeton aléatoire par requête


def test_cookie_only_for_a_photo_with_view_limit(make_app):
    app = make_app()
    # envoi avec limite de vues : réservé aux comptes ou à l'admin
    from conftest import login as admin_login
    owner = admin_login(app.test_client())
    send(owner, view_limit_enabled="on", max_views="5")
    file_id, meta = only_file(app)
    assert meta.get("view_limit_enabled")
    visitor = app.test_client()
    headers = {"User-Agent": "Mozilla/5.0 Firefox"}
    assert visitor.get(f"/view/{file_id}?raw=1", headers=headers).status_code == 404  # pas encore passé par la page
    resp = visitor.get(f"/file/{file_id}", headers=headers)
    assert resp.status_code == 200
    header = cookie_header(resp)
    assert "visitor_token" in header
    max_age = int(re.search(r"Max-Age=(\d+)", header).group(1))
    assert 60 <= max_age <= 60 * 60 * 24 * 365
    # la même personne garde l'accès à l'image et n'est pas recomptée
    assert visitor.get(f"/view/{file_id}?raw=1", headers=headers).status_code == 200
    visitor.get(f"/file/{file_id}", headers=headers).close()
    assert only_file(app)[1]["views"] == 1


def test_texts_describe_the_conditional_cookie(make_app):
    client = make_app().test_client()
    legal = client.get("/mentions-legales").get_data(as_text=True)
    assert "uniquement pour une photo dont l’envoyeur a choisi la suppression après un" in legal
    assert "sans cookie" in legal
    assert "aucun cookie n’est utilisé pour compter les vues" in client.get("/cgu").get_data(as_text=True).replace("Aucun", "aucun")
    assert "pour une photo à vues limitées" in client.get("/faq").get_data(as_text=True)
