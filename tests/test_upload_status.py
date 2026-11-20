"""Après un envoi : la page suit la vérification automatique, sans message trompeur."""
import io

from PIL import Image

from conftest import csrf
from pixshare.services.json_services import load_db, save_db


def png():
    buf = io.BytesIO()
    Image.new("RGB", (40, 40), (90, 30, 160)).save(buf, "PNG")
    return buf.getvalue()


def send(client):
    resp = client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(png()), "photo.png")},
                       content_type="multipart/form-data")
    resp.close()
    return resp


def set_meta(app, file_id, **values):
    with app.app_context():
        db = load_db()
        db[file_id].update(values)
        save_db(db)


def test_status_follows_moderation_and_stays_private(make_app):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    owner = app.test_client()
    send(owner)
    with app.app_context():
        file_id = next(iter(load_db()))
    page = owner.get("/").get_data(as_text=True)
    assert "reste privée jusqu'à la validation" not in page
    set_meta(app, file_id, status="pending", moderation_decision="pending")
    page = owner.get(f"/?nouveau={file_id}").get_data(as_text=True)
    assert f'data-checking="{file_id}"' in page and "Vérification automatique" in page

    url = f"/mes-fichiers/statut?ids={file_id},inconnu"
    assert owner.get(url).get_json() == {file_id: "checking", "inconnu": "gone"}
    assert app.test_client().get(url).get_json() == {file_id: "gone", "inconnu": "gone"}  # pas à lui : rien n'est dévoilé

    set_meta(app, file_id, moderation_decision="manual_review")
    assert owner.get(url).get_json()[file_id] == "review"
    assert "En attente de vérification" in owner.get("/").get_data(as_text=True)

    set_meta(app, file_id, status="active", moderation_decision="approved")
    resp = owner.get(url)
    assert resp.get_json()[file_id] == "active" and resp.headers["Cache-Control"] == "no-store"
    assert f'data-checking="{file_id}"' not in owner.get("/").get_data(as_text=True)


def test_upload_message_is_accurate(make_app):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    owner = app.test_client()
    send(owner)
    with app.app_context():
        file_id, meta = next(iter(load_db().items()))
    if meta["status"] == "pending":
        page = owner.get("/").get_data(as_text=True)
        assert "Vérification automatique en cours" in page
