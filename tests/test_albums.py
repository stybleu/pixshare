"""Albums photo des membres, partagés par QR code, où les invités peuvent ajouter leurs photos."""
import io
import zipfile

import cv2
import numpy as np
import pytest
from PIL import Image

from conftest import csrf, login
from pixshare.services import account_service, album_service, json_services, qr_service
from test_accounts import PASSWORD, mails, member, png  # noqa: F401
from test_nsfw_moderation import GREEN, ORANGE, fake_nudenet  # noqa: F401


@pytest.fixture
def app(make_app):
    return make_app(MODERATION_PENDING_IMAGES=True)


def create(client, name="Mariage de Julie et Marc", **extra):
    data = {"csrf_token": csrf(client, "/mes-albums"), "name": name, "description": "Merci à tous !",
            "guests_can_add": "1", "theme": "mariage", "password": ""}
    data.update(extra)
    resp = client.post("/mes-albums", data=data)
    assert resp.status_code == 302, resp.data
    return resp.headers["Location"].rsplit("/", 1)[-1]


def add(client, album_id, *colors, contributor="", js=True, names=None):
    files = [(io.BytesIO(png(c)), (names or [f"p{i}.png" for i in range(len(colors))])[i]) for i, c in enumerate(colors)]
    data = {"csrf_token": csrf(client, f"/album/{album_id}"), "files": files, "contributor": contributor}
    headers = {"X-Requested-With": "pixshare"} if js else {}
    resp = client.post(f"/album/{album_id}/ajouter", data=data, content_type="multipart/form-data", headers=headers)
    resp.close()
    return resp


def album_files(app, album_id):
    with app.app_context():
        return [m for m in json_services.load_db().values() if m.get("album_id") == album_id]


def test_only_members_create_albums_and_owner_fills_it(app, mails):
    assert app.test_client().get("/mes-albums").status_code == 302           # sans compte : connexion
    owner = member(app.test_client(), mails)
    assert "Mes albums" in owner.get("/compte").get_data(as_text=True)
    album_id = create(owner)
    resp = add(owner, album_id, GREEN, (30, 120, 200), (200, 200, 40))
    assert resp.status_code == 200 and resp.get_json()["added"] == 3
    files = album_files(app, album_id)
    assert len(files) == 3 and all(f["status"] == "active" and f["account_id"] for f in files)
    with app.app_context():
        from pixshare.services.time_service import parse_dt
        f = files[0]
        days = (parse_dt(f["expires_at"]) - parse_dt(f["uploaded_at"])).days
    assert days >= 360                                                      # durée des membres : 1 an
    page = owner.get(f"/album/{album_id}").get_data(as_text=True)
    assert "Mariage de Julie et Marc" in page and "Vous êtes l'organisateur" in page and "💍" in page
    assert page.count("/view/") >= 3
    mine = owner.get("/mes-albums").get_data(as_text=True)
    assert "3 photo(s)" in mine and "Affiche à imprimer" in mine


def test_guests_add_photos_with_their_name_and_strict_filter(app, mails):
    owner = member(app.test_client(), mails)
    album_id = create(owner)
    guest = app.test_client()
    page = guest.get(f"/album/{album_id}").get_data(as_text=True)
    assert "Ajoutez vos photos" in page and "Votre prénom" in page
    add(guest, album_id, GREEN, contributor="Julie")
    add(guest, album_id, ORANGE, contributor="Marc")                         # douteuse (admin présent : en attente)
    files = {f["album_contributor"]: f for f in album_files(app, album_id)}
    assert files["Julie"]["status"] == "active" and files["Julie"]["account_id"] == ""
    assert files["Julie"]["album_guest"] is True
    assert files["Marc"]["status"] == "pending"                               # filtre des visiteurs, pas des membres
    public = app.test_client().get(f"/album/{album_id}").get_data(as_text=True)
    assert "par Julie" in public and "par Marc" not in public                 # en attente : invisible
    assert "En vérification" in owner.get(f"/album/{album_id}").get_data(as_text=True)
    with app.app_context():
        assert not account_service.find_by_email("alice@example.com").get("strikes")  # rien sur le compte du membre
    owner.post(f"/mes-albums/{album_id}/modifier", data={"csrf_token": csrf(owner, "/mes-albums"), "name": "Mariage"})
    closed = app.test_client()
    resp = closed.post(f"/album/{album_id}/ajouter", headers={"X-Requested-With": "pixshare"},
                       data={"csrf_token": csrf(closed), "files": [(io.BytesIO(png(GREEN)), "x.png")]},
                       content_type="multipart/form-data")
    assert resp.status_code == 403                                            # ajout fermé aux invités
    assert "Ajoutez vos photos" not in app.test_client().get(f"/album/{album_id}").get_data(as_text=True)


def test_filter_by_contributor_and_cover(app, mails):
    owner = member(app.test_client(), mails)
    album_id = create(owner)
    add(app.test_client(), album_id, GREEN, contributor="Julie")
    add(app.test_client(), album_id, (30, 120, 200), contributor="Léo")
    page = app.test_client().get(f"/album/{album_id}?par=Julie").get_data(as_text=True)
    assert "Julie (1)" in page and "par Julie" in page and "par Léo" not in page
    julie = next(f for f in album_files(app, album_id) if f["album_contributor"] == "Julie")
    file_id = julie["server_name"].split(".")[0]
    owner.post(f"/album/{album_id}/apparence", data={"csrf_token": csrf(owner, f"/album/{album_id}"), "cover": file_id})
    assert f"background-image: url('/view/{file_id}?m=1')" in app.test_client().get(f"/album/{album_id}").get_data(as_text=True)


def test_password_protects_page_photos_and_zip(app, mails):
    owner = member(app.test_client(), mails)
    album_id = create(owner, password="mariage2026")
    add(owner, album_id, GREEN)
    guest = app.test_client()
    locked = guest.get(f"/album/{album_id}").get_data(as_text=True)
    assert "protégé par un mot de passe" in locked and "/view/" not in locked
    assert guest.get(f"/album/{album_id}/photos.json").status_code == 404
    assert guest.get(f"/album/{album_id}/tout.zip").status_code == 404
    assert add(guest, album_id, GREEN).status_code == 403
    guest.post(f"/album/{album_id}/deverrouiller", data={"csrf_token": csrf(guest, f"/album/{album_id}"), "password": "faux"})
    assert "/view/" not in guest.get(f"/album/{album_id}").get_data(as_text=True)
    guest.post(f"/album/{album_id}/deverrouiller", data={"csrf_token": csrf(guest, f"/album/{album_id}"), "password": "mariage2026"})
    assert "/view/" in guest.get(f"/album/{album_id}").get_data(as_text=True)
    assert len(guest.get(f"/album/{album_id}/photos.json").get_json()["photos"]) == 1


def test_qr_code_poster_slideshow_and_zip(app, mails):
    owner = member(app.test_client(), mails)
    album_id = create(owner)
    add(owner, album_id, GREEN, (30, 120, 200), names=["a.png", "a.png"])
    guest = app.test_client()
    qr = guest.get(f"/album/{album_id}/qr.png")
    assert qr.status_code == 200 and qr.mimetype == "image/png"
    img = np.array(Image.open(io.BytesIO(qr.data)).convert("L"))
    value, _pts, _ = cv2.QRCodeDetector().detectAndDecode(img)
    assert value.endswith(f"/album/{album_id}")                               # le QR code ouvre bien l'album
    assert guest.get(f"/album/{album_id}/qr.svg").data.startswith(b"<svg")
    poster = guest.get(f"/album/{album_id}/affiche").get_data(as_text=True)
    assert "Mariage de Julie et Marc" in poster and "<svg" in poster and "Scannez pour voir les photos" in poster
    assert "Diaporama" in guest.get(f"/album/{album_id}/diaporama").get_data(as_text=True)
    resp = guest.get(f"/album/{album_id}/tout.zip")
    archive = zipfile.ZipFile(io.BytesIO(resp.data))
    names = archive.namelist()
    assert resp.mimetype == "application/zip" and len(names) == 2 and len(set(names)) == 2
    assert archive.testzip() is None
    Image.open(io.BytesIO(archive.read(names[0]))).verify()


def test_qr_encoder_handles_long_links():
    for text in ("https://pixshare.fr/album/abcdefghijk", "x" * 106, "é" * 40):
        img = np.array(Image.open(io.BytesIO(qr_service.png(text))).convert("L"))
        assert cv2.QRCodeDetector().detectAndDecode(img)[0] == text
    with pytest.raises(ValueError):
        qr_service.png("x" * 107)


def test_owner_customises_the_look(app, mails):
    owner = member(app.test_client(), mails)
    album_id = create(owner, theme="hommage")
    page = owner.get(f"/album/{album_id}").get_data(as_text=True)
    assert "🕊️" in page and "#5d6670" in page                                # thème sobre
    owner.post(f"/album/{album_id}/apparence", data={"csrf_token": csrf(owner, f"/album/{album_id}"), "theme": "fete",
                                                     "own_color": "1", "accent": "#ff0055", "font": "manuscrite",
                                                     "layout": "mosaique"})
    page = app.test_client().get(f"/album/{album_id}").get_data(as_text=True)
    assert "#ff0055" in page and "cursive" in page and "#14121f" in page
    owner.post(f"/album/{album_id}/apparence", data={"csrf_token": csrf(owner, f"/album/{album_id}"), "theme": "fete",
                                                     "own_color": "1", "accent": "red;}</style><script>", "font": "x"})
    page = app.test_client().get(f"/album/{album_id}").get_data(as_text=True)
    assert "<script>alert" not in page and "red;}" not in page and "#a855f7" in page   # couleur refusée


def test_only_the_owner_manages_the_album(app, mails):
    owner = member(app.test_client(), mails)
    album_id = create(owner)
    add(app.test_client(), album_id, GREEN, contributor="Julie")
    file_id = album_files(app, album_id)[0]["server_name"].split(".")[0]
    other = member(app.test_client(), mails, email="bob@example.com")
    for client in (app.test_client(), other):
        token = csrf(client, f"/album/{album_id}")
        assert client.post(f"/album/{album_id}/photo/{file_id}/supprimer", data={"csrf_token": token}).status_code == 404
        assert client.post(f"/mes-albums/{album_id}/supprimer", data={"csrf_token": token, "confirm": "1"}).status_code == 404
        assert client.post(f"/album/{album_id}/apparence", data={"csrf_token": token, "theme": "fete"}).status_code == 404
    owner.post(f"/album/{album_id}/photo/{file_id}/supprimer", data={"csrf_token": csrf(owner, f"/album/{album_id}")})
    assert album_files(app, album_id)[0]["status"] == "deleted"


def test_deleting_album_or_account_removes_every_photo(app, mails):
    owner = member(app.test_client(), mails)
    first = create(owner, name="Premier")
    second = create(owner, name="Second")
    add(owner, first, GREEN)
    add(app.test_client(), first, (30, 120, 200), contributor="Invité")
    add(app.test_client(), second, GREEN, contributor="Invité")
    owner.post(f"/mes-albums/{first}/supprimer", data={"csrf_token": csrf(owner, "/mes-albums"), "confirm": "1"})
    assert all(f["status"] == "deleted" for f in album_files(app, first))
    assert app.test_client().get(f"/album/{first}").status_code == 404
    owner.post("/compte/supprimer", data={"csrf_token": csrf(owner, "/compte"), "password": PASSWORD,
                                          "confirm": "1"})
    with app.app_context():
        assert album_service.get(second) is None
    assert all(f["status"] == "deleted" for f in album_files(app, second))


def test_limits_photos_only_and_safe_text(app, mails, monkeypatch):
    owner = member(app.test_client(), mails)
    album_id = create(owner, name="<script>alert(1)</script>Fête")
    with app.app_context():
        assert "<" not in album_service.get(album_id)["name"]
    txt = owner.post(f"/album/{album_id}/ajouter", headers={"X-Requested-With": "pixshare"},
                     data={"csrf_token": csrf(owner, f"/album/{album_id}"), "files": [(io.BytesIO(b"hello"), "a.txt")]},
                     content_type="multipart/form-data")
    assert txt.status_code == 400 and "seules les photos" in txt.get_json()["message"]
    monkeypatch.setattr(album_service, "GUEST_UPLOADS_PER_HOUR", 1)
    guest = app.test_client()
    add(guest, album_id, GREEN)
    assert "Trop de photos" in add(guest, album_id, (30, 120, 200)).get_json()["message"]
    monkeypatch.setattr(album_service, "PHOTOS_PER_ALBUM", 1)
    assert "complet" in add(owner, album_id, (200, 200, 40)).get_json()["message"]
    assert "Disallow: /album/" in app.test_client().get("/robots.txt").get_data(as_text=True)
    assert "noindex" in app.test_client().get(f"/album/{album_id}").headers["X-Robots-Tag"]


def test_without_javascript_the_form_still_works(app, mails):
    owner = member(app.test_client(), mails)
    album_id = create(owner)
    resp = add(owner, album_id, GREEN, (30, 120, 200), js=False)
    assert resp.status_code == 302
    assert "2 photo(s) ajoutée(s)" in owner.get(f"/album/{album_id}").get_data(as_text=True)
