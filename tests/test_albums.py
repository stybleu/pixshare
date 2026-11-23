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


def set_settings(app, **values):
    from pixshare.services import settings_service
    with app.app_context():
        s = settings_service.load_settings()
        s.update(values)
        settings_service.save_settings(s)


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
    set_settings(app, album_guest_per_hour=1)
    guest = app.test_client()
    add(guest, album_id, GREEN)
    assert "Trop de photos" in add(guest, album_id, (30, 120, 200)).get_json()["message"]
    set_settings(app, album_max_photos=1)
    assert "complet" in add(owner, album_id, (200, 200, 40)).get_json()["message"]
    assert "Disallow: /album/" in app.test_client().get("/robots.txt").get_data(as_text=True)
    assert "noindex" in app.test_client().get(f"/album/{album_id}").headers["X-Robots-Tag"]


def test_without_javascript_the_form_still_works(app, mails):
    owner = member(app.test_client(), mails)
    album_id = create(owner)
    resp = add(owner, album_id, GREEN, (30, 120, 200), js=False)
    assert resp.status_code == 302
    assert "2 photo(s) ajoutée(s)" in owner.get(f"/album/{album_id}").get_data(as_text=True)


# ------------------------------------------------------------------ défis photo, réactions, livre d'or

def test_challenges_suggested_by_theme_and_answered_by_guests(app, mails):
    owner = member(app.test_client(), mails)
    album_id = create(owner)
    page = app.test_client().get(f"/album/{album_id}").get_data(as_text=True)
    assert "🎯 Défis photo" in page and "Un éclat de rire" in page                # défis proposés pour un mariage
    guest = app.test_client()
    data = {"csrf_token": csrf(guest, f"/album/{album_id}"), "files": [(io.BytesIO(png(GREEN)), "rire.png")],
            "contributor": "Julie", "challenge": "0"}
    guest.post(f"/album/{album_id}/ajouter", data=data, content_type="multipart/form-data").close()
    page = app.test_client().get(f"/album/{album_id}?defi=0").get_data(as_text=True)
    assert "🎯 Un éclat de rire" in page and "Un éclat de rire · 1 ✓" in page and "par Julie" in page
    assert app.test_client().get(f"/album/{album_id}/photos.json").get_json()["photos"][0]["challenge"] == "Un éclat de rire"
    owner.post(f"/album/{album_id}/animations", data={"csrf_token": csrf(owner, f"/album/{album_id}"),
                                                       "challenges": "La déco\n<b>Les mariés</b>\nLa déco\n",
                                                       "guestbook": "1", "reactions": "1"})
    with app.app_context():
        assert album_service.get(album_id)["challenges"] == ["La déco", "bLes mariés/b"]
    page = app.test_client().get(f"/album/{album_id}").get_data(as_text=True)
    assert "Un éclat de rire" not in page                                      # défi retiré : plus affiché sous la photo


def test_reactions_toggle_and_count(app, mails):
    owner = member(app.test_client(), mails)
    album_id = create(owner)
    add(owner, album_id, GREEN)
    file_id = album_files(app, album_id)[0]["server_name"].split(".")[0]
    a, b = app.test_client(), app.test_client()
    for client in (a, b):
        r = client.post(f"/album/{album_id}/reaction", data={"csrf_token": csrf(client, f"/album/{album_id}"),
                                                              "file_id": file_id, "emoji": "❤️"})
        assert r.status_code == 200
    assert r.get_json() == {"counts": {"❤️": 2}, "mine": ["❤️"]}
    r = a.post(f"/album/{album_id}/reaction", data={"csrf_token": csrf(a, f"/album/{album_id}"), "file_id": file_id, "emoji": "❤️"})
    assert r.get_json()["counts"] == {"❤️": 1} and r.get_json()["mine"] == []  # retirée au 2e appui
    assert a.post(f"/album/{album_id}/reaction", data={"csrf_token": csrf(a, f"/album/{album_id}"), "file_id": file_id,
                                                         "emoji": "💩"}).status_code == 404
    assert a.post(f"/album/{album_id}/reaction", data={"csrf_token": csrf(a, f"/album/{album_id}"), "file_id": "autre",
                                                         "emoji": "❤️"}).status_code == 404
    owner.post(f"/album/{album_id}/animations", data={"csrf_token": csrf(owner, f"/album/{album_id}"), "guestbook": "1"})
    assert 'data-emoji="❤️"' not in app.test_client().get(f"/album/{album_id}").get_data(as_text=True)


def test_guestbook_signed_moderated_and_safe(app, mails, monkeypatch):
    owner = member(app.test_client(), mails)
    album_id = create(owner)
    guest = app.test_client()
    def sign(client, text, name="Julie"):
        return client.post(f"/album/{album_id}/livre-dor", data={"csrf_token": csrf(client, f"/album/{album_id}"),
                                                                 "name": name, "text": text})
    sign(guest, "Félicitations <script>alert(1)</script> aux mariés !")
    sign(guest, "Venez sur http://spam.example")
    page = app.test_client().get(f"/album/{album_id}").get_data(as_text=True)
    assert "Félicitations scriptalert(1)/script aux mariés !" in page and "<script>alert" not in page
    assert "spam.example" not in page
    set_settings(app, album_guestbook_per_hour=3)  # même adresse IP dans les tests : 2 déjà utilisés
    other = app.test_client()
    sign(other, "Premier")
    sign(other, "Second")
    page = app.test_client().get(f"/album/{album_id}").get_data(as_text=True)
    assert "Premier" in page and "Second" not in page
    with app.app_context():
        entry = album_service.guestbook(album_id)[-1]
    assert app.test_client().post(f"/album/{album_id}/livre-dor/{entry['id']}/supprimer",
                                  data={"csrf_token": csrf(guest, f"/album/{album_id}")}).status_code in (400, 404)
    owner.post(f"/album/{album_id}/livre-dor/{entry['id']}/supprimer", data={"csrf_token": csrf(owner, f"/album/{album_id}")})
    with app.app_context():
        assert all(m["id"] != entry["id"] for m in album_service.guestbook(album_id))
    owner.post(f"/album/{album_id}/animations", data={"csrf_token": csrf(owner, f"/album/{album_id}"), "reactions": "1"})
    assert "Signer le livre d'or" not in app.test_client().get(f"/album/{album_id}").get_data(as_text=True)
    owner.post(f"/mes-albums/{album_id}/supprimer", data={"csrf_token": csrf(owner, "/mes-albums"), "confirm": "1"})
    with app.app_context():
        assert album_service.guestbook(album_id) == []                         # effacé avec l'album
    with app.app_context():
        from pixshare.services import legal_log_service as legal
        assert any(r["op"] == legal.LIVRE_OR for r in legal.search())   # registre légal (1 an)


def test_site_texts_say_albums_are_for_members(app):
    client = app.test_client()
    assert "Créez un album souvenir" in client.get("/").get_data(as_text=True)
    cgu = client.get("/cgu").get_data(as_text=True)
    assert "La création d’albums est réservée aux membres" in cgu and "livre d’or" in cgu
    assert "Albums photo à partager par QR code" in client.get("/inscription").get_data(as_text=True)


# ------------------------------------------------------------------ réglages des albums dans l'admin

def big_png(seed=1):
    rng = np.random.default_rng(seed)
    buf = io.BytesIO()
    Image.fromarray(rng.integers(0, 255, (700, 700, 3), dtype=np.uint8)).save(buf, "PNG")  # ~1,4 Mo
    return buf.getvalue()


def test_storage_cap_per_album(app, mails):
    set_settings(app, album_max_mb=10)
    owner = member(app.test_client(), mails)
    album_id = create(owner)
    sent = 0
    for i in range(9):
        r = owner.post(f"/album/{album_id}/ajouter", headers={"X-Requested-With": "pixshare"},
                       data={"csrf_token": csrf(owner, f"/album/{album_id}"), "files": [(io.BytesIO(big_png(i)), f"b{i}.png")]},
                       content_type="multipart/form-data")
        r.close()
        if r.status_code != 200:
            assert "L'album est plein (10 Mo maximum)" in r.get_json()["message"]
            break
        sent += 1
    assert 5 <= sent < 9
    with app.test_request_context():
        assert album_service.usage_bytes(album_id) <= 10 * 1024 * 1024        # jamais au-delà du plafond
    assert "Mo utilisés sur 10 Mo" in owner.get(f"/album/{album_id}").get_data(as_text=True)
    guest = app.test_client()
    r = guest.post(f"/album/{album_id}/ajouter", headers={"X-Requested-With": "pixshare"},
                   data={"csrf_token": csrf(guest, f"/album/{album_id}"), "files": [(io.BytesIO(big_png(99)), "g.png")]},
                   content_type="multipart/form-data")
    assert "L'album est plein (10 Mo maximum)" in r.get_json()["message"]          # invités compris


def test_admin_controls_albums(app, mails):
    owner = member(app.test_client(), mails)
    album_id = create(owner, password="secret12")
    add(owner, album_id, GREEN)
    admin = login(app.test_client())
    page = admin.get("/admin/comptes").get_data(as_text=True)
    assert "📸 Albums (1)" in page and "Mariage de Julie et Marc" in page and "alice@example.com" in page
    assert 'name="album_max_mb"' in page and 'name="albums_per_member"' in page
    assert "/view/" in admin.get(f"/album/{album_id}").get_data(as_text=True)    # l'admin voit l'album protégé
    data = {"csrf_token": csrf(admin, "/admin/comptes"), "accounts_enabled": "1", "guest_max_lifetime_minutes": "120",
            "guest_max_upload_size_mb": "10", "guest_uploads_per_hour": "10", "member_uploads_per_hour": "100",
            "member_strikes_max": "3", "albums_enabled": "0", "albums_per_member": "1", "album_max_mb": "300",
            "album_max_photos": "50", "album_guest_per_hour": "20", "album_guestbook_per_hour": "2"}
    admin.post("/admin/comptes/reglages", data=data)
    from pixshare.services import settings_service
    with app.app_context():
        s = settings_service.load_settings()
    assert (s["albums_enabled"], s["album_max_mb"], s["album_max_photos"]) == (False, 300, 50)
    mine = owner.get("/mes-albums").get_data(as_text=True)
    assert "La création d'albums est suspendue" in mine and "Créer l'album" not in mine
    assert owner.post("/mes-albums", data={"csrf_token": csrf(owner, "/mes-albums"), "name": "Autre"}).status_code == 302
    with app.app_context():
        assert len(album_service.list_for(account_service.find_by_email("alice@example.com")["id"])) == 1
    assert "/view/" not in app.test_client().get(f"/album/{album_id}").get_data(as_text=True)  # protégé : mot de passe demandé
    admin.post("/admin/albums/supprimer", data={"csrf_token": csrf(admin, "/admin/comptes"), "album_id": album_id})
    assert app.test_client().get(f"/album/{album_id}").status_code == 404
    assert app.test_client().post("/admin/albums/supprimer", data={"album_id": "x"}).status_code in (302, 400, 403)


def test_custom_plan_gives_more_albums_and_space(app, mails):
    set_settings(app, albums_per_member=1)
    owner = member(app.test_client(), mails)
    create(owner, name="Un")
    assert "nombre maximum d'albums" in owner.get("/mes-albums").get_data(as_text=True)
    admin = login(app.test_client())
    with app.app_context():
        acc = account_service.find_by_email("alice@example.com")
    admin.post("/admin/comptes/formule", data={"csrf_token": csrf(admin, "/admin/comptes"), "account_id": acc["id"],
                                               "do": "save", "name": "Photographe", "albums": "5", "album_mb": "2000"})
    page = owner.get("/mes-albums").get_data(as_text=True)
    assert "Créer l'album" in page and "5 album(s)" in page and "2000 Mo" in page
    assert "5 album(s) · 2000 Mo par album" in owner.get("/compte").get_data(as_text=True)


def test_limits_table_shows_album_limits(app):
    page = app.test_client().get("/inscription").get_data(as_text=True)
    assert "20 album(s) de 500 photos et 200 Mo" in page
    set_settings(app, albums_enabled=False)
    assert "Albums photo à partager" not in app.test_client().get("/inscription").get_data(as_text=True)


def test_google_preview_and_album_landing_page(app):
    client = app.test_client()
    home = client.get("/").get_data(as_text=True)
    # « hébergeur d'images » : la recherche qui amène le plus de visiteurs (Search Console) reste dans le titre
    assert "<title>PixShare – Hébergeur d&#39;images gratuit et albums photo partagés</title>" in home
    assert 'name="description" content="Hébergez et partagez vos images gratuitement, sans inscription' in home
    assert "Hébergeur d&#39;images gratuit, sans inscription" in home
    assert "Albums souvenirs d'événement partagés par QR code" in home                 # données structurées
    assert 'og:description" content="Hébergez et partagez vos images' in home
    page = client.get("/album-souvenir")
    text = page.get_data(as_text=True)
    assert page.status_code == 200 and "Un album souvenir pour votre événement" in text
    assert '"@type": "FAQPage"' in text and 'content="index, follow"' in text
    assert "/album-souvenir" in client.get("/sitemap.xml").get_data(as_text=True)
    assert "Albums souvenirs" in home                                                  # lien dans le pied de page
