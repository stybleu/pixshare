"""Changer le filtre d'une image déjà envoyée : même lien, photo d'origine gardée à part pour revenir à « Normal »."""
import io
import os

from PIL import Image

from conftest import csrf
from test_accounts import mails, member, png, records, upload  # noqa: F401

COLOR = (200, 40, 40)


def pixel(app, client, file_id):
    body = client.get(f"/view/{file_id}?raw=1").data
    with Image.open(io.BytesIO(body)) as im:
        return im.convert("RGB").getpixel((5, 5))


def apply(client, file_id, name, strength=100):
    resp = client.post(f"/filtre/{file_id}", data={"csrf_token": csrf(client), "photo_filter": name,
                                                   "filter_strength": str(strength)})
    resp.close()
    return resp


def source_files(app):
    folder = os.path.join(app.config["UPLOAD_FOLDER"], "_sources")
    return sorted(os.listdir(folder)) if os.path.isdir(folder) else []


def test_filter_can_be_changed_then_removed(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    upload(user, "photo.png", png(COLOR))
    file_id, before = next(iter(records(app).items()))
    guest = app.test_client()

    # 1. noir et blanc : la photo devient grise, le lien et l'expiration ne bougent pas
    assert apply(user, file_id, "noir_blanc").status_code == 302
    after = records(app)[file_id]
    assert after["photo_filter"] == "noir_blanc" and after["expires_at"] == before["expires_at"]
    r, g, b = pixel(app, guest, file_id)
    assert abs(r - g) <= 3 and abs(g - b) <= 3
    assert source_files(app) == [f"{file_id}.png"]

    # 2. un autre filtre part de la photo d'origine (pas de la photo grise) : la couleur revient
    assert apply(user, file_id, "chaud").status_code == 302
    r, g, b = pixel(app, guest, file_id)
    assert r - g > 60
    assert records(app)[file_id]["photo_filter"] == "chaud"
    assert source_files(app) == [f"{file_id}.png"]

    # 3. « Normal » : photo d'origine remise, copie effacée
    assert apply(user, file_id, "").status_code == 302
    assert pixel(app, guest, file_id) == COLOR
    assert "photo_filter" not in records(app)[file_id]
    assert source_files(app) == []
    assert len(records(app)) == 1


def test_normal_without_filter_is_refused(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    upload(user, "photo.png", png(COLOR))
    file_id = next(iter(records(app)))
    assert apply(user, file_id, "").status_code == 302
    assert "photo_filter" not in records(app)[file_id] and records(app)[file_id].get("replace_count", 0) == 0


def test_source_is_removed_with_the_image(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    upload(user, "photo.png", png(COLOR))
    file_id = next(iter(records(app)))
    apply(user, file_id, "dramatique")
    assert source_files(app)
    user.post(f"/delete/{file_id}", data={"csrf_token": csrf(user)}).close()
    assert records(app)[file_id]["status"] == "deleted"
    assert source_files(app) == []


def test_replacing_the_photo_drops_the_old_source(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    upload(user, "photo.png", png(COLOR))
    file_id = next(iter(records(app)))
    apply(user, file_id, "froid")
    user.post(f"/remplacer/{file_id}", data={"csrf_token": csrf(user), "file": (io.BytesIO(png((10, 10, 200))), "autre.png")},
              content_type="multipart/form-data").close()
    assert source_files(app) == [] and "photo_filter" not in records(app)[file_id]


def test_only_the_owner_can_change_the_filter(make_app, mails):
    app = make_app()
    owner = member(app.test_client(), mails)
    upload(owner, "photo.png", png(COLOR))
    file_id = next(iter(records(app)))
    stranger = member(app.test_client(), mails, email="bob@example.com")
    assert apply(stranger, file_id, "retro").status_code == 404
    guest = app.test_client()
    assert apply(guest, file_id, "retro").status_code == 302  # renvoyé vers la connexion
    assert "photo_filter" not in records(app)[file_id] and source_files(app) == []


def test_unknown_filter_is_refused(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    upload(user, "photo.png", png(COLOR))
    file_id = next(iter(records(app)))
    for bad in ("document", "n-importe-quoi"):
        apply(user, file_id, bad).close()
    assert "photo_filter" not in records(app)[file_id] and source_files(app) == []


def test_reports_are_kept_when_the_filter_changes(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    upload(user, "photo.png", png(COLOR))
    file_id = next(iter(records(app)))
    with app.app_context():
        from pixshare.services import json_services
        db = json_services.load_db()
        db[file_id]["reports"] = [{"reason": "autre", "at": "2026-11-25T10:00:00"}]
        json_services.save_db(db)
    apply(user, file_id, "retro")
    assert len(records(app)[file_id]["reports"]) == 1


def test_button_is_shown_to_the_owner_only(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    upload(user, "photo.png", png(COLOR))
    html = user.get("/").get_data(as_text=True)
    assert "Changer le filtre" in html and "Dramatique" in html and "Normal (photo d'origine)" not in html
    file_id = next(iter(records(app)))
    apply(user, file_id, "retro")
    html = user.get("/").get_data(as_text=True)
    assert "actuel : Rétro" in html and "Normal (photo d'origine)" in html


def test_legal_texts_mention_the_kept_original(make_app):
    client = make_app().test_client()
    cgu = client.get("/cgu").get_data(as_text=True)
    assert "photo d’origine" in cgu and "changer le filtre d’une photo déjà envoyée" in cgu
    legal = client.get("/mentions-legales").get_data(as_text=True)
    assert "Photo d’origine d’une image à laquelle un membre a appliqué un filtre" in legal
    faq = client.get("/faq").get_data(as_text=True)
    assert "Puis-je changer le filtre d&#39;une photo déjà envoyée ?" in faq or "Puis-je changer le filtre d'une photo déjà envoyée ?" in faq
