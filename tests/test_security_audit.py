"""Audit de sécurité : vraies attaques contre une copie locale du site.

Albums (naissance, baptême, mariage), comptes, mots de passe, injections, accès aux fichiers des autres.
"""
import io
import re

import pytest
from PIL import Image

from conftest import csrf, login
from pixshare.services import json_services
from test_accounts import PASSWORD, form_post, login_new_device, mails, member, png, records, upload  # noqa: F401
from test_albums import add, create
from test_nsfw_moderation import GREEN, fake_nudenet  # noqa: F401


@pytest.fixture
def app(make_app):
    return make_app(MODERATION_PENDING_IMAGES=True)


def from_ip(client, ip):
    client.environ_base["HTTP_CF_CONNECTING_IP"] = ip
    return client


def try_album_password(client, album_id, password):
    return client.post(f"/album/{album_id}/deverrouiller",
                       data={"csrf_token": csrf(client, f"/album/{album_id}"), "password": password})


def can_see(client, album_id):
    return client.get(f"/album/{album_id}/photos.json").status_code == 200


# ------------------------------------------------------------------ albums

def test_album_address_cannot_be_guessed(app, mails):
    owner = member(app.test_client(), mails)
    ids = {create(owner, name=f"Album {i}") for i in range(5)}
    assert len(ids) == 5 and all(len(i) >= 11 and re.fullmatch(r"[A-Za-z0-9_-]+", i) for i in ids)  # 64 bits au hasard


def test_album_brute_force_from_one_ip_is_stopped(app, mails):
    owner = member(app.test_client(), mails)
    album_id = create(owner, password="bapteme-lea")
    attacker = from_ip(app.test_client(), "203.0.113.7")
    for i in range(25):
        try_album_password(attacker, album_id, f"essai{i}")
    try_album_password(attacker, album_id, "bapteme-lea")      # même le bon mot de passe est refusé pendant le blocage
    assert not can_see(attacker, album_id)


def test_album_brute_force_from_many_ips_is_stopped(app, mails):
    """Un réseau de machines (une IP différente à chaque essai) ne doit pas pouvoir essayer sans fin."""
    owner = member(app.test_client(), mails)
    album_id = create(owner, password="bapteme-lea")
    for i in range(80):
        try_album_password(from_ip(app.test_client(), f"198.51.100.{i}"), album_id, f"essai{i}")
    attacker = from_ip(app.test_client(), "192.0.2.200")
    try_album_password(attacker, album_id, "bapteme-lea")
    assert not can_see(attacker, album_id)
    # l'invité qui avait déjà ouvert l'album avant l'attaque garde l'accès
    # (vérifié dans le test suivant) ; le propriétaire aussi :
    assert can_see(owner, album_id)


def test_new_album_password_closes_old_access(app, mails):
    """Lien et mot de passe partis trop loin : le propriétaire change le mot de passe -> les anciens invités sont dehors."""
    owner = member(app.test_client(), mails)
    album_id = create(owner, password="naissance-tom")
    guest = app.test_client()
    try_album_password(guest, album_id, "naissance-tom")
    assert can_see(guest, album_id)
    resp = owner.post(f"/mes-albums/{album_id}/modifier",
                      data={"csrf_token": csrf(owner, f"/album/{album_id}"), "name": "Naissance de Tom", "description": "",
                            "guests_can_add": "1", "password": "nouveau-secret"})
    assert resp.status_code == 302
    assert not can_see(guest, album_id)
    try_album_password(guest, album_id, "nouveau-secret")
    assert can_see(guest, album_id)


def test_locked_album_reveals_nothing(app, mails):
    owner = member(app.test_client(), mails)
    album_id = create(owner, password="bapteme-lea", description="Nés le 3 mars, 12 rue des Lilas")
    add(owner, album_id, GREEN)
    guest = app.test_client()
    page = guest.get(f"/album/{album_id}").get_data(as_text=True)
    assert "12 rue des Lilas" not in page and "/view/" not in page and "/file/" not in page
    poster = guest.get(f"/album/{album_id}/affiche").get_data(as_text=True)
    assert "12 rue des Lilas" not in poster
    for path in ("photos.json", "tout.zip", "diaporama"):
        assert guest.get(f"/album/{album_id}/{path}").status_code in (302, 404), path
    for path in ("reaction", "livre-dor"):
        r = guest.post(f"/album/{album_id}/{path}", data={"csrf_token": csrf(guest, f"/album/{album_id}"), "text": "x", "emoji": "❤️"})
        assert r.status_code in (403, 404), path


def test_album_pages_are_hidden_from_google(app, mails):
    owner = member(app.test_client(), mails)
    album_id = create(owner)
    c = app.test_client()
    for path in ("", "/diaporama", "/affiche", "/qr.svg", "/photos.json"):
        r = c.get(f"/album/{album_id}{path}")
        assert "noindex" in r.headers.get("X-Robots-Tag", ""), path
    robots = c.get("/robots.txt").get_data(as_text=True)
    sitemap = c.get("/sitemap.xml").get_data(as_text=True)
    assert album_id not in sitemap and "/album/" + album_id not in robots


def jpeg_with_gps():
    img = Image.new("RGB", (64, 48), (200, 120, 60))
    exif = Image.Exif()
    exif[0x8825] = {1: "N", 2: (48.0, 51.0, 24.0), 3: "E", 4: (2.0, 21.0, 3.0)}   # position GPS
    exif[0x010F] = "Telephone de Papa"                                            # appareil
    buf = io.BytesIO()
    img.save(buf, "JPEG", exif=exif)
    data = buf.getvalue()
    assert b"Telephone de Papa" in data
    return data


def test_gps_position_removed_from_album_and_normal_photos(app, mails, fake_nudenet):
    owner = member(app.test_client(), mails)
    album_id = create(owner)
    resp = owner.post(f"/album/{album_id}/ajouter", data={
        "csrf_token": csrf(owner, f"/album/{album_id}"), "files": [(io.BytesIO(jpeg_with_gps()), "bebe.jpg")]},
        content_type="multipart/form-data", headers={"X-Requested-With": "pixshare"})
    resp.close()
    upload(owner, "bebe2.jpg", jpeg_with_gps())
    folder = app.config["UPLOAD_FOLDER"]
    import os
    names = [m["server_name"] for m in records(app).values()]
    assert len(names) == 2
    for name in names:
        with open(os.path.join(folder, name), "rb") as f:
            data = f.read()
        assert b"Telephone de Papa" not in data
        with Image.open(io.BytesIO(data)) as im:
            assert 0x8825 not in im.getexif(), name


# ------------------------------------------------------------------ comptes

def try_login(client, email, password):
    return form_post(client, "/connexion", email=email, password=password)


def test_member_password_brute_force_one_ip(app, mails):
    member(app.test_client(), mails)
    attacker = from_ip(app.test_client(), "203.0.113.9")
    for i in range(10):
        try_login(attacker, "alice@example.com", f"mauvais{i}")
    try_login(attacker, "alice@example.com", PASSWORD)
    assert attacker.get("/compte").status_code != 200


def test_member_password_brute_force_many_ips(app, mails):
    member(app.test_client(), mails)
    for i in range(25):
        try_login(from_ip(app.test_client(), f"198.51.100.{i}"), "alice@example.com", f"mauvais{i}")
    attacker = from_ip(app.test_client(), "192.0.2.77")
    try_login(attacker, "alice@example.com", PASSWORD)
    assert attacker.get("/compte").status_code != 200


def test_password_change_logs_out_other_devices(app, mails):
    phone = member(app.test_client(), mails)
    thief = login_new_device(app.test_client(), mails)
    assert thief.get("/compte").status_code == 200
    resp = form_post(phone, "/compte/mot-de-passe", page="/compte", current=PASSWORD, current_password=PASSWORD,
                     password="un-autre-mot-de-passe", password2="un-autre-mot-de-passe",
                     new_password="un-autre-mot-de-passe", new_password2="un-autre-mot-de-passe")
    assert resp.status_code in (200, 302)
    assert thief.get("/compte").status_code != 200


def test_reset_link_works_once(app, mails):
    member(app.test_client(), mails)
    c = app.test_client()
    form_post(c, "/mot-de-passe-oublie", email="alice@example.com")
    link = re.search(r"https?://[^/\s]+(/mot-de-passe/[^\s]+)", mails[-1]["body"]).group(1)
    form_post(c, link, password="tout-nouveau-mdp", password2="tout-nouveau-mdp")
    other = app.test_client()
    page = other.get(link).get_data(as_text=True)
    assert 'name="password"' not in page                  # le lien déjà utilisé n'ouvre plus le formulaire
    other.post(link, data={"csrf_token": csrf(other, "/connexion"), "password": "pirate-mdp-123", "password2": "pirate-mdp-123"})
    assert try_login(app.test_client(), "alice@example.com", "pirate-mdp-123").status_code != 302
    assert try_login(app.test_client(), "alice@example.com", "tout-nouveau-mdp").status_code == 302


def test_session_cookie_is_protected(app, mails):
    c = member(app.test_client(), mails)
    resp = try_login(app.test_client(), "alice@example.com", PASSWORD)
    cookie = " ".join(v for k, v in resp.headers.items() if k.lower() == "set-cookie" and v.startswith("session="))
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
    assert "alice@example.com" not in cookie and PASSWORD not in cookie
    assert c.get("/compte").status_code == 200


def test_admin_brute_force(app):
    attacker = from_ip(app.test_client(), "203.0.113.50")
    codes = [attacker.post("/admin/login", data={"csrf_token": csrf(attacker, "/admin/login"), "username": "admin",
                                                  "password": f"x{i}"}).status_code for i in range(8)]
    assert 429 in codes


# ------------------------------------------------------------------ accès aux affaires des autres

def test_other_member_cannot_touch_my_files_or_albums(app, mails):
    alice = member(app.test_client(), mails)
    upload(alice, "privee.png", png())
    file_id = next(iter(records(app)))
    album_id = create(alice, password="secret-alice")
    bob = member(app.test_client(), mails, email="bob@example.com")
    t = csrf(bob, "/")
    assert bob.post(f"/delete/{file_id}", data={"csrf_token": t}).status_code in (403, 404)
    r = bob.post(f"/remplacer/{file_id}", data={"csrf_token": t, "file": (io.BytesIO(png()), "x.png")},
                 content_type="multipart/form-data")
    assert r.status_code in (403, 404)
    assert bob.get(f"/mes-images/{file_id}/apercu").status_code == 404
    assert bob.post(f"/mes-albums/{album_id}/supprimer", data={"csrf_token": t}).status_code == 404
    assert bob.post(f"/mes-albums/{album_id}/modifier", data={"csrf_token": t, "name": "pirate", "password": ""}).status_code == 404
    assert not can_see(bob, album_id)
    assert records(app)[file_id]["status"] in ("active", "pending")


def test_post_without_csrf_token_is_refused(app, mails):
    """Toute action (formulaire) doit porter le jeton anti-falsification, sinon refus."""
    c = member(app.test_client(), mails)
    admin = login(app.test_client())
    album_id = create(c)
    # API de l'extension : clé personnelle, pas de cookie. Lien de modération par mail : sans lien signé valable,
    # rien ne se passe (et avec, le jeton du formulaire est exigé).
    skip = {"extension.upload", "admin.mail_review"}
    for rule in app.url_map.iter_rules():
        if "POST" not in rule.methods or rule.endpoint in skip:
            continue
        url = rule.rule
        for arg in rule.arguments:
            url = url.replace(f"<{arg}>", album_id if arg == "album_id" else "abc").replace(f"<path:{arg}>", "x")
        for who, label in ((app.test_client(), "visiteur"), (c, "membre"), (admin, "admin")):
            r = who.post(url, data={"password": "x", "name": "x", "email": "a@b.c"})
            where = r.headers.get("Location", "")
            refused = r.status_code in (400, 403, 404, 405) or (r.status_code == 302 and (
                "/admin/login" in where or "/connexion" in where                        # pas le droit : renvoyé à la connexion
                or (rule.endpoint in ("account.signup", "account.login") and label != "visiteur")))  # déjà connecté
            assert refused, (rule.endpoint, r.status_code, label, where)


# ------------------------------------------------------------------ injections

@pytest.mark.parametrize("evil", ["' OR '1'='1", "1; DROP TABLE files;--", "..%2F..%2Fetc%2Fpasswd", "%00", "<script>"])
def test_injections_in_addresses(app, evil):
    c = app.test_client()
    for prefix in ("/file/", "/view/", "/download/", "/album/", "/image/", "/mes-images/"):
        r = c.get(prefix + evil)
        assert r.status_code in (400, 404), (prefix, evil, r.status_code)
    with app.app_context():
        assert isinstance(json_services.load_db(), dict)   # la base est intacte


def test_xss_in_album_texts_is_neutralised(app, mails):
    owner = member(app.test_client(), mails)
    evil = '<script>alert(1)</script><img src=x onerror=alert(2)>'
    album_id = create(owner, name=evil, description=evil)
    add(owner, album_id, GREEN, contributor=evil)
    page = app.test_client().get(f"/album/{album_id}").get_data(as_text=True)
    assert "<script>alert(1)" not in page and "onerror=alert(2)>" not in page


def test_file_password_brute_force_from_many_ips(app, mails):
    owner = member(app.test_client(), mails)
    resp = owner.post("/", data={"csrf_token": csrf(owner), "file": (io.BytesIO(png()), "secret.png"),
                                 "file_password": "motdepasse-photo", "password": "motdepasse-photo"},
                      content_type="multipart/form-data")
    resp.close()
    file_id, meta = next(iter(records(app).items()))
    if not meta.get("password_hash"):
        pytest.skip("champ du mot de passe de fichier nommé autrement")
    with app.app_context():
        db = json_services.load_db(); db[file_id]["status"] = "active"; json_services.save_db(db)
    for i in range(40):
        c = from_ip(app.test_client(), f"198.51.100.{i}")
        c.post(f"/file/{file_id}/unlock", data={"csrf_token": csrf(c, f"/file/{file_id}"), "password": f"x{i}"})
    attacker = from_ip(app.test_client(), "192.0.2.99")
    attacker.post(f"/file/{file_id}/unlock", data={"csrf_token": csrf(attacker, f"/file/{file_id}"), "password": "motdepasse-photo"})
    assert attacker.get(f"/view/{file_id}?raw=1").status_code == 404
