"""Options avancées sans compte : envois simples libres, une « utilisation » par heure pour les
options spéciales (mot de passe, vues, filtres, sons, plus gros, plus longtemps), compteur visible.
Les comptes n'ont pas de compteur ; les albums restent réservés aux comptes."""
import io

from PIL import Image

from conftest import csrf
from test_accounts import mails, member, records, upload  # noqa: F401  (fixture mails)


def settings(app, **values):
    from pixshare.services import settings_service
    with app.app_context():
        s = settings_service.load_settings()
        s.update(values)
        settings_service.save_settings(s)


def jpeg(color=(200, 60, 30), size=(60, 40)):
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, "JPEG", quality=92)
    return buf.getvalue()


def meta(app, name):
    return next(m for m in records(app).values() if m["original_name"] == name)


def minutes(m):
    from pixshare.services.time_service import parse_dt
    return round((parse_dt(m["expires_at"]) - parse_dt(m["uploaded_at"])).total_seconds() / 60)


def test_guest_sees_options_and_counter(make_app):
    app = make_app()
    html = app.test_client().get("/").get_data(as_text=True)
    assert 'name="file_password"' in html and 'name="photo_filter"' in html and 'name="view_limit_enabled"' in html
    assert "Options avancées sans compte" in html and "Il vous reste <strong>1 utilisation</strong>" in html
    values = [int(v) for v in html.split('id="lifetimeSelect"')[1].split("</select>")[0].split('value="')[1:]
              for v in [v.split('"')[0]]]
    assert max(values) == 1440                     # 24 h au maximum par défaut, pas 1 an
    assert "accept=\"image/*,video/*,audio/*\"" in html


def test_simple_uploads_are_free_and_options_use_the_counter(make_app):
    app = make_app()
    guest = app.test_client()
    for i in range(3):                             # envois simples : pas d'utilisation consommée
        upload(guest, f"simple{i}.png")
    assert "Il vous reste <strong>1 utilisation</strong>" in guest.get("/").get_data(as_text=True)

    upload(guest, "secret.png", file_password="secret123", lifetime="525600")
    m = meta(app, "secret.png")
    assert m.get("password_hash") and minutes(m) == 1440      # option accordée, durée plafonnée à 24 h
    page = guest.get("/").get_data(as_text=True)
    assert "Utilisées." in page and "Rechargées à" in page

    resp = upload(guest, "deuxieme.jpg", data=jpeg(), photo_filter="noir_blanc")
    assert resp.status_code == 302
    assert not any(m["original_name"] == "deuxieme.jpg" for m in records(app).values())   # refusé, rien d'enregistré
    with guest.session_transaction() as s:
        flashes = " ".join(msg for _cat, msg in s.get("_flashes", []))
    assert "Vous avez utilisé vos options avancées" in flashes and "compte gratuit" in flashes

    upload(guest, "encore-simple.png")             # toujours possible sans options
    assert any(m["original_name"] == "encore-simple.png" for m in records(app).values())


def test_guest_filter_and_document_work_with_the_counter(make_app):
    app = make_app()
    settings(app, guest_pass_per_hour=2)
    guest = app.test_client()
    upload(guest, "nb.jpg", data=jpeg(), photo_filter="noir_blanc")
    assert meta(app, "nb.jpg")["photo_filter"] == "noir_blanc"
    resp = guest.post("/outils/document/coins", data={"csrf_token": csrf(guest), "image": (io.BytesIO(jpeg()), "a.jpg")},
                      content_type="multipart/form-data")
    assert resp.status_code == 200                 # l'aperçu du scanner ne consomme rien
    assert "Il vous reste <strong>1 utilisation</strong>" in guest.get("/").get_data(as_text=True)


def test_guest_size_cap_with_options(make_app):
    app = make_app()
    settings(app, guest_max_upload_size_mb=1, guest_pass_max_upload_size_mb=2, max_upload_size_mb=100, guest_pass_per_hour=5)
    big = jpeg(size=(1, 1)) + b"\0" * (1024 * 1024 + 300 * 1024)       # 1,3 Mo
    guest = app.test_client()
    upload(guest, "gros.jpg", data=big)
    assert any(m["original_name"] == "gros.jpg" for m in records(app).values())   # 1 utilisation pour la taille
    huge = jpeg(size=(1, 1)) + b"\0" * (3 * 1024 * 1024)
    other = app.test_client()
    upload(other, "trop-gros.jpg", data=huge)      # au-delà de 2 Mo, même avec les options
    assert not any(m["original_name"] == "trop-gros.jpg" for m in records(app).values())


def test_members_have_no_counter(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    for i in range(3):
        upload(user, f"m{i}.png", file_password="secret123")
    assert all(meta(app, f"m{i}.png").get("password_hash") for i in range(3))
    assert "Options avancées sans compte" not in user.get("/").get_data(as_text=True)


def test_option_can_be_switched_off(make_app):
    app = make_app()
    settings(app, guest_pass_per_hour=0)
    guest = app.test_client()
    html = guest.get("/").get_data(as_text=True)
    assert 'name="file_password"' not in html and "Options avancées sans compte" not in html
    upload(guest, "x.png", file_password="secret123")
    assert not meta(app, "x.png").get("password_hash")


def test_admin_can_set_the_guest_options(make_app):
    from conftest import login
    app = make_app()
    admin = app.test_client()
    login(admin)
    page = admin.get("/admin/comptes").get_data(as_text=True)
    assert 'name="guest_pass_per_hour"' in page and 'name="guest_pass_max_upload_size_mb"' in page
    token = csrf(admin, "/admin/comptes")
    admin.post("/admin/comptes/reglages", data={"csrf_token": token, "accounts_enabled": "1",
                                                "guest_max_lifetime_minutes": "120", "guest_max_upload_size_mb": "3",
                                                "guest_uploads_per_hour": "10", "member_uploads_per_hour": "0",
                                                "guest_pass_per_hour": "3", "guest_pass_max_lifetime_minutes": "10080",
                                                "guest_pass_max_upload_size_mb": "30", "member_strikes_max": "3"})
    from pixshare.services import settings_service
    with app.app_context():
        s = settings_service.load_settings()
    assert s["guest_pass_per_hour"] == 3 and s["guest_pass_max_lifetime_minutes"] == 10080
    assert s["guest_pass_max_upload_size_mb"] == 30
