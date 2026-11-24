"""Espace entreprise (essai) : privé, chiffré, sans expiration ; l'hébergeur n'y entre qu'avec l'accord du responsable."""
import io
import os

from PIL import Image, ImageDraw

from conftest import csrf, login
from test_accounts import mails, member  # noqa: F401


def jpeg(color=(200, 60, 30)):
    im = Image.new("RGB", (900, 600), color)
    ImageDraw.Draw(im).rectangle([100, 100, 400, 300], fill=(20, 20, 20))
    buf = io.BytesIO()
    im.save(buf, "JPEG")
    return buf.getvalue()


def new_machine(c, name="Compresseur C3"):
    r = c.post("/pro/machines", data={"csrf_token": csrf(c, "/pro"), "name": name, "location": "Atelier B"})
    return r.headers["Location"].rsplit("/", 1)[-1]


def new_intervention(c, mid):
    r = c.post(f"/pro/machine/{mid}/intervention",
               data={"csrf_token": csrf(c, f"/pro/machine/{mid}"), "ref": "BT-12", "comment": "Fuite d'huile réparée.\nJoint changé.",
                     "photos_avant": [(io.BytesIO(jpeg()), "avant.jpg")], "photos_apres": [(io.BytesIO(jpeg((30, 160, 60))), "apres.jpg")]},
               content_type="multipart/form-data")
    return r.headers["Location"].rsplit("/", 1)[-1]


def test_trial_is_admin_only_and_everything_is_encrypted(make_app, mails):
    app = make_app()
    assert app.test_client().get("/pro").status_code in (302, 303)                 # visiteur -> connexion
    assert member(app.test_client(), mails).get("/pro").status_code == 404           # membre du site public : non
    admin = login(app.test_client())
    mid = new_machine(admin)
    iid = new_intervention(admin, mid)
    page = admin.get(f"/pro/intervention/{iid}").get_data(as_text=True)
    assert "Fuite d&#39;huile" in page and "BT-12" in page
    assert admin.get(f"/pro/intervention/{iid}").headers["Cache-Control"].startswith("private")

    # Sur le disque : rien de lisible (ni la photo, ni le commentaire, ni le nom de la machine)
    from pixshare.services.json_services import _get_data_dir, load_json
    with app.app_context():
        folder = os.path.join(_get_data_dir(), "pro")
        blobs = [open(os.path.join(folder, n), "rb").read() for n in os.listdir(folder)]
        assert len(blobs) == 2 and all(b.startswith(b"PXP1") and b"\xff\xd8\xff" not in b[:64] for b in blobs)
        stored = str(load_json("pro_data.json", {}))
        assert "Compresseur" not in stored and "Fuite" not in stored and "enc" in stored

    from pixshare.services import pro_service
    with app.app_context():
        pid = pro_service.intervention(iid)["photos"][0]["id"]
    photo = admin.get(f"/pro/photo/{pid}?s=mini")
    assert photo.status_code == 200 and photo.data.startswith(b"\xff\xd8\xff")
    pdf = admin.get(f"/pro/intervention/{iid}.pdf")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF") and b"/Page" in pdf.data
    qr = admin.get(f"/pro/machine/{mid}/qr.svg")
    assert qr.status_code == 200 and b"<svg" in qr.data


def test_tampered_photo_is_refused(make_app):
    app = make_app()
    admin = login(app.test_client())
    iid = new_intervention(admin, new_machine(admin))
    from pixshare.services import pro_service
    from pixshare.services.json_services import _get_data_dir
    with app.app_context():
        pid = pro_service.intervention(iid)["photos"][0]["id"]
        path = os.path.join(_get_data_dir(), "pro", f"{pid}.bin")
    blob = bytearray(open(path, "rb").read())
    blob[-5] ^= 0xFF
    open(path, "wb").write(bytes(blob))
    assert admin.get(f"/pro/photo/{pid}").status_code == 404                        # modifié = refusé


def test_fake_photo_is_refused(make_app):
    app = make_app()
    admin = login(app.test_client())
    mid = new_machine(admin)
    admin.post(f"/pro/machine/{mid}/intervention",
               data={"csrf_token": csrf(admin, f"/pro/machine/{mid}"), "photos_avant": [(io.BytesIO(b"<html>"), "piege.jpg")]},
               content_type="multipart/form-data")
    from pixshare.services import pro_service
    with app.app_context():
        assert pro_service.history(mid) == []


def test_enterprise_mode_secret_and_support_access(make_app, mails, monkeypatch):
    app = make_app(ENTERPRISE_EMAIL_DOMAINS="example.com", ENTERPRISE_MANAGERS="chef@example.com",
                   BRAND_NAME="Maintenance Atelier")
    tech = member(app.test_client(), mails, email="tech@example.com")        # comptes créés avant de fermer le site
    chef = member(app.test_client(), mails, email="chef@example.com")
    admin = login(app.test_client())                                      # l'hébergeur, connecté à l'admin technique
    app.config["ENTERPRISE_MODE"] = True
    c = app.test_client()
    assert c.get("/").headers["Location"].endswith("/pro")                         # pas de site public
    assert c.get("/robots.txt").get_data(as_text=True).strip().endswith("Disallow: /")
    assert "noindex" in c.get("/connexion").headers["X-Robots-Tag"]

    mid = new_machine(tech)
    new_intervention(tech, mid)
    assert "Maintenance Atelier" in tech.get("/pro").get_data(as_text=True)

    assert admin.get("/pro").status_code == 404                                    # l'hébergeur n'entre pas
    assert admin.get(f"/pro/machine/{mid}").status_code == 404

    assert tech.get("/pro/acces-depannage").status_code == 404                     # réservé au responsable
    chef.post("/pro/acces-depannage", data={"csrf_token": csrf(chef, "/pro/acces-depannage"), "hours": "2"})
    assert admin.get(f"/pro/machine/{mid}").status_code == 200                     # ouvert par le responsable
    journal = chef.get("/pro/acces-depannage").get_data(as_text=True)
    assert "hébergeur (dépannage)" in journal and f"/pro/machine/{mid}" in journal  # chaque passage est noté
    chef.post("/pro/acces-depannage", data={"csrf_token": csrf(chef, "/pro/acces-depannage"), "hours": "0"})
    assert admin.get(f"/pro/machine/{mid}").status_code == 404                     # refermé


def test_enterprise_signup_only_company_addresses(make_app, mails):
    app = make_app(ENTERPRISE_MODE=True, ENTERPRISE_EMAIL_DOMAINS="example.com")
    c = app.test_client()
    pw = "mot-de-passe-solide"
    r = c.post("/inscription", data={"csrf_token": csrf(c, "/inscription"), "email": "pirate@gmail.com",
                                     "password": pw, "password2": pw, "accept_cgu": "1"}, follow_redirects=True)
    assert "réservée aux adresses e-mail de l&#39;entreprise" in r.get_data(as_text=True)
    assert not mails                                                       # aucun e-mail de confirmation envoyé
