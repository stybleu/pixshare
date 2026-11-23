"""Recadrage au doigt avant l'envoi : pour tout le monde, fait sur la photo d'origine par le serveur."""
import io
import os

from PIL import Image

from test_accounts import records, upload
from pixshare.services import photo_filter_service as pf


def quadrants(fmt="PNG", mode="RGB"):
    """400 × 200 : rouge à gauche, bleu à droite (transparent en bas à droite si RGBA)."""
    img = Image.new(mode, (400, 200), (255, 0, 0, 255) if mode == "RGBA" else (255, 0, 0))
    img.paste((0, 0, 255, 255) if mode == "RGBA" else (0, 0, 255), (200, 0, 400, 200))
    if mode == "RGBA":
        img.paste((0, 0, 255, 0), (200, 100, 400, 200))
    buf = io.BytesIO()
    img.save(buf, fmt)
    return buf.getvalue()


def stored(app, name):
    m = next(m for m in records(app).values() if m["original_name"] == name)
    return m, Image.open(os.path.join(app.config["UPLOAD_FOLDER"], m["server_name"]))


def test_parse_crop():
    assert pf.parse_crop("0.5,0,0.5,1") == (0.5, 0.0, 0.5, 1.0)
    assert pf.parse_crop("") is None and pf.parse_crop("a,b,c,d") is None
    assert pf.parse_crop("0,0,1,1") is None                     # photo entière : rien à faire
    assert pf.parse_crop("0.9,0,0.5,1") is None                 # dépasse de la photo
    assert pf.parse_crop("0,0,0.001,0.5") is None               # trop petit
    assert pf.parse_crop("nan,0,0.5,0.5") is None


def test_guest_can_crop_and_keeps_quality(make_app):
    app = make_app()
    upload(app.test_client(), "droite.png", data=quadrants(), crop_box="0.5,0,0.5,1")
    m, img = stored(app, "droite.png")
    assert img.size == (200, 200) and img.convert("RGB").getpixel((100, 100)) == (0, 0, 255)
    assert not m.get("photo_filter")                             # pas compté comme une option avancée
    html = app.test_client().get("/").get_data(as_text=True)
    assert 'id="cropStart"' in html and 'name="crop_box"' in html


def test_crop_keeps_transparency(make_app):
    app = make_app()
    upload(app.test_client(), "alpha.png", data=quadrants(mode="RGBA"), crop_box="0.5,0,0.5,1")
    _m, img = stored(app, "alpha.png")
    assert img.mode == "RGBA" and img.size == (200, 200)
    assert img.getpixel((100, 50))[3] == 255 and img.getpixel((100, 150))[3] == 0


def test_crop_then_filter_order(make_app):
    app = make_app()
    from test_guest_pass import settings
    settings(app, guest_pass_per_hour=5)
    upload(app.test_client(), "nb.jpg", data=quadrants("JPEG"), crop_box="0,0,0.5,1", photo_filter="noir_blanc")
    _m, img = stored(app, "nb.jpg")
    r, g, b = img.convert("RGB").getpixel((100, 100))
    assert img.size == (200, 200) and abs(r - b) <= 3            # zone rouge, passée en noir et blanc


def test_bad_crop_is_ignored(make_app):
    app = make_app()
    upload(app.test_client(), "entiere.png", data=quadrants(), crop_box="0,0,9,9")
    _m, img = stored(app, "entiere.png")
    assert img.size == (400, 200)
