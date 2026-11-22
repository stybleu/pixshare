"""Filtres photo et scanner de documents : réservés aux membres, aperçu identique au résultat,
coins détectés, page redressée, PDF A4."""
import io
import os

import numpy as np
from PIL import Image, ImageDraw

from conftest import csrf
from test_accounts import mails, member, no_guest_pass, records, upload  # noqa: F401  (fixture mails)
from pixshare.services import photo_filter_service as pf


def jpeg(img):
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=92)
    return buf.getvalue()


def sheet_photo(w=1200, h=900):
    """Une feuille claire, un peu de travers, posée sur une table foncée."""
    img = Image.new("RGB", (w, h), (110, 72, 40))
    d = ImageDraw.Draw(img)
    d.polygon([(250, 140), (930, 190), (890, 820), (190, 740)], fill=(236, 232, 224))
    for i in range(10):
        d.line([(320, 260 + i * 45), (820, 290 + i * 45)], fill=(35, 35, 40), width=4)
    return img


def stored_image(app, meta):
    return Image.open(os.path.join(app.config["UPLOAD_FOLDER"], meta["server_name"]))


# ---------- formules ----------

def test_filters_known_values():
    px = np.array([[[200, 100, 50]]], dtype=np.float32)
    grey = pf.apply_filter_array(px.copy(), "noir_blanc", 100)
    assert grey[0, 0, 0] == grey[0, 0, 1] == grey[0, 0, 2]
    same = pf.apply_filter_array(px.copy(), "vintage", 0)
    assert np.allclose(same, px, atol=0.6)                 # intensité 0 : rien ne change
    assert pf.parse_filter("retro") == "retro" and pf.parse_filter("inconnu") == ""
    assert pf.parse_strength("250") == 100 and pf.parse_strength("x") == 100 and pf.parse_strength("-3") == 0


def test_corners_found_and_page_straightened():
    img = sheet_photo()
    corners, found = pf.detect_corners(img)
    assert found
    expected = [(250, 140), (930, 190), (890, 820), (190, 740)]
    for (x, y), (ex, ey) in zip(corners, expected):
        assert abs(x * 1200 - ex) < 15 and abs(y * 900 - ey) < 15
    page = pf.straighten(img, corners, "scan")
    arr = np.asarray(page.convert("L"))
    assert arr.mean() > 200                                # fond blanchi, plus de table brune
    assert (arr < 80).mean() > 0.01                        # le texte est resté noir
    pdf = pf.to_pdf_bytes(page)
    assert pdf.startswith(b"%PDF") and b"/MediaBox" in pdf


def test_corners_parsing_rejects_nonsense():
    assert pf.parse_corners("0.1,0.1,0.9,0.1,0.9,0.9,0.1,0.9") is not None
    assert pf.parse_corners("0.1,0.1,0.9") is None
    assert pf.parse_corners("a,b,c,d,e,f,g,h") is None
    assert pf.parse_corners("0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5") is None   # dégénéré
    assert pf.parse_corners("0,0,9,0,9,9,0,9") is None                   # hors de l'image


def test_browser_script_uses_same_filter_list():
    js = open("static/js/filtres.js", encoding="utf-8").read()
    for name in pf.FILTERS:
        assert name in js


# ---------- envoi ----------

def test_filter_is_for_members_only(make_app, mails):
    app = no_guest_pass(make_app())
    guest = app.test_client()
    assert 'name="photo_filter"' not in guest.get("/").get_data(as_text=True)
    upload(guest, "invite.jpg", data=jpeg(Image.new("RGB", (60, 40), (200, 60, 30))), photo_filter="noir_blanc")
    meta = next(m for m in records(app).values() if m["original_name"] == "invite.jpg")
    r, g, b = stored_image(app, meta).convert("RGB").getpixel((30, 20))
    assert abs(r - b) > 100 and not meta.get("photo_filter")   # ignoré sans compte

    user = member(app.test_client(), mails)
    page = user.get("/").get_data(as_text=True)
    assert 'name="photo_filter"' in page and "js/filtres.js" in page and 'data-filter="document"' in page
    upload(user, "membre.jpg", data=jpeg(Image.new("RGB", (60, 40), (200, 60, 30))),
           photo_filter="noir_blanc", filter_strength="100")
    meta = next(m for m in records(app).values() if m["original_name"] == "membre.jpg")
    r, g, b = stored_image(app, meta).convert("RGB").getpixel((30, 20))
    assert abs(r - b) <= 3 and meta["photo_filter"] == "noir_blanc"


def test_document_upload_gives_pdf(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    upload(user, "feuille.jpg", data=jpeg(sheet_photo()), photo_filter="document", doc_mode="scan",
           doc_corners="0.2083,0.1556,0.7750,0.2111,0.7417,0.9111,0.1583,0.8222")
    fid, meta = next((k, m) for k, m in records(app).items() if m["original_name"] == "feuille.jpg")
    assert meta["document_scan"] is True
    img = stored_image(app, meta)
    assert img.size[0] < 1200 and np.asarray(img.convert("L")).mean() > 200
    assert "Télécharger en PDF" in user.get(f"/file/{fid}").get_data(as_text=True)
    resp = user.get(f"/download/{fid}.pdf")
    assert resp.status_code == 200 and resp.mimetype == "application/pdf" and resp.data.startswith(b"%PDF")
    assert "noindex" in resp.headers.get("X-Robots-Tag", "")
    assert user.get("/download/inexistant.pdf").status_code == 404


def test_document_tools_need_account_and_csrf(make_app, mails):
    app = no_guest_pass(make_app())
    data = jpeg(sheet_photo())
    guest = app.test_client()
    token = csrf(guest)
    resp = guest.post("/outils/document/coins", data={"csrf_token": token, "image": (io.BytesIO(data), "a.jpg")},
                      content_type="multipart/form-data")
    assert resp.status_code == 403

    user = member(app.test_client(), mails)
    resp = user.post("/outils/document/coins", data={"image": (io.BytesIO(data), "a.jpg")},
                     content_type="multipart/form-data")
    assert resp.status_code in (400, 403)                              # sans jeton CSRF
    token = csrf(user)
    resp = user.post("/outils/document/coins", data={"csrf_token": token, "image": (io.BytesIO(data), "a.jpg")},
                     content_type="multipart/form-data")
    assert resp.status_code == 200 and resp.get_json()["found"] is True
    corners = ",".join(f"{v:.4f}" for p in resp.get_json()["corners"] for v in p)
    resp = user.post("/outils/document/apercu", data={"csrf_token": token, "corners": corners, "mode": "gris",
                                                      "image": (io.BytesIO(data), "a.jpg")},
                     content_type="multipart/form-data")
    assert resp.status_code == 200 and resp.mimetype == "image/jpeg"
    assert Image.open(io.BytesIO(resp.data)).size[0] <= 1000
