"""Codes prêts à coller (BBCode, HTML, Markdown) pour les images publiées."""
import html
import io
import re

from PIL import Image

from conftest import csrf
from pixshare.services import json_services


def png():
    buf = io.BytesIO()
    Image.new("RGB", (30, 30), (10, 200, 90)).save(buf, "PNG")
    return buf.getvalue()


def test_codes_for_a_published_image(make_app):
    app = make_app()
    c = app.test_client()
    c.post("/", data={"csrf_token": csrf(c), "file": (io.BytesIO(png()), 'vacances<b>.png')},
           content_type="multipart/form-data").close()
    with app.app_context():
        db = json_services.load_db()
        file_id = next(iter(db))
        db[file_id]["status"] = "active"
        json_services.save_db(db)
    page = c.get("/").get_data(as_text=True)
    assert "Codes pour forums et sites" in page
    values = {m.group(1): html.unescape(m.group(2)) for m in re.finditer(r'id="code_(bb|html|md)_[^"]+"[^>]*value="([^"]*)"', page)}
    assert values["bb"].startswith("[url=http") and f"/view/{file_id}" in values["bb"] and values["bb"].endswith("[/img][/url]")
    assert values["html"].startswith('<a href="') and '<img src="' in values["html"] and "<b>" not in page.split("Codes pour forums")[1].split("</details>")[0]
    assert values["md"].startswith("[![") and f"/view/{file_id}" in values["md"]


def test_no_codes_for_protected_or_pending(make_app):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    c = app.test_client()
    c.post("/", data={"csrf_token": csrf(c), "file": (io.BytesIO(png()), "a.png")}, content_type="multipart/form-data").close()
    with app.app_context():
        db = json_services.load_db()
        file_id = next(iter(db))
        db[file_id]["status"] = "pending"
        json_services.save_db(db)
    assert "Codes pour forums" not in c.get("/").get_data(as_text=True)
    with app.app_context():
        db = json_services.load_db()
        db[file_id].update(status="active", password_hash="x")
        json_services.save_db(db)
    assert "Codes pour forums" not in c.get("/").get_data(as_text=True)
