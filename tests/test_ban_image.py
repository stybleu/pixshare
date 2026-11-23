"""« Image non valide » : l'admin interdit une image passée à travers le filtre, même expirée."""
import io
import os

import numpy as np
import pytest
from PIL import Image

from conftest import REAL_IS_PRESENT, csrf, login
from pixshare.services import admin_presence_service, json_services
from test_nsfw_moderation import fake_nudenet, upload  # noqa: F401


def photo(seed=3, tweak=False):
    rng = np.random.default_rng(seed)
    arr = rng.integers(0, 255, (240, 320, 3), dtype=np.uint8)
    arr[:, :160] //= 3                       # une image avec des formes, pas du bruit uniforme
    if tweak:
        arr[0:3, 0:3] = 255                  # retouche minuscule : autre fichier, même image
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, "PNG")
    return buf.getvalue()


@pytest.fixture
def app(make_app):
    return make_app(MODERATION_PENDING_IMAGES=True)


def records(app):
    with app.app_context():
        return json_services.load_db()


def only(app, name):
    return next((k, m) for k, m in records(app).items() if m["original_name"] == name)


def test_active_image_is_deleted_and_refused_when_it_comes_back(app):
    upload(app.test_client(), "a.png", photo())
    file_id, meta = only(app, "a.png")
    assert meta["status"] == "active"                              # le filtre l'a laissée passer
    admin = login(app.test_client())
    admin.post("/admin/interdire", data={"csrf_token": csrf(admin, "/admin/thumbnails"), "file_id": file_id})
    assert only(app, "a.png")[1]["status"] == "deleted"
    upload(app.test_client(), "b.png", photo())                     # exactement la même : refusée
    assert not any(m["original_name"] == "b.png" and m["status"] == "active" for m in records(app).values())
    upload(app.test_client(), "c.png", photo(tweak=True))           # retouchée : mise de côté
    assert only(app, "c.png")[1]["status"] == "pending"


def test_expired_image_can_still_be_forbidden_from_its_thumbnail(app, monkeypatch):
    upload(app.test_client(), "a.png", photo())
    file_id, meta = only(app, "a.png")
    with app.app_context():
        from pixshare.services.file_service import delete_by_id, get_thumbnail_abs_path
        thumb = get_thumbnail_abs_path(file_id)
        assert os.path.isfile(thumb)
        delete_by_id(file_id, reason="expired")                     # image terminée : l'original est effacé
    assert os.path.isfile(thumb)
    admin = login(app.test_client())
    page = admin.get("/admin/thumbnails").get_data(as_text=True)
    assert "🚫 Image non valide" in page
    resp = admin.post("/admin/interdire", data={"csrf_token": csrf(admin, "/admin/thumbnails"), "file_id": file_id},
                      follow_redirects=True)
    assert "Image interdite 🚫" in resp.get_data(as_text=True)
    assert "🚫 Image interdite" in admin.get("/admin/thumbnails").get_data(as_text=True)
    upload(app.test_client(), "b.png", photo())                     # même fichier (empreinte gardée) : refusé
    assert not any(m["original_name"] == "b.png" and m["status"] == "active" for m in records(app).values())
    monkeypatch.setattr(admin_presence_service, "is_present", REAL_IS_PRESENT)
    admin.post("/admin/logout", data={"csrf_token": csrf(admin, "/admin")})
    upload(app.test_client(), "c.png", photo(tweak=True))           # retouchée, admin absent : supprimée
    _fid, meta = only(app, "c.png")
    assert meta["status"] == "deleted" and meta["delete_reason"] == "auto:admin_absent"


def test_only_admin_can_forbid(app):
    upload(app.test_client(), "a.png", photo())
    file_id, _ = only(app, "a.png")
    client = app.test_client()
    assert client.post("/admin/interdire", data={"csrf_token": csrf(client), "file_id": file_id}).status_code in (302, 400, 403)
    assert only(app, "a.png")[1]["status"] == "active"


def test_thumbnails_show_view_count(app):
    upload(app.test_client(), "a.png", photo())
    file_id, _meta = only(app, "a.png")
    visitor = app.test_client()
    for _ in range(3):
        visitor.get(f"/view/{file_id}")
    with app.app_context():
        views = only(app, "a.png")[1].get("views", 0)
    admin = login(app.test_client())
    page = admin.get("/admin/thumbnails").get_data(as_text=True)
    assert 'class="thumb-views' in page and f"👁 {views}" in page


def test_files_page_shows_view_badge(app):
    upload(app.test_client(), "a.png", photo())
    admin = login(app.test_client())
    page = admin.get("/admin").get_data(as_text=True)
    assert 'class="views-badge' in page and "👁 " in page
