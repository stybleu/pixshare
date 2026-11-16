"""Disque persistant : images rangées dessus, place surveillée, envois refusés quand il est plein."""
import importlib
import io
import shutil
from collections import namedtuple

from PIL import Image

from conftest import csrf, login
from pixshare.services import json_services

Usage = namedtuple("Usage", "total used free")


def png():
    buf = io.BytesIO()
    Image.new("RGB", (10, 10), "blue").save(buf, "PNG")
    return buf.getvalue()


def test_disk_dir_holds_images_and_thumbnails(monkeypatch, tmp_path):
    monkeypatch.setenv("PIXSHARE_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("UPLOAD_FOLDER", raising=False)
    monkeypatch.delenv("THUMBNAIL_FOLDER", raising=False)
    import pixshare.config as config
    try:
        cfg = importlib.reload(config).Config
        assert cfg.UPLOAD_FOLDER == str(tmp_path / "fichiers")
        assert cfg.THUMBNAIL_FOLDER == str(tmp_path / "mod_thumbs")
    finally:
        monkeypatch.delenv("PIXSHARE_DATA_DIR")
        importlib.reload(config)


def test_full_disk_refuses_uploads(make_app, monkeypatch):
    app = make_app(NSFW_AUTO_MODERATION=False)
    client = app.test_client()
    monkeypatch.setattr(shutil, "disk_usage", lambda path: Usage(1000 * 2**20, 990 * 2**20, 10 * 2**20))
    resp = client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(png()), "a.png")},
                       content_type="multipart/form-data", follow_redirects=True)
    assert "stockage est plein" in resp.get_data(as_text=True)
    with app.app_context():
        assert json_services.load_db() == {}


def test_system_page_shows_storage(make_app):
    app = make_app()
    page = login(app.test_client()).get("/admin/system").get_data(as_text=True)
    assert "Stockage des images" in page and "Mo libres" in page
