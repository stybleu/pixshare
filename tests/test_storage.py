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


def test_disk_contents_on_system_page(make_app, tmp_path):
    import io

    from PIL import Image

    from conftest import csrf, login

    data = tmp_path / "disk"
    up = data / "fichiers"
    up.mkdir(parents=True)
    (data / "geoip").mkdir()
    app = make_app(PERSISTENT_DIR=str(data), UPLOAD_FOLDER=str(up))
    client = app.test_client()
    buf = io.BytesIO()
    Image.new("RGB", (30, 30), (200, 10, 10)).save(buf, "PNG")
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(buf.getvalue()), "vacances-secretes.png")},
                content_type="multipart/form-data")
    page = login(app.test_client()).get("/admin/system").get_data(as_text=True)
    assert "Contenu du disque" in page and "fichiers" in page and "Images et fichiers envoyés" in page
    assert ".png" in page and "vacances-secretes" not in page


def test_disk_explorer(make_app, tmp_path):
    import io

    from PIL import Image

    from conftest import csrf, login
    from pixshare.services import json_services

    data = tmp_path / "disk"
    up = data / "fichiers"
    up.mkdir(parents=True)
    (tmp_path / "secret.txt").write_text("hors du disque")
    app = make_app(PERSISTENT_DIR=str(data), UPLOAD_FOLDER=str(up))
    client = app.test_client()
    buf = io.BytesIO()
    Image.new("RGB", (30, 30), (200, 10, 10)).save(buf, "PNG")
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(buf.getvalue()), "vacances.png")},
                content_type="multipart/form-data")
    (up / "perdu.png").write_bytes(b"x")
    with app.app_context():
        file_id = next(iter(json_services.load_db()))

    anon = app.test_client()
    assert anon.get("/admin/disque").status_code in (302, 401, 403)
    assert anon.get("/admin/disque/ouvrir?chemin=fichiers/perdu.png").status_code in (302, 401, 403)

    admin = login(app.test_client())
    root = admin.get("/admin/disque").get_data(as_text=True)
    assert "fichiers" in root and "Images et fichiers envoyés" in root
    folder = admin.get("/admin/disque?chemin=fichiers&tri=taille").get_data(as_text=True)
    assert f"{file_id}.png" in folder and "« vacances.png »" in folder and "en ligne" in folder
    assert "perdu.png" in folder and "orphelin" in folder
    img = admin.get(f"/admin/disque/ouvrir?chemin=fichiers/{file_id}.png")
    assert img.status_code == 200 and img.mimetype == "image/png" and img.headers["X-Content-Type-Options"] == "nosniff"
    for bad in ("../secret.txt", "fichiers/../../secret.txt", "/etc/passwd", "inexistant"):
        assert admin.get(f"/admin/disque/ouvrir?chemin={bad}").status_code == 404, bad
        assert admin.get(f"/admin/disque?chemin={bad}").status_code == 404, bad


def _disk_app(make_app, tmp_path):
    data = tmp_path / "disk"
    up = data / "fichiers"
    up.mkdir(parents=True)
    (data / "files.json").write_text("{}")
    app = make_app(PERSISTENT_DIR=str(data), UPLOAD_FOLDER=str(up))
    return app, data, up


def _act(admin, **form):
    from conftest import csrf
    sel = form.pop("selection", [])
    return admin.post("/admin/disque/action", data={"csrf_token": csrf(admin, "/admin/disque"), "selection": sel, **form})


def test_disk_manage_mkdir_move_rename_delete(make_app, tmp_path):
    from conftest import login

    app, data, up = _disk_app(make_app, tmp_path)
    (data / "vieux.txt").write_text("x")
    (up / "orphelin.png").write_bytes(b"x")
    admin = login(app.test_client())
    _act(admin, action="mkdir", chemin="", nom="Archives")
    assert (data / "Archives").is_dir()
    _act(admin, action="move", chemin="", selection=["vieux.txt"], destination="Archives")
    assert (data / "Archives" / "vieux.txt").exists() and not (data / "vieux.txt").exists()
    _act(admin, action="rename", chemin="Archives", selection=["Archives/vieux.txt"], nom="notes.txt")
    assert (data / "Archives" / "notes.txt").exists()
    _act(admin, action="delete", chemin="fichiers", selection=["fichiers/orphelin.png"])
    assert not (up / "orphelin.png").exists()
    _act(admin, action="delete", chemin="", selection=["Archives"])
    assert not (data / "Archives").exists()


def test_disk_protects_site_files(make_app, tmp_path):
    import io

    from PIL import Image

    from conftest import csrf, login
    from pixshare.services import json_services

    app, data, up = _disk_app(make_app, tmp_path)
    client = app.test_client()
    buf = io.BytesIO()
    Image.new("RGB", (20, 20), (1, 2, 3)).save(buf, "PNG")
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(buf.getvalue()), "a.png")},
                content_type="multipart/form-data")
    with app.app_context():
        file_id = next(iter(json_services.load_db()))
    admin = login(app.test_client())
    _act(admin, action="mkdir", chemin="", nom="Rangement")
    # dossiers et données du site : ni supprimés ni déplacés
    _act(admin, action="delete", chemin="", selection=["fichiers", "files.json"])
    assert up.is_dir() and (data / "files.json").exists()
    # un fichier en ligne ne se déplace pas (son lien casserait)…
    _act(admin, action="move", chemin="fichiers", selection=[f"fichiers/{file_id}.png"], destination="Rangement")
    assert (up / f"{file_id}.png").exists()
    # … mais sa suppression passe par la suppression normale de l'admin
    _act(admin, action="delete", chemin="fichiers", selection=[f"fichiers/{file_id}.png"])
    with app.app_context():
        meta = json_services.load_db()[file_id]
    assert meta["status"] == "deleted" and meta["delete_reason"] == "admin_delete"
    # pas de dossier dans les dossiers du site, pas de sortie du disque
    _act(admin, action="mkdir", chemin="fichiers", nom="x")
    assert not (up / "x").exists()
    _act(admin, action="move", chemin="", selection=["Rangement"], destination="../..")
    assert (data / "Rangement").is_dir()


def test_disk_thumbnails(make_app, tmp_path):
    from PIL import Image

    from conftest import login

    app, data, up = _disk_app(make_app, tmp_path)
    Image.new("RGB", (900, 600), (200, 40, 40)).save(up / "grande.jpg", "JPEG")
    admin = login(app.test_client())
    page = admin.get("/admin/disque?chemin=fichiers").get_data(as_text=True)
    assert "/admin/disque/apercu?chemin=fichiers/grande.jpg" in page
    thumb = admin.get("/admin/disque/apercu?chemin=fichiers/grande.jpg")
    assert thumb.status_code == 200 and thumb.mimetype == "image/webp"
    with Image.open(__import__("io").BytesIO(thumb.data)) as im:
        assert max(im.size) <= 128
    assert app.test_client().get("/admin/disque/apercu?chemin=fichiers/grande.jpg").status_code in (302, 401, 403)
    assert admin.get("/admin/disque/apercu?chemin=../x.jpg").status_code == 404


def test_orphan_upload_can_be_moved(make_app, tmp_path):
    from conftest import login

    app, data, up = _disk_app(make_app, tmp_path)
    (up / "ancien.mp4").write_bytes(b"x")
    admin = login(app.test_client())
    _act(admin, action="mkdir", chemin="", nom="Orphelins")
    _act(admin, action="move", chemin="fichiers", selection=["fichiers/ancien.mp4"], destination="Orphelins")
    assert (data / "Orphelins" / "ancien.mp4").exists()
