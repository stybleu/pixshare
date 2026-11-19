"""Seules les pages de présentation sont visibles sur Google ; jamais les fichiers des utilisateurs."""
import io

from PIL import Image

from conftest import csrf
from pixshare.services import json_services

INDEXED = ("/", "/album-souvenir", "/cgu", "/mentions-legales", "/contact")


def test_only_presentation_pages_are_indexed(make_app):
    app = make_app()
    client = app.test_client()
    robots = client.get("/robots.txt").get_data(as_text=True)
    for path in ("/admin", "/file/", "/view/", "/download/", "/album/", "/mes-albums"):
        assert f"Disallow: {path}" in robots
    for gone in ("/api/", "/admin_panel", "/admin_login", "/tmp/"):  # adresses supprimées : Google doit voir la 404
        assert f"Disallow: {gone}" not in robots
        assert client.get(gone + "x" if gone.endswith("/") else gone).status_code == 404
    sitemap = client.get("/sitemap.xml").get_data(as_text=True)
    for page in INDEXED:
        assert 'content="index, follow"' in client.get(page).get_data(as_text=True), page
        assert f"/{page.strip('/')}</loc>" in sitemap or page == "/"
    buf = io.BytesIO()
    Image.new("RGB", (20, 20), (1, 200, 3)).save(buf, "PNG")
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(buf.getvalue()), "a.png")},
                content_type="multipart/form-data").close()
    with app.app_context():
        file_id = next(iter(json_services.load_db()))
    for url in (f"/image/{file_id}", f"/view/{file_id}", f"/view/{file_id}?raw=1", f"/file/{file_id}"):
        resp = client.get(url)
        assert "noindex" in resp.headers.get("X-Robots-Tag", ""), url
