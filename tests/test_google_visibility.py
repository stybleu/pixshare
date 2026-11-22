"""Seules les pages de présentation sont visibles sur Google ; jamais les fichiers des utilisateurs."""
import io

from PIL import Image

from conftest import csrf
from pixshare.services import json_services

INDEXED = ("/", "/album-souvenir", "/faq", "/cgu", "/mentions-legales", "/contact")


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


def test_each_public_page_has_its_own_title_and_description(make_app):
    """Rapport IONOS : titres et descriptions en double, variantes ?lang=fr / ?type= comptées comme pages."""
    import html as html_mod
    import re
    app = make_app()
    seen_t, seen_d = {}, {}
    for path in ("/", "/contact", "/cgu", "/faq", "/mentions-legales", "/album-souvenir",
                 "/connexion", "/inscription", "/mot-de-passe-oublie"):
        html = app.test_client().get(path).get_data(as_text=True)
        title = html_mod.unescape(re.search(r"<title>(.*?)</title>", html, re.S).group(1).strip())
        desc = re.search(r'<meta name="description" content="([^"]*)"', html).group(1)
        assert 30 <= len(title) <= 65, (path, title)
        assert 110 <= len(desc) <= 170, (path, len(desc))
        assert title not in seen_t and desc not in seen_d, (path, seen_t.get(title), seen_d.get(desc))
        seen_t[title], seen_d[desc] = path, path
    c = app.test_client()
    for path in ("/contact?lang=fr", "/contact?type=appeal", "/faq?lang=fr"):
        assert 'content="noindex, follow"' in c.get(path).get_data(as_text=True)
    assert 'content="index, follow"' in c.get("/faq?lang=en").get_data(as_text=True)
    assert 'rel="nofollow"' in c.get("/").get_data(as_text=True)
