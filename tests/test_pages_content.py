"""Contenu des pages publiques : rien d'obsolète, dates lisibles, pages d'erreur en français."""
import io
from PIL import Image

from conftest import csrf
from pixshare.services import json_services


def test_homepage_mentions_only_existing_features(make_app):
    html = make_app().test_client().get("/").get_data(as_text=True)
    assert "API" not in html and "qualitée" not in html
    for text in ("Partagez vos photos en un instant", "Choisir une photo ou un fichier", "codes prêts",
                 "Suppression automatique", "Compte gratuit : plus de temps", "questions fréquentes"):
        assert text in html, text
    for long_text in ("Pourquoi utiliser PixShare", "Hébergement d'image temporaire simple et rapide", "utilisez le bouton"):
        assert long_text not in html, long_text                       # plus de longs textes : ils sont dans la FAQ
    assert "Toi, tu" not in html and "note-le" not in html


def test_image_page_shows_readable_expiration(make_app):
    app = make_app()
    client = app.test_client()
    buf = io.BytesIO()
    Image.new("RGB", (9, 9)).save(buf, "PNG")
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(buf.getvalue()), "a.png")},
                content_type="multipart/form-data")
    with app.app_context():
        file_id = next(iter(json_services.load_db()))
    html = app.test_client().get(f"/image/{file_id}").get_data(as_text=True)
    assert "+00:00" not in html and " à " in html


def test_french_error_pages(make_app):
    client = make_app().test_client()
    page = client.get("/cette-page-n-existe-pas", headers={"Accept": "text/html"})
    html = page.get_data(as_text=True)
    assert page.status_code == 404 and "Page introuvable" in html and "Not Found" not in html
    assert html.count("<h1") == 1
    raw = client.get("/view/inexistant", headers={"Accept": "image/*"})
    assert raw.status_code == 404 and "<html" not in raw.get_data(as_text=True)


def test_contact_appeal_type(make_app):
    html = make_app().test_client().get("/contact?type=appeal").get_data(as_text=True)
    assert '<h1 class="h4 mb-3">Contact</h1>' in html
    assert 'value="appeal" selected' in html and "Contester une décision de modération" in html


def test_legal_notice_is_up_to_date(make_app):
    html = make_app().test_client().get("/mentions-legales").get_data(as_text=True)
    assert "ne demande pas la création de compte" not in html and "facultative" in html
    assert "Cloudflare Turnstile" in html and "aperçu réduit" in html
    assert "utilise le" not in html


def test_after_upload_the_page_opens_on_the_new_file(make_app):
    app = make_app()
    client = app.test_client()
    buf = io.BytesIO()
    Image.new("RGB", (9, 9), (200, 30, 30)).save(buf, "PNG")
    resp = client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(buf.getvalue()), "a.png")},
                       content_type="multipart/form-data")
    with app.app_context():
        file_id = next(iter(json_services.load_db()))
    assert resp.headers["Location"].endswith(f"/?nouveau={file_id}#file-{file_id}")
    page = client.get(f"/?nouveau={file_id}").get_data(as_text=True)
    assert f'file-new" id="file-{file_id}"' in page.replace("  ", " ") or "file-new" in page
