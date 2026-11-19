"""Contenu des pages publiques : rien d'obsolète, dates lisibles, pages d'erreur en français."""
import io
from PIL import Image

from conftest import csrf
from pixshare.services import json_services


def test_homepage_mentions_only_existing_features(make_app):
    html = make_app().test_client().get("/").get_data(as_text=True)
    assert "API" not in html and "qualitée" not in html
    for text in ("Codes prêts à coller", "Position GPS", "Mot de passe et suppression après un nombre de vues", "Compte gratuit facultatif",
                 "Glissez-déposez", "utilisez le bouton"):
        assert text in html, text
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
