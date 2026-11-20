"""Page des questions fréquentes : réponses justes, qui suivent les réglages."""
import json
import re


def settings(app, **values):
    from pixshare.services import settings_service
    with app.app_context():
        s = settings_service.load_settings()
        s.update(values)
        settings_service.save_settings(s)


def test_faq_page(make_app):
    app = make_app()
    client = app.test_client()
    page = client.get("/faq").get_data(as_text=True)
    assert "Questions fréquentes" in page and "Quels formats sont acceptés ?" in page
    assert "Comment créer un album pour un mariage" in page and "/album-souvenir" in page
    data = json.loads(re.search(r'<script type="application/ld\+json">\s*(.*?)\s*</script>', page, re.S).group(1))
    assert data["@type"] == "FAQPage" and len(data["mainEntity"]) >= 15
    assert "/faq" in client.get("/").get_data(as_text=True)                 # lien en bas de page
    assert "questions fréquentes" in client.get("/contact").get_data(as_text=True)


def test_faq_follows_settings(make_app):
    app = make_app()
    settings(app, guest_max_upload_size_mb=7, albums_enabled=False)
    page = app.test_client().get("/faq").get_data(as_text=True)
    assert "7 Mo sans compte" in page
    assert "Comment créer un album" not in page and "albums souvenirs à partager" not in page


def test_faq_google_answer_is_clear_and_donation_is_linked(make_app):
    from pixshare.services.settings_service import get_support_url
    app = make_app()
    page = app.test_client().get("/faq").get_data(as_text=True)
    assert "apparaissent pas dans les résultats de Google" in page
    assert "signalés à Google" not in page
    with app.app_context():
        url = get_support_url()
    if url:
        assert f'href="{url}" target="_blank" rel="noopener noreferrer">☕ Soutenir PixShare' in page
