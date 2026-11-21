"""Vitesse de la page d'accueil sur mobile : rien de lourd ni d'inutile au chargement."""
import os


def test_antirobot_is_not_loaded_on_arrival(make_app, monkeypatch):
    monkeypatch.setenv("TURNSTILE_SITE_KEY", "cle-site")
    monkeypatch.setenv("TURNSTILE_SECRET_KEY", "cle-secrete")
    page = make_app().test_client().get("/").get_data(as_text=True)
    assert 'class="cf-turnstile' in page                                    # la case est là…
    assert '<script src="https://challenges.cloudflare.com' not in page      # …mais le script vient au premier geste
    assert "turnstile/v0/api.js" in page and "requestSubmit" in page


def test_icons_are_light(make_app):
    page = make_app().test_client().get("/").get_data(as_text=True)
    assert "favicon-32.png" in page and "apple-touch-icon.png" in page
    root = os.path.join(os.path.dirname(__file__), "..", "static")
    for name in ("favicon-32.png", "favicon-192.png", "apple-touch-icon.png", "favicon.png", "images/pixshare_logo.png"):
        assert os.path.getsize(os.path.join(root, name)) < 60_000, name
