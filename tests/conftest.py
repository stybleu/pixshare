"""Outils communs aux tests : une appli PixShare isolée par test (dossiers temporaires).

Lancer les tests depuis la racine du projet :  python -m pytest -q tests
"""
import os
import re
import shutil
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.dirname(os.path.abspath(__file__))
for path in (ROOT, TESTS):
    if path not in sys.path:
        sys.path.insert(0, path)

# Avant d'importer l'appli : la configuration lit ces variables au chargement.
os.environ["ADMIN_USER"] = "boss"
os.environ["ADMIN_PASS"] = "s3cret-pass"
os.environ["SECRET_KEY"] = "cle-de-test-" + "x" * 32
for name in ("MAIL_SMTP_HOST", "MAIL_TO", "NSFW_CLASSES", "NSFW_REVIEW_THRESHOLD", "NSFW_BLOCK_THRESHOLD"):
    os.environ.pop(name, None)

from pixshare import create_app  # noqa: E402

ADMIN_USER = "boss"
ADMIN_PASS = "s3cret-pass"


def csrf(client, path="/"):
    """Jeton CSRF de la session du client (lu dans un formulaire de la page)."""
    html = client.get(path).get_data(as_text=True)
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, f"pas de jeton CSRF sur {path}"
    return match.group(1)


def login(client):
    client.post("/admin/login", data={"csrf_token": csrf(client), "username": ADMIN_USER, "password": ADMIN_PASS})
    return client


@pytest.fixture
def make_app(tmp_path, monkeypatch):
    """make_app(**config) -> appli Flask avec ses données, envois et miniatures dans tmp_path."""

    def _make(**overrides):
        data = tmp_path / "data"
        data.mkdir(exist_ok=True)
        translations = os.path.join(ROOT, "pixshare", "data", "translations")
        if os.path.isdir(translations) and not (data / "translations").exists():
            shutil.copytree(translations, data / "translations")
        monkeypatch.setenv("PIXSHARE_DATA_DIR", str(data))
        config = {
            "TESTING": True,
            "ADMIN_USER": ADMIN_USER,
            "ADMIN_PASS": ADMIN_PASS,
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
            "THUMBNAIL_FOLDER": str(tmp_path / "thumbs"),
        }
        config.update(overrides)
        return create_app(config)

    return _make
