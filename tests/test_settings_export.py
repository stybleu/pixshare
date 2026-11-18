"""Les réglages de l'admin survivent aux déploiements grâce à la variable Render PIXSHARE_SETTINGS."""
import json

from conftest import csrf, login
from pixshare.services import settings_service


def test_export_then_fresh_deploy_restores_settings(make_app, monkeypatch):
    app = make_app()
    client = login(app.test_client())
    client.post("/admin/settings/nsfw", data={"csrf_token": csrf(client, "/admin/settings"), "nsfw_auto_moderation": "1",
                                              "nsfw_tiling": "0", "nsfw_review_threshold": "0.55", "nsfw_block_threshold": "0.9"})
    page = client.get("/admin/settings").get_data(as_text=True)
    assert "PIXSHARE_SETTINGS" in page and "pas encore sauvegardés" in page
    with app.app_context():
        exported = settings_service.export_settings()
    data = json.loads(exported)
    assert data["nsfw_review_threshold"] == 0.55 and "allow_permanent_files" not in data

    # Nouveau déploiement : fichiers effacés, variable Render remplie
    monkeypatch.setenv("PIXSHARE_SETTINGS", exported)
    with app.app_context():
        import os
        from pixshare.services import sqlite_store
        sqlite_store.delete_document(os.environ["PIXSHARE_DATA_DIR"], "settings.json")
        restored = settings_service.load_settings()
        assert restored["nsfw_review_threshold"] == 0.55 and restored["nsfw_tiling"] is False
        assert settings_service.export_matches_env()
    assert "déjà sauvegardés" in client.get("/admin/settings").get_data(as_text=True)


def test_bad_variable_is_ignored(make_app, monkeypatch):
    monkeypatch.setenv("PIXSHARE_SETTINGS", "{pas du json")
    app = make_app()
    with app.app_context():
        assert settings_service.load_settings()["max_upload_size_mb"] == 100
