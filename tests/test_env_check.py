"""Page Système : variables Render définies ou absentes, sans jamais afficher un secret."""
from conftest import login
from pixshare.services import env_check_service


def test_variables_panel_hides_secrets_and_flags_problems(make_app, monkeypatch):
    monkeypatch.setenv("MAIL_SMTP_HOST", "smtp.orange.fr")
    monkeypatch.setenv("MAIL_SMTP_USER", "moi@orange.fr")
    monkeypatch.setenv("MAIL_SMTP_PASS", "motdepasse-tres-secret")
    monkeypatch.setenv("MAIL_TO", "moi@orange.fr")
    monkeypatch.setenv("TURNSTILE_SECRET_KEY", "0x4AAAA-secret-turnstile")
    monkeypatch.setenv("MAX_LIFETIME_MIN", "10080")
    monkeypatch.setenv("GEOIP", "1")
    monkeypatch.setenv("MAIL_SMPT_PORT", "465")  # faute de frappe
    page = login(make_app().test_client()).get("/admin/system").get_data(as_text=True)
    assert "Variables d'environnement (Render)" in page
    for secret in ("motdepasse-tres-secret", "0x4AAAA-secret-turnstile", "s3cret-pass"):
        assert secret not in page
    assert "définie (masquée" in page and "smtp.orange.fr" in page
    assert "une seule des deux clés" in page                       # Turnstile incomplet
    assert "adresse visible par les inscrits" in page and "moi@orange.fr" in page
    assert "MAX_LIFETIME_MIN = 10080" in page
    assert "GEOIP ne sert plus" in page
    assert "MAIL_SMPT_PORT : variable inconnue" in page


def test_account_mail_checks(monkeypatch):
    monkeypatch.setenv("ACCOUNT_MAIL_SMTP_HOST", "smtp.gmail.com")
    monkeypatch.setenv("ACCOUNT_MAIL_SMTP_USER", "pixshare@gmail.com")
    monkeypatch.setenv("ACCOUNT_MAIL_FROM", "PixShare <autre@example.com>")
    messages = " ".join(m for _lvl, m in env_check_service.check()["problems"])
    assert "il manque ACCOUNT_MAIL_SMTP_PASS" in messages
    assert "Gmail refuse un expéditeur différent" in messages


def test_unrelated_variables_are_not_reported(monkeypatch):
    monkeypatch.setenv("MAX_THINKING_TOKENS", "1")
    monkeypatch.setenv("WEB_CONCURRENCY", "2")
    messages = " ".join(m for _lvl, m in env_check_service.check()["problems"])
    assert "MAX_THINKING_TOKENS" not in messages and "WEB_CONCURRENCY" not in messages
