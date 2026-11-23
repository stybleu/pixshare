"""Audit de novembre 2026 : redirection piégée, en-têtes, textes légaux, exposé des motifs."""
from pixshare.services.moderation_service import removal_message


def test_login_next_rejects_backslash_tricks(make_app):
    from pixshare.routes.account_routes import _safe_next
    app = make_app()
    for bad in ("/\\evil.com", "//evil.com", "https://evil.com", "/\x09/evil.com", "/\x00x"):
        with app.test_request_context("/connexion", query_string={"next": bad}):
            assert _safe_next() == "", bad
    with app.test_request_context("/connexion", query_string={"next": "/compte"}):
        assert _safe_next() == "/compte"


def test_security_headers(make_app):
    r = make_app().test_client().get("/")
    assert "form-action 'self'" in r.headers["Content-Security-Policy"]
    assert "camera=()" in r.headers["Permissions-Policy"]
    assert r.headers["Cross-Origin-Opener-Policy"] == "same-origin"


def test_legal_texts(make_app):
    c = make_app().test_client()
    legal = c.get("/mentions-legales").get_data(as_text=True)
    for needle in ("2022/2065", "Intérêt légitime", "portabilité", "Data Privacy Framework", "internet-signalement.gouv.fr",
                   "Point de contact unique"):
        assert needle in legal, needle
    cgu = c.get("/cgu").get_data(as_text=True)
    assert "au moins 15 ans" in cgu and "deux parents" in cgu


def test_statement_of_reasons():
    auto = removal_message({"original_name": "a.jpg", "server_name": "x.jpg", "moderation_label": "nudite"}, "auto:admin_absent")
    assert "automatiquement" in auto and "réexamen" in auto
    manual = removal_message({"original_name": "a.jpg", "server_name": "x.jpg"}, "non_respect_cgu")
    assert "automatiquement" not in manual and "Contester une décision de modération" in manual
