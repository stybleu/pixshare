"""Le site s'adresse aux visiteurs et aux membres en les vouvoyant, partout (pas de tutoiement)."""
import html
import re

from test_accounts import PASSWORD, form_post, mails, member  # noqa: F401

TU = re.compile(r"\b(tu|ton|ta|tes|toi|te)\b", re.IGNORECASE)


def visible(page: str) -> str:
    page = re.sub(r"(?s)<(script|style|svg)[^>]*>.*?</\1>", " ", page)
    page = re.sub(r"<[^>]+>", " ", page)
    return html.unescape(page)


def test_no_tutoiement_on_visitor_and_member_pages(make_app, mails):
    app = make_app()
    guest = app.test_client()
    pages = ["/", "/inscription", "/connexion", "/mot-de-passe-oublie", "/inscription/renvoyer", "/contact", "/page-inconnue"]
    texts = {p: visible(guest.get(p, headers={"Accept": "text/html"}).get_data(as_text=True)) for p in pages}
    user = member(app.test_client(), mails)
    texts["/compte"] = visible(user.get("/compte").get_data(as_text=True))
    texts["/ (membre)"] = visible(user.get("/").get_data(as_text=True))
    texts["mails"] = " ".join(m["subject"] + " " + m["body"] for m in mails)
    for name, text in texts.items():
        found = TU.findall(text)
        assert not found, (name, found[:5])
