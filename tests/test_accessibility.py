"""Accessibilité de base : un seul titre h1, chaque champ a une étiquette, les images ont un texte alternatif."""
from html.parser import HTMLParser

import pytest

from conftest import login


class Audit(HTMLParser):
    def __init__(self):
        super().__init__()
        self.h1 = 0
        self.problems = []
        self.labels_for = set()
        self.fields = []
        self.in_label = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "label":
            self.in_label += 1
            if a.get("for"):
                self.labels_for.add(a["for"])
        elif tag == "h1":
            self.h1 += 1
        elif tag == "img" and "alt" not in a:
            self.problems.append(f"image sans alt : {a.get('src')}")
        elif tag in ("input", "select", "textarea") and a.get("type") not in ("hidden", "submit", "button"):
            self.fields.append((a.get("name") or a.get("id"), a.get("id"), bool(a.get("aria-label")), self.in_label > 0))

    def handle_endtag(self, tag):
        if tag == "label":
            self.in_label -= 1

    def check(self):
        for name, fid, aria, wrapped in self.fields:
            if not (aria or wrapped or (fid and fid in self.labels_for)):
                self.problems.append(f"champ sans étiquette : {name}")
        if self.h1 != 1:
            self.problems.append(f"{self.h1} titres h1")
        return self.problems


PUBLIC = ["/", "/contact", "/cgu", "/mentions-legales", "/admin/login"]
ADMIN = ["/admin", "/admin/stats", "/admin/settings", "/admin/blocked-ips", "/admin/thumbnails", "/admin/messages", "/admin/system"]


@pytest.mark.parametrize("path", PUBLIC + ADMIN)
def test_page_is_accessible(make_app, path):
    app = make_app()
    client = login(app.test_client()) if path in ADMIN else app.test_client()
    resp = client.get(path)
    assert resp.status_code == 200
    audit = Audit()
    audit.feed(resp.get_data(as_text=True))
    assert audit.check() == []
