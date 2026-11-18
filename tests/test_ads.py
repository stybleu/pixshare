"""Publicité : coupée par défaut, Google avec bandeau de consentement certifié, bannières directes sans pistage."""
import io

from PIL import Image

from conftest import csrf, login
from pixshare.services import ads_service
from test_accounts import mails, member  # noqa: F401

CLIENT = "ca-pub-1234567890123456"


def png_bytes(size=(728, 90)):
    buf = io.BytesIO()
    Image.new("RGB", size, (30, 90, 200)).save(buf, "PNG")
    return buf.getvalue()


def configure(admin, **fields):
    data = {"csrf_token": csrf(admin, "/admin/publicite"), "enabled": "1", "adsense_client": "", "auto_ads": "0",
            "hide_for_members": "1"}
    for name in ads_service.SLOTS:
        data.update({f"{name}_mode": "off", f"{name}_ad_slot": "", f"{name}_link": "", f"{name}_alt": ""})
    data.update(fields)
    return admin.post("/admin/publicite", data=data, content_type="multipart/form-data")


def test_off_by_default(make_app):
    client = make_app().test_client()
    home = client.get("/").get_data(as_text=True)
    assert "adsbygoogle" not in home and "Publicité" not in home
    assert "googlesyndication" not in client.get("/").headers["Content-Security-Policy"]
    assert client.get("/ads.txt").status_code == 404
    assert "n’affiche aucune publicité" in client.get("/mentions-legales").get_data(as_text=True)


def test_google_ads_with_consent_message_csp_and_ads_txt(make_app):
    app = make_app()
    admin = login(app.test_client())
    assert "Publicité" in admin.get("/admin/publicite").get_data(as_text=True)
    configure(admin, adsense_client=CLIENT, accueil_mode="google", accueil_ad_slot="1234567890")
    visitor = app.test_client()
    resp = visitor.get("/")
    page = resp.get_data(as_text=True)
    assert f"adsbygoogle.js?client={CLIENT}" in page and 'data-ad-slot="1234567890"' in page
    assert "Gérer mes choix de cookies" in page and "showRevocationMessage" in page
    assert ">Publicité<" in page                                    # mention obligatoire
    csp = resp.headers["Content-Security-Policy"]
    assert "https://pagead2.googlesyndication.com" in csp and "fundingchoicesmessages.google.com" in csp
    assert "frame-ancestors 'none'" in csp and "object-src 'none'" in csp  # le reste de la protection reste en place
    assert visitor.get("/ads.txt").get_data(as_text=True) == "google.com, pub-1234567890123456, DIRECT, f08c47fec0942fa0\n"
    legal = visitor.get("/mentions-legales")
    assert "Google AdSense" in legal.get_data(as_text=True)
    assert "googlesyndication" not in legal.headers["Content-Security-Policy"]  # pas d'annonce sur les pages légales
    for path in ("/cgu", "/contact", "/connexion", "/inscription", "/rien-du-tout"):
        r = visitor.get(path)
        assert "adsbygoogle" not in r.get_data(as_text=True), path
    assert "adsbygoogle" not in admin.get("/admin").get_data(as_text=True)


def test_members_see_no_ads_unless_admin_chooses(make_app, mails):
    app = make_app()
    admin = login(app.test_client())
    configure(admin, adsense_client=CLIENT, auto_ads="1")
    assert "adsbygoogle" in app.test_client().get("/").get_data(as_text=True)
    user = member(app.test_client(), mails)
    page = user.get("/").get_data(as_text=True)
    assert "adsbygoogle" not in page and "✔ Aucune" in user.get("/compte").get_data(as_text=True)
    configure(admin, adsense_client=CLIENT, auto_ads="1", hide_for_members="0")
    assert "adsbygoogle" in user.get("/").get_data(as_text=True)


def test_direct_banner_counts_clicks_without_tracking(make_app):
    app = make_app()
    admin = login(app.test_client())
    configure(admin, pied_mode="direct", pied_link="https://partenaire.example/offre", pied_alt="Partenaire",
              pied_image=(io.BytesIO(png_bytes()), "banniere.png"))
    visitor = app.test_client()
    resp = visitor.get("/")
    page = resp.get_data(as_text=True)
    assert 'rel="sponsored noopener"' in page and 'alt="Partenaire"' in page
    assert "adsbygoogle" not in page and "googlesyndication" not in resp.headers["Content-Security-Policy"]
    img = visitor.get("/pub/pied")
    assert img.status_code == 200 and img.mimetype == "image/png"
    click = visitor.get("/pub/pied/clic")
    assert click.status_code == 302 and click.headers["Location"] == "https://partenaire.example/offre"
    assert "Set-Cookie" not in click.headers
    with app.app_context():
        assert ads_service.load()["clicks"]["pied"] == 1
    assert "1 clic(s)" in admin.get("/admin/publicite").get_data(as_text=True)
    assert "seul le" in visitor.get("/mentions-legales").get_data(as_text=True)  # bannières décrites


def test_bad_inputs_are_refused(make_app):
    app = make_app()
    admin = login(app.test_client())
    configure(admin, adsense_client="<script>alert(1)</script>")
    with app.app_context():
        assert ads_service.load()["adsense_client"] == ""
    configure(admin, pied_mode="direct", pied_link="javascript:alert(1)",
              pied_image=(io.BytesIO(b"<svg onload=alert(1)>"), "x.svg"))
    configure(admin, accueil_mode="google", accueil_ad_slot="12'><script>")
    with app.app_context():
        cfg = ads_service.load()
    assert cfg["slots"]["pied"]["link"] == "" and cfg["slots"]["pied"]["image"] == ""
    assert cfg["slots"]["accueil"]["ad_slot"] == ""
    visitor = app.test_client()
    assert "<script>alert" not in visitor.get("/").get_data(as_text=True)
    for path in ("/pub/pied", "/pub/pied/clic", "/pub/../ads.json", "/pub/inconnu"):
        assert visitor.get(path).status_code == 404, path


def test_only_admin_can_configure(make_app):
    client = make_app().test_client()
    assert client.get("/admin/publicite").status_code == 302
    assert client.post("/admin/publicite", data={"enabled": "1"}).status_code in (302, 400, 403)
    assert "Disallow: /pub/" in client.get("/robots.txt").get_data(as_text=True)


def test_admin_menu_has_ads_tab(make_app):
    admin = login(make_app().test_client())
    html = admin.get("/admin/publicite").get_data(as_text=True)
    assert html.count('aria-label="Menu de l\'admin"') == 1 and 'aria-current="page"' in html
    assert ">Publicité</a>" in admin.get("/admin").get_data(as_text=True)
