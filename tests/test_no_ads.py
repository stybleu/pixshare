"""La publicité est retirée du site : aucune annonce, aucun script de régie, rien dans l'admin."""
from conftest import login


def test_no_ads_anywhere(make_app):
    client = make_app().test_client()
    for page in ("/", "/cgu", "/mentions-legales", "/album-souvenir", "/contact"):
        text = client.get(page).get_data(as_text=True)
        assert "adsbygoogle" not in text and "pxs-ad" not in text, page
    assert "googlesyndication" not in client.get("/").headers["Content-Security-Policy"]
    assert "n’affiche aucune publicité" in client.get("/mentions-legales").get_data(as_text=True)
    assert "sans but lucratif et sans publicité" in client.get("/cgu").get_data(as_text=True)
    for url in ("/ads.txt", "/pub/pied", "/pub/pied/clic"):
        assert client.get(url).status_code == 404
    admin = login(make_app().test_client())
    assert admin.get("/admin/publicite").status_code == 404
    assert ">Publicité</a>" not in admin.get("/admin").get_data(as_text=True)
