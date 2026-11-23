"""Nombre de vues : ni l'envoyeur, ni l'admin, ni les robots ; un vrai visiteur compte une fois."""
from conftest import login
from test_accounts import mails, records, upload  # noqa: F401

BROWSER = {"User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/131 Mobile Safari/537.36"}


def views(app, name):
    return next(m for m in records(app).values() if m["original_name"] == name).get("views", 0)


def fid(app, name):
    return next(k for k, m in records(app).items() if m["original_name"] == name)


def test_owner_admin_and_bots_do_not_count(make_app):
    app = make_app()
    owner = app.test_client()
    upload(owner, "a.png")
    f = fid(app, "a.png")
    owner.get(f"/file/{f}", headers=BROWSER)                  # sa page de partage
    owner.get(f"/view/{f}", headers=BROWSER)                  # la photo dans « Mes envois »
    admin = login(app.test_client())
    admin.get(f"/view/{f}", headers=BROWSER)
    for ua in ("WhatsApp/2.23", "facebookexternalhit/1.1", "Mozilla/5.0 (compatible; Discordbot/2.0)", ""):
        app.test_client().get(f"/file/{f}", headers={"User-Agent": ua})
    assert views(app, "a.png") == 0


def test_real_visitor_counts_once(make_app):
    app = make_app()
    upload(app.test_client(), "a.png")
    f = fid(app, "a.png")
    friend = app.test_client()
    for _ in range(3):
        friend.get(f"/file/{f}", headers=BROWSER)
        friend.get(f"/view/{f}", headers=BROWSER)
    assert views(app, "a.png") == 1
    app.test_client().get(f"/file/{f}", headers=BROWSER | {"X-Forwarded-For": "203.0.113.9"})
    assert views(app, "a.png") == 2


def test_cookieless_reloads_count_once(make_app):
    """Image intégrée sur un autre site : pas de cookie, mais recharger ne recompte pas."""
    app = make_app()
    upload(app.test_client(), "a.png")
    f = fid(app, "a.png")
    for _ in range(4):
        app.test_client().get(f"/view/{f}", headers=BROWSER)   # client neuf à chaque fois = sans cookie
    assert views(app, "a.png") == 1


def test_view_limited_image_still_shows_on_first_visit(make_app, mails):  # noqa: F811
    from test_accounts import member
    app = make_app()
    user = member(app.test_client(), mails)
    upload(user, "limite.png", view_limit_enabled="1", max_views="5")
    f = fid(app, "limite.png")
    visitor = app.test_client()
    assert visitor.get(f"/file/{f}", headers=BROWSER).status_code == 200
    assert visitor.get(f"/view/{f}", headers=BROWSER).status_code == 200   # l'image de la page s'affiche
    assert views(app, "limite.png") == 1
