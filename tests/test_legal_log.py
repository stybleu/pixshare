"""Registre légal : 1 an, pour la justice uniquement (LCEN art. 6 V, décret 2021-1362)."""
from datetime import datetime, timedelta, timezone

from conftest import csrf, login
from test_accounts import mails, member, records, upload  # noqa: F401
from pixshare.services import legal_log_service as legal

IP = {"CF-Connecting-IP": "203.0.113.7"}


def rows(app, q=""):
    with app.app_context():
        return legal.search(q)


def test_upload_and_own_delete_are_logged(make_app):
    app = make_app()
    c = app.test_client()
    c.post("/", data={"csrf_token": csrf(c), "file": (__import__("io").BytesIO(
        __import__("test_upload_content").png()), "a.png")}, content_type="multipart/form-data", headers=IP)
    fid = next(iter(records(app)))
    r = rows(app, fid)
    assert len(r) == 1 and r[0]["op"] == legal.CREATION and r[0]["ip"] == "203.0.113.7" and r[0]["proto"].startswith("HTTP")
    c.post(f"/delete/{fid}", data={"csrf_token": csrf(c)}, headers=IP)
    assert [x["op"] for x in rows(app, fid)] == [legal.SUPPRESSION, legal.CREATION]


def test_member_actions_are_logged_with_email(make_app, mails):
    app = make_app()
    user = member(app.test_client(), mails)
    ops = [x["op"] for x in rows(app)]
    assert legal.COMPTE_CREATION in ops
    upload(user, "m.png")
    fid = next(k for k, m in records(app).items() if m["original_name"] == "m.png")
    assert rows(app, fid)[0]["author"].endswith("@example.com")
    user.post("/compte/supprimer", data={"csrf_token": csrf(user, "/compte"), "password": "mot-de-passe-solide",
                                         "confirm": "1"})
    # la ligne reste un an, même après la suppression du compte
    assert rows(app, fid)


def test_old_lines_are_purged_after_one_year(make_app):
    app = make_app()
    with app.app_context():
        from pixshare.services import sqlite_store
        from pixshare.services.json_services import _get_data_dir
        old = (datetime.now(timezone.utc) - timedelta(days=366)).isoformat(timespec="seconds")
        recent = (datetime.now(timezone.utc) - timedelta(days=300)).isoformat(timespec="seconds")
        sqlite_store.legal_add(_get_data_dir(), old, "création", "vieux", "1.1.1.1", "HTTPS", "")
        sqlite_store.legal_add(_get_data_dir(), recent, "création", "recent", "1.1.1.1", "HTTPS", "")
        assert legal.purge_if_due(force=True) == 1
        assert [r["content"] for r in legal.search()] == ["recent"]


def test_admin_only_and_csv_is_safe(make_app):
    app = make_app()
    with app.app_context():
        legal.record("message du livre d'or", "alb/1", author="=HYPERLINK(\"x\")", ip="198.51.100.1")
    assert app.test_client().get("/admin/registre-legal").status_code in (302, 401, 403, 404)
    admin = login(app.test_client())
    page = admin.get("/admin/registre-legal?q=198.51").get_data(as_text=True)
    assert "198.51.100.1" in page and "réquisition" in page
    csv_text = admin.get("/admin/registre-legal.csv?q=alb").get_data(as_text=True)
    assert "'=HYPERLINK" in csv_text and "198.51.100.1" in csv_text


def test_users_are_informed(make_app):
    c = make_app().test_client()
    assert "gardée un an, uniquement pour la justice" in c.get("/").get_data(as_text=True)
    legal_page = c.get("/mentions-legales").get_data(as_text=True)
    assert 'id="registre-legal"' in legal_page and "2021-1362" in legal_page
    assert "Conservation légale d’un an" in c.get("/cgu").get_data(as_text=True)
