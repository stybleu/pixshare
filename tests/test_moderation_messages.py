"""Une image retirée par la modération : la personne sait laquelle et pourquoi ; un membre peut la remplacer."""
import io
from datetime import timedelta

import pytest
from PIL import Image

from conftest import csrf
from test_accounts import PASSWORD, form_post, login_new_device, mails, member, png, records, upload  # noqa: F401

from pixshare.services.json_services import load_db, save_db
from pixshare.services.moderation_service import create_moderation_notice, pop_pending_notice, removal_message
from pixshare.services.time_service import utcnow


@pytest.fixture
def app(make_app):
    return make_app()


def _png(color=(10, 120, 200)):
    buf = io.BytesIO()
    Image.new("RGB", (64, 64), color).save(buf, "PNG")
    return buf.getvalue()


def test_message_names_image_and_reason(app):
    with app.app_context():
        msg = removal_message({"original_name": "plage.jpg", "server_name": "a.jpg",
                               "moderation_label": "FEMALE_BREAST_EXPOSED"}, "non_respect_cgu")
        assert "« plage.jpg »" in msg and "nudité détectée" in msg
        msg = removal_message({"original_name": "x.png", "server_name": "b.png", "moderation_label": "deja_refusee"},
                              "non_respect_cgu")
        assert "déjà interdite" in msg
        msg = removal_message({"original_name": "x.png", "server_name": "b.png", "account_id": "acc1"}, "spam_abus")
        assert "usage abusif" in msg and "même lien" in msg


def test_member_notice_follows_account_on_any_device(app):
    with app.app_context():
        meta = {"guest_token": "tok-phone", "account_id": "acc-42", "original_name": "photo.jpg",
                "server_name": "f.jpg", "moderation_label": "BUTTOCKS_EXPOSED"}
        assert create_moderation_notice(meta, "f1", "non_respect_cgu")
        # l'autre appareil n'a pas le même jeton visiteur, mais c'est le même compte
        notice = pop_pending_notice("tok-tablette", "acc-42")
        assert notice and "photo.jpg" in notice["message"]
        assert pop_pending_notice("tok-phone", "") is None  # vu une fois, plus de doublon


def test_guest_without_token_but_with_account_still_notified(app):
    with app.app_context():
        assert create_moderation_notice({"account_id": "acc-7", "original_name": "z.png"}, "f2", "contenu_illicite")
        assert not create_moderation_notice({"original_name": "z.png"}, "f3", "contenu_illicite")


def _removed(file_id, account_id, days_ago=1, reason="non_respect_cgu", expires_in_days=10):
    now = utcnow()
    db = load_db()
    db[file_id] = {"original_name": "vieille.png", "server_name": f"{file_id}.png", "status": "deleted",
                   "delete_reason": reason, "deleted_at": (now - timedelta(days=days_ago)).isoformat(timespec="seconds"),
                   "account_id": account_id, "guest_token": "autre",
                   "expires_at": (now + timedelta(days=expires_in_days)).isoformat(timespec="seconds"),
                   "uploaded_at": now.isoformat(timespec="seconds"), "views": 3}
    save_db(db)


def test_can_replace_rules(app):
    from pixshare.services.file_service import can_replace_removed
    with app.app_context():
        _removed("r1", "acc")
        _removed("r2", "acc", days_ago=9)
        _removed("r3", "acc", reason="deleted")
        _removed("r4", "acc", expires_in_days=-1)
        db = load_db()
        assert can_replace_removed(db["r1"], "acc")
        assert not can_replace_removed(db["r1"], "someone-else")
        assert not can_replace_removed(db["r1"], None)
        assert not can_replace_removed(db["r2"], "acc")   # trop ancienne
        assert not can_replace_removed(db["r3"], "acc")   # supprimée par son auteur
        assert not can_replace_removed(db["r4"], "acc")   # expirée


def test_replace_removed_image_keeps_link(app, monkeypatch):
    from pixshare.services import file_service
    from pixshare.services.file_service import replace_file
    from werkzeug.datastructures import FileStorage
    monkeypatch.setattr(file_service, "_check_banned", lambda *a, **k: None)
    with app.test_request_context():
        _removed("keep1", "acc")
        meta = replace_file("keep1", FileStorage(io.BytesIO(_png()), "nouvelle.png"), "nouvelle.png", "1.2.3.4", 10**7)
        assert meta["status"] in ("pending", "active")
        assert "delete_reason" not in meta and "deleted_at" not in meta
        assert meta["original_name"] == "nouvelle.png" and meta["views"] == 3
        assert load_db()["keep1"]["restored_after_removal"]


def test_member_end_to_end_other_device(make_app, mails):
    from pixshare.services.file_service import delete_by_id
    app = make_app()
    phone = member(app.test_client(), mails)
    upload(phone, "vacances.png", png((20, 160, 40)))
    file_id = next(iter(records(app)))
    with app.test_request_context():
        db = load_db(); db[file_id]["moderation_label"] = "FEMALE_BREAST_EXPOSED"; save_db(db)
        create_moderation_notice(load_db()[file_id], file_id, "non_respect_cgu")
        delete_by_id(file_id, reason="non_respect_cgu")
    assert records(app)[file_id]["status"] == "deleted"

    tablet = app.test_client()  # l'autre appareil : se connecte au même compte
    login_new_device(tablet, mails)
    page = tablet.get("/").get_data(as_text=True)
    assert "« vacances.png » a été retirée par la modération : nudité détectée" in page   # le message
    assert "retirée par la modération" in page and "Remplacer (même lien)" in page        # la trace dans Mes fichiers
    assert "a été retirée par la modération : nudité" not in tablet.get("/").get_data(as_text=True)  # message vu une fois

    resp = tablet.post(f"/remplacer/{file_id}", data={"csrf_token": csrf(tablet), "file": (io.BytesIO(png((200, 10, 10))), "autre.png")},
                       content_type="multipart/form-data")
    resp.close()
    assert resp.status_code == 302
    rec = records(app)[file_id]
    assert rec["status"] in ("pending", "active") and rec["original_name"] == "autre.png"
    assert "Remplacer (même lien)" not in tablet.get("/").get_data(as_text=True)

    guest = app.test_client()
    with app.test_request_context():
        delete_by_id(file_id, reason="non_respect_cgu")
    resp = guest.post(f"/remplacer/{file_id}", data={"csrf_token": csrf(guest), "file": (io.BytesIO(png()), "x.png")},
                      content_type="multipart/form-data")
    assert resp.status_code == 302 and "/connexion" in resp.headers["Location"]
