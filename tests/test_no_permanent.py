"""Les fichiers permanents n'existent plus : tout expire, rien n'est listé pour Google."""
import io

from PIL import Image

from conftest import csrf
from pixshare.services import file_service, json_services


def png():
    buf = io.BytesIO()
    Image.new("RGB", (20, 20), "blue").save(buf, "PNG")
    return buf.getvalue()


def test_keep_checkbox_is_gone_and_ignored(make_app):
    app = make_app(NSFW_AUTO_MODERATION=False)
    client = app.test_client()
    assert 'name="keep"' not in client.get("/").get_data(as_text=True)
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(png()), "a.png"), "keep": "1"},
                content_type="multipart/form-data")
    with app.app_context():
        (meta,) = json_services.load_db().values()
    assert meta["permanent"] is False and meta["expires_at"]


def test_old_permanent_files_now_expire_and_stay_out_of_google(make_app):
    app = make_app(NSFW_AUTO_MODERATION=False)
    client = app.test_client()
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(png()), "a.png")},
                content_type="multipart/form-data")
    with app.app_context():
        db = json_services.load_db()
        file_id, meta = next(iter(db.items()))
        meta.update(permanent=True, expires_at="")
        json_services.save_db(db)
        file_service.cleanup_expired()
        meta = json_services.load_db()[file_id]
    assert meta["permanent"] is False and meta["expires_at"]
    page = client.get(f"/image/{file_id}")
    assert "noindex" in page.headers.get("X-Robots-Tag", "")
    assert f"/image/{file_id}" not in client.get("/sitemap.xml").get_data(as_text=True)
