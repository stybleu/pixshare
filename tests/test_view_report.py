"""Le lien /view/ ouvert dans le navigateur propose aussi « Signaler » ; intégré ailleurs, c'est l'image brute."""
import io

from PIL import Image

from conftest import csrf
from pixshare.services import json_services

DOC = {"Sec-Fetch-Dest": "document"}


def setup(make_app):
    app = make_app(NSFW_AUTO_MODERATION=False)
    client = app.test_client()
    buf = io.BytesIO()
    Image.new("RGB", (20, 20), "blue").save(buf, "PNG")
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(buf.getvalue()), "a.png")},
                content_type="multipart/form-data")
    with app.app_context():
        (file_id,) = json_services.load_db()
    return app, file_id


def views(app, file_id):
    with app.app_context():
        return json_services.load_db()[file_id].get("views", 0)


def test_browser_gets_a_page_with_report_button(make_app):
    app, file_id = setup(make_app)
    resp = app.test_client().get(f"/view/{file_id}", headers=DOC)
    html = resp.get_data(as_text=True)
    assert resp.mimetype == "text/html" and f"/report/{file_id}" in html and f"/view/{file_id}?raw=1" in html
    assert "noindex" in resp.headers["X-Robots-Tag"] and "Sec-Fetch-Dest" in resp.headers["Vary"]
    assert views(app, file_id) == 0  # la page seule ne compte pas de vue


def test_embeds_and_raw_link_get_the_image(make_app):
    app, file_id = setup(make_app)
    client = app.test_client()
    assert client.get(f"/view/{file_id}", headers={"Sec-Fetch-Dest": "image"}).mimetype == "image/png"
    assert client.get(f"/view/{file_id}").mimetype == "image/png"  # robots, aperçus, vieux navigateurs
    assert client.get(f"/view/{file_id}?raw=1", headers=DOC).mimetype == "image/png"
    assert views(app, file_id) == 1


def test_report_from_view_page_comes_back_to_it(make_app):
    app, file_id = setup(make_app)
    client = app.test_client()
    token = csrf(client, f"/image/{file_id}")
    resp = client.post(f"/report/{file_id}", data={"csrf_token": token, "reason": "violence", "back": "view"})
    assert resp.headers["Location"].endswith(f"/view/{file_id}")
    assert "Merci" in client.get(f"/view/{file_id}", headers=DOC).get_data(as_text=True)
