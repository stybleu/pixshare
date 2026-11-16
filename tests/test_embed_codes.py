"""Codes prêts à copier sur la page d'une image : lien, HTML, BBCode, Markdown."""
import io
import re

from PIL import Image

from conftest import csrf
from pixshare.services import json_services
from pixshare.services.embed_service import embed_codes


def test_codes_are_correct_and_safe():
    codes = {c["key"]: c["code"] for c in embed_codes("https://pixshare.fr/image/abc", "https://pixshare.fr/view/abc",
                                                      'mon "chat" [drôle](x)<b>.png')}
    assert codes["bbcode"] == "[img]https://pixshare.fr/view/abc[/img]"
    assert codes["bbcode_link"] == "[url=https://pixshare.fr/image/abc][img]https://pixshare.fr/view/abc[/img][/url]"
    assert codes["markdown"].startswith("![mon  chat   drôle  x  b") and codes["markdown"].endswith("](https://pixshare.fr/view/abc)")
    assert codes["markdown_link"].endswith(")](https://pixshare.fr/image/abc)")
    assert codes["html"].startswith('<img src="https://pixshare.fr/view/abc" alt="') and '"chat"' not in codes["html"]
    assert "<b>" not in codes["html"]


def test_image_page_shows_codes_with_full_links(make_app):
    app = make_app(NSFW_AUTO_MODERATION=False)
    client = app.test_client()
    buf = io.BytesIO()
    Image.new("RGB", (10, 10), "red").save(buf, "PNG")
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(buf.getvalue()), "vacances.png")},
                content_type="multipart/form-data")
    with app.app_context():
        (file_id,) = json_services.load_db()
    html = client.get(f"/image/{file_id}").get_data(as_text=True)
    assert html.count('class="btn btn-outline-primary embed-copy"') == 8
    assert f"[img]http://localhost/view/{file_id}[/img]" in html
    assert f"![vacances](http://localhost/view/{file_id})" in html
    assert re.search(r'value="&lt;img src=&#34;http://localhost/view/' + file_id, html)
