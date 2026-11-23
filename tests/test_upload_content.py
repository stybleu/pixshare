"""Contenu réel des fichiers : une page web ou un programme renommé en .png / .mp4 est refusé."""
import io

from PIL import Image

from conftest import csrf
from test_accounts import records, upload
from pixshare.services.file_service import content_matches_extension as ok


def png():
    buf = io.BytesIO()
    Image.new("RGB", (8, 8), (1, 2, 3)).save(buf, "PNG")
    return buf.getvalue()


def test_signatures():
    assert ok(png(), ".png") and ok(png(), ".jpg")                    # PNG mal nommé par un téléphone : accepté
    assert ok(b"\xff\xd8\xff\xe0" + b"\0" * 20, ".jpeg")
    assert ok(b"\0\0\0\x18ftypheic" + b"\0" * 8, ".heic")
    assert ok(b"\0\0\0\x18ftypisom" + b"\0" * 8, ".mp4") and ok(b"\0\0\0\x18ftypM4A " + b"\0" * 8, ".m4a")
    assert ok(b"\x1a\x45\xdf\xa3" + b"\0" * 20, ".webm") and ok(b"OggS" + b"\0" * 20, ".ogg")
    assert ok(b"ID3\x04" + b"\0" * 20, ".mp3") and ok(b"fLaC" + b"\0" * 20, ".flac")
    assert ok(b"RIFF\0\0\0\0WAVEfmt ", ".wav") and ok(b"RIFF\0\0\0\0AVI LIST", ".avi")
    assert not ok(b"<html><script>alert(1)</script>", ".png")
    assert not ok(b"PK\x03\x04" + b"\0" * 20, ".jpg")                  # archive .zip
    assert not ok(b"MZ\x90\0" + b"\0" * 20, ".mp4")                    # programme Windows
    assert not ok(b"ID3\x04" + b"\0" * 20, ".png")                     # un son déguisé en image
    assert not ok(png(), ".mp4")                                      # une image déguisée en vidéo


def test_disguised_upload_is_refused(make_app):
    app = make_app()
    c = app.test_client()
    upload(c, "piege.png", data=b"<html><script>alert(1)</script></html>")
    upload(c, "piege.mp4", data=b"MZ\x90\x00 programme")
    assert not records(app)
    with c.session_transaction() as s:
        assert any("pas une vraie photo" in msg for _c, msg in s.get("_flashes", []))
    upload(c, "vraie.png", data=png())
    assert [m["original_name"] for m in records(app).values()] == ["vraie.png"]


def test_disguised_file_in_multi_upload(make_app):
    app = make_app()
    c = app.test_client()
    c.post("/", data={"csrf_token": csrf(c), "file": [(io.BytesIO(png()), "a.png"), (io.BytesIO(b"<html>"), "b.png")]},
           content_type="multipart/form-data")
    assert [m["original_name"] for m in records(app).values()] == ["a.png"]
