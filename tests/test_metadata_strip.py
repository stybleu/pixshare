"""Les fichiers envoyés ne doivent plus contenir de GPS, de nom ou de modèle d'appareil."""
import io
import os
import struct

import pytest
from PIL import Image, PngImagePlugin

from conftest import csrf
from pixshare.services import file_service, json_services
from pixshare.services.image_metadata_service import strip_image_metadata_file, strip_video_metadata_file

SECRETS = (b"Guillaume", b"Samsung", b"48.25")


def exif():
    e = Image.Exif()
    e[0x010F] = "Samsung"
    e[0x013B] = "Guillaume"
    e[0x0112] = 6  # orientation : à garder
    e[0x8825] = {1: "N", 2: (48.0, 15.0, 0.0), 3: "E", 4: (1.0, 26.0, 0.0), 0x1B: "48.25"}
    return e


def leaks(path):
    data = open(path, "rb").read()
    return [s for s in SECRETS if s in data]


@pytest.mark.parametrize("ext,fmt", [("jpg", "JPEG"), ("webp", "WEBP"), ("png", "PNG")])
def test_common_photos_lose_gps_but_keep_orientation(tmp_path, ext, fmt):
    path = tmp_path / f"a.{ext}"
    kw = {"exif": exif()}
    if fmt == "PNG":
        info = PngImagePlugin.PngInfo()
        info.add_text("Author", "Guillaume 48.25")
        kw["pnginfo"] = info
    Image.new("RGB", (40, 30), "red").save(path, fmt, **kw)
    assert leaks(path)
    assert strip_image_metadata_file(path)
    assert leaks(path) == []
    with Image.open(path) as im:
        assert im.size == (40, 30) and im.getexif().get(0x0112) == 6


def test_gif_loses_comments_and_xmp_but_stays_animated(tmp_path):
    path = tmp_path / "a.gif"
    frames = [Image.new("RGB", (20, 20), c) for c in ("red", "blue", "green")]
    frames[0].save(path, save_all=True, append_images=frames[1:], loop=0, duration=100,
                   comment=b"Guillaume 48.25")
    data = open(path, "rb").read()
    xmp = b"\x21\xff\x0bXMP DataXMP" + b"\x0dSamsung 48.25" + b"\x00"
    open(path, "wb").write(data[:-1] + xmp + b"\x3b" + b"cache: Guillaume")
    assert strip_image_metadata_file(path)
    assert leaks(path) == []
    with Image.open(path) as im:
        assert im.n_frames == 3 and im.info.get("loop") == 0


def test_tiff_is_rewritten_without_tags(tmp_path):
    path = tmp_path / "a.tif"
    Image.new("RGB", (30, 20), "red").save(path, tiffinfo={0x010F: "Samsung", 0x013B: "Guillaume", 0x010E: "48.25"})
    assert leaks(path)
    assert strip_image_metadata_file(path)
    assert leaks(path) == []
    with Image.open(path) as im:
        assert im.size == (30, 20) and im.getpixel((0, 0)) == (255, 0, 0)


def box(kind, payload):
    return struct.pack(">I", 8 + len(payload)) + kind + payload


def test_video_metadata_is_blanked_in_place(tmp_path):
    udta = box(b"udta", box(b"\xa9xyz", b"+48.2500+001.4300/") + box(b"\xa9mak", b"Samsung"))
    trak = box(b"trak", box(b"tkhd", b"\x00" * 20) + box(b"udta", box(b"name", b"Guillaume")))
    moov = box(b"moov", box(b"mvhd", b"\x00" * 20) + trak + udta)
    data = box(b"ftyp", b"isom\x00\x00\x02\x00isom") + moov + box(b"mdat", b"VIDEO" * 10)
    path = tmp_path / "a.mp4"
    path.write_bytes(data)
    assert strip_video_metadata_file(path)
    after = path.read_bytes()
    assert len(after) == len(data) and [s for s in SECRETS if s in after] == []
    assert b"mvhd" in after and b"tkhd" in after and b"VIDEO" * 10 in after
    assert after.count(b"free") == 2


def test_heic_upload_becomes_a_clean_jpeg(make_app, monkeypatch):
    monkeypatch.setattr(file_service, "HEIF_AVAILABLE", True)  # le vrai décodeur est pillow-heif
    app = make_app(NSFW_AUTO_MODERATION=False)
    client = app.test_client()
    buf = io.BytesIO()
    Image.new("RGB", (60, 40), "red").save(buf, "JPEG", exif=exif())
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(buf.getvalue()), "photo.heic")},
                content_type="multipart/form-data")
    with app.app_context():
        (meta,) = json_services.load_db().values()
    assert meta["original_name"] == "photo.jpg" and meta["server_name"].endswith(".jpg")
    path = os.path.join(app.config["UPLOAD_FOLDER"], meta["server_name"])
    assert leaks(path) == []
    with Image.open(path) as im:
        assert im.format == "JPEG" and im.size == (40, 60)  # orientation appliquée
