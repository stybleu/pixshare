"""Sons (MP3, OGG, WAV…) : réservés aux membres, écoutables depuis le lien."""
import io
import struct

from conftest import csrf
from test_accounts import mails, member, records  # noqa: F401
from test_albums import create


def wav_bytes():
    rate, n = 8000, 800
    data = b"\x00\x00" * n
    return (b"RIFF" + struct.pack("<I", 36 + len(data)) + b"WAVEfmt " + struct.pack("<IHHIIHH", 16, 1, 1, rate, rate * 2, 2, 16)
            + b"data" + struct.pack("<I", len(data)) + data)


def send(client, name, data):
    resp = client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(data), name)}, content_type="multipart/form-data")
    resp.close()
    return resp


def test_guest_is_invited_to_create_an_account(make_app):
    app = make_app()
    c = app.test_client()
    send(c, "chanson.mp3", b"ID3" + b"\x00" * 200)
    assert records(app) == {}
    page = c.get("/").get_data(as_text=True)
    assert "réservés aux comptes gratuits" in page
    assert 'accept="image/*,video/*"' in page and "Choisir des photos ou des vidéos" in page


def test_member_can_share_a_sound(make_app, mails):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    c = member(app.test_client(), mails)
    home = c.get("/").get_data(as_text=True)
    assert 'accept="image/*,video/*,audio/*"' in home and "Choisir des photos, vidéos ou sons" in home
    send(c, "memo.wav", wav_bytes())
    (file_id, meta), = records(app).items()
    assert meta["status"] == "active"                       # pas d'analyse d'image pour un son
    page = c.get(f"/file/{file_id}").get_data(as_text=True)
    assert "<audio controls" in page and "Écouter dans un nouvel onglet" in page
    raw = app.test_client().get(f"/view/{file_id}")
    assert raw.status_code == 200 and raw.mimetype == "audio/wav"


def test_unplayable_or_album_audio_refused(make_app, mails):
    app = make_app()
    c = member(app.test_client(), mails)
    send(c, "vieux.wma", b"0&\xb2u" + b"\x00" * 100)
    assert records(app) == {}
    album_id = create(c)
    resp = c.post(f"/album/{album_id}/ajouter", data={"csrf_token": csrf(c, f"/album/{album_id}"),
                  "files": [(io.BytesIO(wav_bytes()), "son.wav")]}, content_type="multipart/form-data",
                  headers={"X-Requested-With": "pixshare"})
    resp.close()
    assert records(app) == {}


def test_texts_mention_sounds_and_rights(make_app):
    c = make_app().test_client()
    faq = c.get("/faq").get_data(as_text=True)
    assert "MP3, M4A, AAC, OGG, Opus, WAV et FLAC" in faq and "pas de musique copiée" in faq
    cgu = c.get("/cgu").get_data(as_text=True)
    assert "musique, des films ou des livres copiés" in cgu and "sons (MP3, OGG, WAV…)" in cgu
