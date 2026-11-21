"""Sauvegarde de secours sur Cloudflare R2 : base + fichiers, suppressions suivies, restauration."""
import gzip
import hashlib
import io
import os
from datetime import datetime, timezone

import pytest
from PIL import Image

from conftest import csrf, login
from pixshare.services import backup_service
from pixshare.services.json_services import load_db, save_db

R2_ENV = {"R2_ACCOUNT_ID": "abc123", "R2_ACCESS_KEY_ID": "id", "R2_SECRET_ACCESS_KEY": "secret", "R2_BUCKET": "pixshare"}


class FakeR2:
    """R2 en mémoire : même comportement (ETag = MD5 du contenu)."""

    def __init__(self):
        self.objects = {}
        self.puts = []

    def put_file(self, key, path):
        with open(path, "rb") as f:
            self.objects[key] = f.read()
        self.puts.append(key)

    def get_to_file(self, key, path):
        with open(path, "wb") as f:
            f.write(self.objects[key])

    def delete(self, key):
        self.objects.pop(key, None)

    def list(self, prefix):
        return {k: {"size": len(v), "etag": hashlib.md5(v).hexdigest()}
                for k, v in self.objects.items() if k.startswith(prefix)}


@pytest.fixture
def r2(monkeypatch):
    for k, v in R2_ENV.items():
        monkeypatch.setenv(k, v)
    fake = FakeR2()
    monkeypatch.setattr(backup_service, "get_client", lambda: fake)
    monkeypatch.setattr(backup_service, "maybe_nightly_backup", lambda app: None)  # pas de fil en arrière-plan ici
    return fake


def png(color):
    buf = io.BytesIO()
    Image.new("RGB", (40, 40), color).save(buf, "PNG")
    return buf.getvalue()


def upload(client, name, color):
    resp = client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(png(color)), name)},
                       content_type="multipart/form-data")
    resp.close()


def ids_by_name(app):
    with app.app_context():
        return {m["original_name"]: k for k, m in load_db().items()}


def test_signature_matches_aws_reference_examples():
    """Exemples officiels de la documentation AWS (Signature v4, S3)."""
    empty = backup_service.EMPTY_SHA256
    keys = ("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1", "20130524T000000Z")
    auth = backup_service.sign("GET", "examplebucket.s3.amazonaws.com", "/test.txt", {},
                               {"range": "bytes=0-9", "x-amz-content-sha256": empty, "x-amz-date": keys[3]},
                               empty, *keys)
    assert auth.endswith("Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
    auth = backup_service.sign("GET", "examplebucket.s3.amazonaws.com", "/", {"max-keys": "2", "prefix": "J"},
                               {"x-amz-content-sha256": empty, "x-amz-date": keys[3]}, empty, *keys)
    assert auth.endswith("Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")


def test_not_configured_does_nothing(make_app, monkeypatch):
    for k in R2_ENV:
        monkeypatch.delenv(k, raising=False)
    app = make_app()
    with app.app_context():
        assert not backup_service.is_configured() and not backup_service.backup_due()
    assert not backup_service.start_backup(app)


def test_backup_sends_only_changes_and_follows_deletions(make_app, r2):
    app = make_app()
    c = app.test_client()
    upload(c, "chat.png", (200, 10, 10))
    upload(c, "chien.png", (10, 200, 10))
    ids = ids_by_name(app)
    with app.test_request_context():
        first = backup_service.run_backup(r2)
    assert first["files"] == 2 and first["sent"] == 2
    db_copies = [k for k in r2.objects if k.startswith("base/")]
    assert len(db_copies) == 1
    with gzip.open(io.BytesIO(r2.objects[db_copies[0]])) as g:
        assert g.read(16) == b"SQLite format 3\x00"   # une vraie base, lisible
    files = sorted(k for k in r2.objects if k.startswith("fichiers/"))
    assert len(files) == 2 and all(k.endswith(".png") for k in files)

    with app.test_request_context():
        again = backup_service.run_backup(r2)
    assert again["sent"] == 0 and again["removed"] == 0   # rien n'a changé : rien ne repart

    from pixshare.services.file_service import delete_by_id
    with app.test_request_context():
        delete_by_id(ids["chat.png"], reason="non_respect_cgu")   # retirée par la modération
        third = backup_service.run_backup(r2)
    assert third["removed"] == 1
    assert not any(ids["chat.png"] in k for k in r2.objects if k.startswith("fichiers/"))
    with app.app_context():
        state = backup_service.load_state()
    assert state["last_success"] and not state["last_error"]


def test_replaced_file_is_sent_again(make_app, r2):
    app = make_app()
    c = app.test_client()
    upload(c, "a.png", (1, 2, 3))
    file_id = next(iter(ids_by_name(app).values()))
    with app.test_request_context():
        backup_service.run_backup(r2)
        path = os.path.join(app.config["UPLOAD_FOLDER"], load_db()[file_id]["server_name"])
    with open(path, "wb") as f:
        f.write(png((250, 250, 0)))
    os.utime(path, (1, 1))
    with app.test_request_context():
        assert backup_service.run_backup(r2)["sent"] == 1


def test_only_seven_database_copies_are_kept(make_app, r2):
    app = make_app()
    for day in range(1, 10):
        r2.objects[f"base/pixshare-2026-11-0{day}-0300.db.gz"] = b"x"
    with app.test_request_context():
        backup_service.run_backup(r2)
    copies = sorted(k for k in r2.objects if k.startswith("base/"))
    assert len(copies) == 7 and "base/pixshare-2026-11-01-0300.db.gz" not in copies


def test_restore_brings_back_database_and_files(make_app, r2):
    app = make_app()
    c = app.test_client()
    upload(c, "souvenir.png", (30, 60, 90))
    file_id = next(iter(ids_by_name(app).values()))
    with app.test_request_context():
        backup_service.run_backup(r2)
        name = load_db()[file_id]["server_name"]
        os.remove(os.path.join(app.config["UPLOAD_FOLDER"], name))   # panne : le fichier et la fiche disparaissent
        db = load_db()
        del db[file_id]
        save_db(db)
        assert file_id not in load_db()
        result = backup_service.restore(r2)
        assert result["files"] == 1
        assert load_db()[file_id]["original_name"] == "souvenir.png"
    assert os.path.isfile(os.path.join(app.config["UPLOAD_FOLDER"], name))
    assert os.path.isfile(os.path.join(os.environ["PIXSHARE_DATA_DIR"], "pixshare-avant-restauration.db"))
    assert c.get(f"/view/{file_id}?raw=1").status_code == 200


def test_restore_refuses_damaged_copy(make_app, r2):
    app = make_app()
    upload(app.test_client(), "x.png", (5, 5, 5))
    r2.objects["base/pixshare-2099-01-01-0300.db.gz"] = gzip.compress(b"pas une base du tout" * 50)
    with app.test_request_context():
        before = dict(load_db())
        with pytest.raises(backup_service.BackupError):
            backup_service.restore(r2)
        assert load_db() == before   # rien n'a été touché


def test_backup_due_once_per_night(make_app, r2):
    app = make_app()
    with app.app_context():
        assert backup_service.backup_due()            # jamais faite : tout de suite
        backup_service._save_state(last_attempt="2026-11-20T02:30:00")   # 3 h 30 à Paris
        assert not backup_service.backup_due(datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc))
        assert not backup_service.backup_due(datetime(2026, 11, 20, 22, 0, tzinfo=timezone.utc))  # 23 h : pas le soir même
        assert not backup_service.backup_due(datetime(2026, 11, 21, 1, 0, tzinfo=timezone.utc))   # 2 h à Paris
        assert backup_service.backup_due(datetime(2026, 11, 21, 2, 5, tzinfo=timezone.utc))       # 3 h 05
        # sauvegarde lancée à la main à 15 h : celle de la nuit suivante a quand même lieu
        backup_service._save_state(last_attempt="2026-11-21T14:00:00")
        assert not backup_service.backup_due(datetime(2026, 11, 21, 20, 0, tzinfo=timezone.utc))
        assert backup_service.backup_due(datetime(2026, 11, 22, 2, 1, tzinfo=timezone.utc))
        # heure d'été : 3 h à Paris = 1 h UTC
        backup_service._save_state(last_attempt="2026-07-01T02:00:00")
        assert not backup_service.backup_due(datetime(2026, 7, 2, 0, 30, tzinfo=timezone.utc))
        assert backup_service.backup_due(datetime(2026, 7, 2, 1, 5, tzinfo=timezone.utc))


def test_admin_card_and_restore_needs_confirmation(make_app, r2, monkeypatch):
    app = make_app()
    started = []
    monkeypatch.setattr(backup_service, "start_restore", lambda a, k=None: started.append(1) or True)
    monkeypatch.setattr(backup_service, "start_backup", lambda a, manual=False: started.append(2) or True)
    admin = login(app.test_client())
    page = admin.get("/admin/system").get_data(as_text=True)
    assert "Sauvegarde de secours (Cloudflare R2)" in page and "Sauvegarder maintenant" in page
    assert "secret" not in page.replace("R2_SECRET_ACCESS_KEY", "")  # la clé n'est jamais affichée
    admin.post("/admin/sauvegarde/restaurer", data={"csrf_token": csrf(admin, "/admin/system"), "confirm": "oui"})
    assert started == []
    admin.post("/admin/sauvegarde/restaurer", data={"csrf_token": csrf(admin, "/admin/system"), "confirm": "restaurer"})
    admin.post("/admin/sauvegarde/lancer", data={"csrf_token": csrf(admin, "/admin/system")})
    assert started == [1, 2]
    guest = app.test_client()
    resp = guest.post("/admin/sauvegarde/lancer", data={"csrf_token": csrf(guest)})
    assert resp.status_code in (302, 403) and started == [1, 2]


def test_legal_notice_mentions_backup_only_when_on(make_app, r2, monkeypatch):
    app = make_app()
    assert "Cloudflare R2" in app.test_client().get("/mentions-legales").get_data(as_text=True)
    monkeypatch.delenv("R2_BUCKET")
    assert "Cloudflare R2" not in app.test_client().get("/mentions-legales").get_data(as_text=True)


def test_env_check_warns_on_partial_r2(make_app, monkeypatch):
    from pixshare.services.env_check_service import check
    monkeypatch.setenv("R2_BUCKET", "pixshare")
    for k in ("R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY"):
        monkeypatch.delenv(k, raising=False)
    app = make_app()
    with app.app_context():
        assert any("R2" in msg for _lvl, msg in check()["problems"])


def test_real_thread_runs_and_records_error(make_app, monkeypatch):
    """Le vrai fil : sans réseau, l'échec est noté dans l'état (affiché dans l'admin), sans planter le site."""
    for k, v in R2_ENV.items():
        monkeypatch.setenv(k, v)

    def boom(*a, **k):
        raise backup_service.BackupError("R2 injoignable : test")
    monkeypatch.setattr(backup_service.R2Client, "_request", boom)
    app = make_app()
    backup_service._run_logged(app)
    with app.app_context():
        state = backup_service.load_state()
    assert "injoignable" in state["last_error"] and not state["running_since"] and state["last_attempt"]


def test_first_request_after_setup_starts_backup(make_app, monkeypatch):
    for k, v in R2_ENV.items():
        monkeypatch.setenv(k, v)
    started = []
    monkeypatch.setattr(backup_service, "start_backup", lambda app, manual=False: started.append(1) or True)
    monkeypatch.setattr(backup_service, "_last_check", None)
    app = make_app()
    app.test_client().get("/").close()
    assert started == [1]
    app.test_client().get("/").close()
    assert started == [1]   # pas plus d'une vérification toutes les 10 minutes
    monkeypatch.setattr(backup_service, "_last_check", None)
    with app.app_context():
        backup_service._save_state(last_attempt=backup_service.utcnow().isoformat(timespec="seconds"))
    app.test_client().get("/").close()
    assert started == [1]   # déjà faite cette nuit : pas de deuxième


def test_stale_running_flag_is_ignored(make_app, r2):
    app = make_app()
    with app.app_context():
        backup_service._save_state(running_since="2026-01-01T03:00:00")
        assert backup_service.load_state()["running_since"] == ""


def test_r2_client_requests(monkeypatch, tmp_path):
    """Le vrai client : adresse, signature, envoi du fichier en flux, lecture de la liste (avec suite)."""
    seen = []
    pages = [
        b'<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        b'<Contents><Key>fichiers/a.png</Key><Size>3</Size><ETag>"abc"</ETag></Contents>'
        b'<IsTruncated>true</IsTruncated><NextContinuationToken>t2</NextContinuationToken></ListBucketResult>',
        b'<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        b'<Contents><Key>fichiers/b c.png</Key><Size>5</Size><ETag>"def"</ETag></Contents>'
        b'<IsTruncated>false</IsTruncated></ListBucketResult>',
    ]

    class Resp:
        def __init__(self, data): self.data = data
        def read(self): return self.data
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=0):
        body = req.data.read() if hasattr(req.data, "read") else req.data
        seen.append((req.get_method(), req.full_url, dict(req.header_items()), body))
        return Resp(pages.pop(0) if req.get_method() == "GET" else b"")

    monkeypatch.setattr(backup_service.urllib.request, "urlopen", fake_urlopen)
    client = backup_service.R2Client({"account": "acc", "key": "id", "secret": "s", "bucket": "pixshare"})
    f = tmp_path / "x.bin"
    f.write_bytes(b"hello")
    client.put_file("fichiers/x.bin", str(f))
    method, url, headers, body = seen[0]
    assert method == "PUT" and url == "https://acc.r2.cloudflarestorage.com/pixshare/fichiers/x.bin" and body == b"hello"
    assert headers["X-amz-content-sha256"] == hashlib.sha256(b"hello").hexdigest()
    assert headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=id/") and "/auto/s3/aws4_request" in headers["Authorization"]
    listing = client.list("fichiers/")
    assert listing == {"fichiers/a.png": {"size": 3, "etag": "abc"}, "fichiers/b c.png": {"size": 5, "etag": "def"}}
    assert "continuation-token=t2" in seen[2][1] and "list-type=2" in seen[1][1]
