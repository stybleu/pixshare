"""Base SQLite : migration des anciens JSON, écritures sans perte, et surtout sécurité (injections SQL)."""
import io
import json
import os
import re
import sqlite3
import stat

from PIL import Image

from conftest import csrf, login
from pixshare.services import json_services, sqlite_store

# Chaînes d'attaque classiques : si une seule était collée dans une requête, la base serait cassée ou vidée.
INJECTIONS = [
    "x'; DROP TABLE files; --",
    "' OR '1'='1",
    "1; DELETE FROM documents",
    "\"); DROP TABLE documents; --",
    "admin'--",
    "%' UNION SELECT name, data FROM documents --",
    "\x00",
]


def _png(color=(10, 120, 200)):
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), color).save(buf, "PNG")
    return buf.getvalue()


def _upload(client, name="a.png", color=(10, 120, 200)):
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(_png(color)), name)},
                content_type="multipart/form-data").close()


def _tables(path):
    con = sqlite3.connect(path)
    try:
        return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        con.close()


def test_no_sql_built_from_strings():
    """Aucune requête n'est fabriquée avec f-string, % ou + : uniquement des paramètres « ? »."""
    source = open(sqlite_store.__file__, encoding="utf-8").read()
    calls = re.findall(r"\.(?:execute|executemany|executescript)\(\s*(f?[\"'][^\n]*)", source)
    assert calls
    for call in calls:
        assert not call.startswith("f"), call            # pas de f-string
        assert ".format(" not in call and "%" not in call.split(",")[0], call
    for line in source.splitlines():
        if "execute" in line and "(" in line:
            assert " + " not in line.split("execute", 1)[1].split(",")[0], line


def test_injection_attempts_are_stored_as_plain_data(make_app):
    app = make_app()
    with app.app_context():
        data_dir = json_services._get_data_dir()
        for i, evil in enumerate(INJECTIONS):
            json_services.save_json(f"doc{i}.json", {"valeur": evil})
            db = json_services.load_db()
            db[evil] = {"original_name": evil, "status": "active"}
            json_services.save_db(db)
        db = json_services.load_db()
        for evil in INJECTIONS:
            assert db[evil]["original_name"] == evil          # rangé tel quel, comme du texte
        for i, evil in enumerate(INJECTIONS):
            assert json_services.load_json(f"doc{i}.json", {})["valeur"] == evil
        assert {"files", "documents"} <= _tables(sqlite_store.db_path(data_dir))  # rien n'a été supprimé


def test_injection_attempts_through_the_site(make_app):
    app = make_app()
    client = app.test_client()
    _upload(client)
    with app.app_context():
        before = dict(json_services.load_db())
    for evil in INJECTIONS[:-1]:
        for path in (f"/view/{evil}", f"/image/{evil}", f"/file/{evil}", f"/mes-images/{evil}/apercu"):
            assert client.get(path).status_code in (200, 302, 400, 403, 404), path
        client.post(f"/delete/{evil}", data={"csrf_token": csrf(client)})
        client.post("/connexion", data={"csrf_token": csrf(client, "/connexion"), "email": evil, "password": evil})
        client.post("/report/" + evil, data={"csrf_token": csrf(client), "reason": evil})
    admin = login(app.test_client())
    for evil in INJECTIONS[:-1]:
        admin.get(f"/admin/disque?chemin={evil}")
        admin.post("/admin/delete", data={"csrf_token": csrf(admin, "/admin"), "file_id": evil, "delete_reason": evil})
    with app.app_context():
        after = json_services.load_db()
        data_dir = json_services._get_data_dir()
    assert set(before) <= set(after)                       # aucune fiche perdue
    assert {"files", "documents"} <= _tables(sqlite_store.db_path(data_dir))


def test_database_file_is_private_and_not_served(make_app):
    app = make_app()
    client = app.test_client()
    _upload(client)
    with app.app_context():
        path = sqlite_store.db_path(json_services._get_data_dir())
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600      # lisible par le serveur seulement
    for url in ("/pixshare.db", "/data/pixshare.db", "/static/../data/pixshare.db", "/static/pixshare.db",
                "/view/../pixshare.db", "/file/pixshare.db"):
        resp = client.get(url)
        assert resp.status_code in (301, 302, 308, 400, 404), url
        assert b"SQLite format" not in resp.data, url


def test_legacy_json_files_are_imported_once(make_app, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "files.json").write_text(json.dumps({"abc": {"original_name": "vieux.png", "status": "active"}}))
    (data / "accounts.json").write_text(json.dumps({"accounts": {"x1": {"email": "a@b.fr"}}}))
    app = make_app()
    with app.app_context():
        assert json_services.load_db()["abc"]["original_name"] == "vieux.png"
        assert json_services.load_json("accounts.json", {})["accounts"]["x1"]["email"] == "a@b.fr"
    assert not (data / "files.json").exists() and (data / "files.json.migre").exists()  # copie de secours gardée
    assert (data / "accounts.json.migre").exists()
    with app.app_context():  # 2e lecture : rien n'est réimporté ni écrasé
        db = json_services.load_db()
        db["abc"]["status"] = "deleted"
        json_services.save_db(db)
        assert json_services.load_db()["abc"]["status"] == "deleted"


def test_two_workers_editing_different_files_lose_nothing(make_app):
    app = make_app()
    with app.app_context():
        json_services.save_db({"a": {"views": 0}, "b": {"views": 0}})
        worker1 = json_services.load_db()
        worker2 = json_services.load_db()
        worker1["a"]["views"] = 5
        json_services.save_db(worker1)
        worker2["b"]["views"] = 7   # worker2 a lu avant l'écriture de worker1
        json_services.save_db(worker2)
        db = json_services.load_db()
    assert db["a"]["views"] == 5 and db["b"]["views"] == 7  # avec les JSON, le 5 était perdu


def test_failed_write_changes_nothing(make_app):
    app = make_app()
    with app.app_context():
        json_services.save_db({"a": {"n": 1}})
        db = json_services.load_db()
        db["a"]["n"] = 2
        db["b"] = {"bad": {1, 2}}  # un ensemble Python ne peut pas être enregistré : erreur au milieu
        try:
            json_services.save_db(db)
        except TypeError:
            pass
        assert json_services.load_db() == {"a": {"n": 1}}  # transaction annulée en entier


def test_admin_backup_and_status(make_app):
    app = make_app()
    client = app.test_client()
    _upload(client)
    assert app.test_client().get("/admin/base/sauvegarde").status_code in (302, 401, 403)
    admin = login(app.test_client())
    page = admin.get("/admin/system").get_data(as_text=True)
    assert "Base de données (SQLite)" in page and "Intacte" in page
    resp = admin.get("/admin/base/sauvegarde")
    assert resp.status_code == 200 and resp.data.startswith(b"SQLite format 3")
    assert "attachment" in resp.headers["Content-Disposition"]
    # le fichier brut de la base ne s'ouvre pas depuis l'explorateur (copie incohérente) : renvoi vers la sauvegarde
    raw = admin.get("/admin/disque/ouvrir?chemin=pixshare.db")
    assert raw.status_code == 302 and "/admin/base/sauvegarde" in raw.headers["Location"]
    listing = admin.get("/admin/disque").get_data(as_text=True)
    assert "Base de données du site" in listing


def test_json_fallback_still_works(make_app, monkeypatch):
    monkeypatch.setenv("PIXSHARE_STORAGE", "json")
    app = make_app()
    with app.app_context():
        json_services.save_db({"a": {"n": 1}})
        assert json_services.load_db() == {"a": {"n": 1}}
        assert os.path.exists(os.path.join(json_services._get_data_dir(), "files.json"))
