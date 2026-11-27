"""Compteurs d'accès par photo : plus d'adresse IP de visiteur, nettoyage de l'existant, effacés avec la photo."""
import io
import json

from PIL import Image

from conftest import csrf
from pixshare.services import json_services, usage_tracking_service as usage


def png(color=(20, 160, 40)):
    buf = io.BytesIO()
    Image.new("RGB", (40, 40), color).save(buf, "PNG")
    return buf.getvalue()


def send(client):
    client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(png()), "a.png")},
                content_type="multipart/form-data").close()


def file_ids(app):
    with app.app_context():
        return list(json_services.load_db())


def test_visits_are_counted_without_the_visitor_ip(make_app):
    app = make_app()
    owner = app.test_client()
    send(owner)
    file_id = file_ids(app)[0]
    visitor = app.test_client()
    assert visitor.get(f"/image/{file_id}", environ_base={"REMOTE_ADDR": "203.0.113.7"}).status_code == 200
    with app.app_context():
        events = json_services.load_usage()[file_id]["events"]
    assert events and all("ip" not in e for e in events)
    with app.app_context():
        assert "203.0.113.7" not in json.dumps(json_services.load_usage())


def test_old_ips_and_orphans_are_scrubbed(make_app):
    app = make_app()
    with app.app_context():
        json_services.save_usage({
            "vivante": {"events": [{"at": "2026-11-01T10:00:00", "access_type": "viewer", "ip": "203.0.113.9"}]},
            "disparue": {"events": [{"at": "2026-11-01T10:00:00", "access_type": "viewer", "ip": "203.0.113.10"}]},
        })
        assert usage.scrub_ips({"vivante"}) == 2
        data = json_services.load_usage()
        assert list(data) == ["vivante"] and "ip" not in data["vivante"]["events"][0]
        assert usage.scrub_ips({"vivante"}) == 0  # rien à refaire


def test_usage_is_forgotten_with_the_file(make_app):
    app = make_app()
    with app.app_context():
        json_services.save_usage({"a": {"events": []}, "b": {"events": []}})
        usage.forget_files(["a"])
        assert list(json_services.load_usage()) == ["b"]


def test_legal_notice_matches_what_is_kept(make_app):
    html = make_app().test_client().get("/mentions-legales").get_data(as_text=True)
    assert "effacées peu après" not in html
    assert "reste rattachée à la photo" in html and "Compteurs d’accès de chaque photo" in html
    assert "historique des blocages" in html


def test_views_are_forgotten_with_the_file(make_app):
    from pixshare.services.file_service import forget_views
    app = make_app()
    with app.app_context():
        json_services.save_views({"a": ["tok1"], "b": ["e:hash"]})
        assert forget_views(["a", "inconnue"]) == 1
        assert json_services.load_views() == {"b": ["e:hash"]}
        assert forget_views([]) == 0


def test_legal_notice_gives_durations_and_conditions(make_app):
    html = make_app().test_client().get("/mentions-legales").get_data(as_text=True)
    for text in ("à deux conditions", "article 8 du DSA", "particulier agissant à titre non professionnel",
                 "puis 7 jours et 30 jours en cas de récidive", "sans limite de durée", "Comptage des vues",
                 "article 17 du DSA", "certifiées au cadre"):
        assert text in html, text
