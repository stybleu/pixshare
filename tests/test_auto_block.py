"""IP bloquées : motif, durée, expiration, et blocage automatique des récidivistes NudeNet."""
import io
from datetime import datetime, timedelta, timezone

import pytest

from conftest import csrf, login
from pixshare.services import json_services
from test_nsfw_moderation import GREEN, RED, image_bytes  # noqa: F401  (le faux NudeNet s'active tout seul)
from test_nsfw_moderation import fake_nudenet  # noqa: F401

VISITOR = {"REMOTE_ADDR": "203.0.113.9"}


def send(client, data, name="a.png"):
    resp = client.post("/", data={"csrf_token": csrf(client), "file": (io.BytesIO(data), name)},
                       content_type="multipart/form-data", environ_overrides=VISITOR)
    resp.close()  # lance l'analyse « après la réponse »
    return resp


def test_temporary_block_ends_by_itself(make_app):
    app = make_app()
    with app.app_context():
        assert json_services.block_ip("198.51.100.1", "test", hours=24)
        assert not json_services.block_ip("198.51.100.1", "encore")
        info = json_services.load_blocked_info()
        info["198.51.100.1"]["until"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        json_services.save_blocked_info(info)
        assert json_services.load_blocked() == []
        assert json_services.load_blocked_info() == {}


def test_manual_block_with_reason_and_duration(make_app):
    app = make_app()
    client = login(app.test_client())
    client.post("/admin/blocked-ips/add", data={"csrf_token": csrf(client, "/admin/blocked-ips"),
                                                "ip": "198.51.100.2", "reason": "spam", "hours": "168"})
    page = client.get("/admin/blocked-ips").get_data(as_text=True)
    assert "198.51.100.2" in page and "spam" in page and "UTC" in page
    client.post("/admin/blocked-ips/add", data={"csrf_token": csrf(client, "/admin/blocked-ips"),
                                                "ip": "198.51.100.3", "hours": "0"})
    with app.app_context():
        assert json_services.load_blocked_info()["198.51.100.3"]["until"] == ""
    client.post("/admin/blocked-ips/unblock", data={"csrf_token": csrf(client, "/admin/blocked-ips"), "ip": "198.51.100.2"})
    with app.app_context():
        assert "198.51.100.2" not in json_services.load_blocked_info()


def test_three_rejected_images_block_the_ip_for_a_while(make_app):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    client = app.test_client()
    send(client, image_bytes("PNG", [GREEN]))  # image saine : ne compte pas
    for _ in range(3):
        send(client, image_bytes("PNG", [RED]))
    with app.app_context():
        assert json_services.load_blocked() == ["203.0.113.9"]
        entry = json_services.load_blocked_info()["203.0.113.9"]
    assert "Auto" in entry["reason"] and "1er blocage" in entry["reason"] and entry["until"]
    assert client.get("/", environ_overrides=VISITOR).status_code == 302  # renvoyé ailleurs


def test_two_rejections_are_not_enough(make_app):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    client = app.test_client()
    for _ in range(2):
        send(client, image_bytes("PNG", [RED]))
    with app.app_context():
        assert json_services.load_blocked() == []


def test_admin_testing_nudenet_is_never_blocked(make_app):
    app = make_app(MODERATION_PENDING_IMAGES=True)
    client = login(app.test_client())
    for _ in range(3):
        send(client, image_bytes("PNG", [RED]))
    with app.app_context():
        assert json_services.load_blocked() == []


@pytest.mark.parametrize("value", ["0"])
def test_auto_block_can_be_disabled(make_app, monkeypatch, value):
    monkeypatch.setenv("AUTO_BLOCK_REJECTIONS", value)
    app = make_app(MODERATION_PENDING_IMAGES=True)
    client = app.test_client()
    for _ in range(3):
        send(client, image_bytes("PNG", [RED]))
    with app.app_context():
        assert json_services.load_blocked() == []
