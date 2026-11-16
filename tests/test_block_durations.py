"""Durées de blocage de 30 minutes à définitif, partout dans l'admin, modifiables après coup."""
from datetime import datetime, timezone

from conftest import csrf, login
from pixshare.services import json_services


def minutes_left(app, ip):
    with app.app_context():
        until = json_services.load_blocked_info()[ip]["until"]
    if not until:
        return None
    return (datetime.fromisoformat(until) - datetime.now(timezone.utc)).total_seconds() / 60


def test_every_duration_is_offered(make_app):
    app = make_app()
    page = login(app.test_client()).get("/admin/blocked-ips").get_data(as_text=True)
    for label in ("30 minutes", "1 heure", "6 heures", "24 heures", "7 jours", "30 jours", "Définitif"):
        assert label in page


def test_thirty_minutes_then_change_to_permanent(make_app):
    app = make_app()
    client = login(app.test_client())
    token = csrf(client, "/admin/blocked-ips")
    client.post("/admin/blocked-ips/add", data={"csrf_token": token, "ip": "198.51.100.7", "hours": "0.5"})
    assert 29 <= minutes_left(app, "198.51.100.7") <= 30
    assert "reste 30 min" in client.get("/admin/blocked-ips").get_data(as_text=True)
    client.post("/admin/blocked-ips/duration", data={"csrf_token": token, "ip": "198.51.100.7", "hours": "0"})
    assert minutes_left(app, "198.51.100.7") is None
    client.post("/admin/blocked-ips/duration", data={"csrf_token": token, "ip": "198.51.100.7", "hours": "6"})
    assert 359 <= minutes_left(app, "198.51.100.7") <= 360


def test_unknown_duration_falls_back_to_24h(make_app):
    app = make_app()
    client = login(app.test_client())
    client.post("/admin/blocked-ips/add", data={"csrf_token": csrf(client, "/admin/blocked-ips"), "ip": "198.51.100.8", "hours": "999"})
    assert 1439 <= minutes_left(app, "198.51.100.8") <= 1440


def test_block_from_messages_uses_chosen_duration(make_app):
    app = make_app()
    client = login(app.test_client())
    with app.app_context():
        json_services.save_contacts([{"id": "m1", "created_at": "2026-11-16T03:00:00", "type": "contact", "name": "x",
                                      "email": "", "subject": "s", "message": "spam", "file_url": "", "ip": "203.0.113.5",
                                      "status": "new"}])
    page = client.get("/admin/messages").get_data(as_text=True)
    assert 'name="hours"' in page
    client.post("/admin/messages/block-ip", data={"csrf_token": csrf(client, "/admin/messages"), "ip": "203.0.113.5", "hours": "1"})
    assert 59 <= minutes_left(app, "203.0.113.5") <= 60
