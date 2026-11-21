"""Alerte mail quand le disque se remplit."""
import pytest

from pixshare.services import disk_alert_service, mail_service, system_service


@pytest.fixture
def sent(monkeypatch):
    box = []
    monkeypatch.setattr(mail_service, "mail_configured", lambda: True)
    monkeypatch.setattr(mail_service, "send_mail_now", lambda subject, body, **kw: (box.append((subject, body)) or (True, "")))
    return box


def disk(monkeypatch, percent, persistent=True):
    monkeypatch.setattr(system_service, "get_storage_usage", lambda: {
        "ok": True, "persistent": persistent, "total_mb": 1000.0, "used_mb": percent * 10.0,
        "free_mb": 1000.0 - percent * 10.0, "percent": float(percent)})


def test_levels_and_reminders(make_app, monkeypatch, sent):
    app = make_app()
    disk(monkeypatch, 50)
    assert disk_alert_service.check_and_alert(app) == "ok" and not sent
    disk(monkeypatch, 82)
    assert disk_alert_service.check_and_alert(app) == "alerte 80 % envoyée"
    assert "82 %" in sent[-1][0] and "Render" in sent[-1][1]
    assert disk_alert_service.check_and_alert(app) == "déjà prévenu" and len(sent) == 1     # pas de mail toutes les 10 min
    disk(monkeypatch, 96)
    assert disk_alert_service.check_and_alert(app) == "alerte 95 % envoyée"                # palier suivant : tout de suite
    assert "refusés" in sent[-1][1]
    disk(monkeypatch, 40)
    assert disk_alert_service.check_and_alert(app) == "ok"
    disk(monkeypatch, 85)
    assert disk_alert_service.check_and_alert(app) == "déjà prévenu"   # moins de 24 h après le dernier mail (95 %)
    from datetime import timedelta
    from pixshare.services import time_service
    real = time_service.utcnow
    monkeypatch.setattr(disk_alert_service, "utcnow", lambda: real() + timedelta(hours=25))
    assert disk_alert_service.check_and_alert(app) == "alerte 80 % envoyée"                # rappel le lendemain


def test_nothing_without_persistent_disk(make_app, monkeypatch, sent):
    app = make_app()
    disk(monkeypatch, 99, persistent=False)
    assert disk_alert_service.check_and_alert(app) == "pas de disque persistant" and not sent


def test_triggered_after_a_page(make_app, monkeypatch):
    calls = []
    monkeypatch.setattr(disk_alert_service, "_last_check", None)
    monkeypatch.setattr(disk_alert_service, "check_later", lambda app: calls.append(1))
    app = make_app()
    app.test_client().get("/").close()
    app.test_client().get("/").close()
    assert calls == [1]
