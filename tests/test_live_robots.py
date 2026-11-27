"""Page « En direct » : liste des robots (Google, IA, scripts…), sans stockage durable."""
import json

import pytest

from conftest import login
from pixshare.services import live_service

CHROME = "Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36"
GOOGLE = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


@pytest.fixture(autouse=True)
def fresh_live_file(tmp_path, monkeypatch):
    monkeypatch.setattr(live_service, "_LIVE_FILE", str(tmp_path / "live.json"))
    live_service._last_write.clear()
    live_service._pending.clear()


def data(admin):
    return json.loads(admin.get("/admin/live.json").get_data(as_text=True))


def hit(app, ua, ip, path="/"):
    app.test_client().get(path, headers={"User-Agent": ua}, environ_overrides={"REMOTE_ADDR": ip})


def test_robots_are_listed_by_family_and_not_as_visitors(make_app):
    app = make_app()
    hit(app, GOOGLE, "66.249.66.1")
    hit(app, "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)", "20.171.0.5", "/cgu")
    hit(app, "AhrefsBot/7.0 (+http://ahrefs.com/robot/)", "54.36.148.9", "/contact")
    hit(app, "python-requests/2.31", "198.51.100.77", "/robots.txt")
    hit(app, CHROME, "86.218.162.249", "/contact")
    d = data(login(app.test_client()))
    names = {r["name"]: r for r in d["robots"]}
    assert {"Google", "GPTBot", "AhrefsBot", "Python"} <= set(names)
    assert names["Google"]["legit"] is True and names["GPTBot"]["legit"] is False
    assert names["Google"]["masked"] == "66.249.x.x" and names["GPTBot"]["path"] == "/cgu"
    assert d["robots_count"] == len(d["robots"]) == 4
    assert all(v["ip"] != "66.249.66.1" for v in d["visitors"]), d["visitors"]
    assert {f["name"] for f in d["robot_families"]} >= {"Google", "GPTBot"}


def test_robot_without_user_agent_and_internal_pages_are_handled(make_app):
    app = make_app()
    hit(app, "", "203.0.113.4", "/mentions-legales")
    hit(app, GOOGLE, "66.249.66.2", "/healthz")           # test de santé : pas un robot à suivre
    hit(app, GOOGLE, "66.249.66.3", "/static/logo.png")
    d = data(login(app.test_client()))
    assert [r["name"] for r in d["robots"]] == ["Sans identifiant"]


def test_requests_of_a_busy_robot_are_counted_together(make_app):
    app = make_app()
    for _ in range(3):
        hit(app, GOOGLE, "66.249.66.1")
    live_service._last_write.clear()  # une seconde plus tard
    hit(app, GOOGLE, "66.249.66.1")
    robot = data(login(app.test_client()))["robots"][0]
    assert robot["hits"] == 4


def test_admin_is_not_listed_and_robots_are_forgotten_after_5_minutes(make_app, monkeypatch):
    app = make_app()
    admin = login(app.test_client())
    admin.get("/contact", headers={"User-Agent": GOOGLE})  # session admin : jamais listée
    assert data(admin)["robots"] == []
    hit(app, GOOGLE, "66.249.66.1")
    assert len(data(admin)["robots"]) == 1
    real_time = live_service.time.time
    monkeypatch.setattr(live_service.time, "time", lambda: real_time() + 301)
    assert data(admin)["robots"] == []


def test_robots_page_section_is_admin_only(make_app):
    app = make_app()
    assert app.test_client().get("/admin/live.json").status_code in (302, 401, 403)
    page = login(app.test_client()).get("/admin/live").get_data(as_text=True)
    assert 'id="botRows"' in page and "Robots" in page
