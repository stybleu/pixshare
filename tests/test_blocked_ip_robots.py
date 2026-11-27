"""Une IP bloquée depuis l'admin est refusée partout quand c'est un robot ; les visiteurs normaux gardent le comportement habituel."""
from conftest import csrf, login

CHROME = "Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36"
GPT = "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"
IP = "198.51.100.44"


def get(app, path, ua, ip=IP):
    return app.test_client().get(path, headers={"User-Agent": ua}, environ_overrides={"REMOTE_ADDR": ip})


def block(app, ip=IP):
    admin = login(app.test_client())
    admin.post("/admin/blocked-ips/add", data={"csrf_token": csrf(admin, "/admin/live"), "ip": ip,
                                               "reason": "Depuis le direct", "hours": "24"})
    return admin


def test_blocked_robot_ip_is_refused_everywhere_but_robots_txt(make_app):
    app = make_app()
    assert get(app, "/cgu", GPT).status_code == 200
    block(app)
    assert get(app, "/cgu", GPT).status_code == 403
    assert get(app, "/faq", GPT).status_code == 403
    assert get(app, "/file/inconnu", GPT).status_code == 403
    assert get(app, "/robots.txt", GPT).status_code == 200


def test_robot_without_user_agent_is_refused_too(make_app):
    app = make_app()
    block(app)
    assert get(app, "/cgu", "").status_code == 403


def test_other_ips_and_normal_visitors_are_not_affected(make_app):
    app = make_app()
    block(app)
    assert get(app, "/cgu", GPT, ip="198.51.100.45").status_code == 200   # autre IP
    assert get(app, "/cgu", CHROME).status_code == 200                    # même IP, vrai navigateur : comme avant


def test_admin_is_never_refused(make_app):
    app = make_app()
    admin = block(app)
    assert admin.get("/cgu", headers={"User-Agent": GPT}, environ_overrides={"REMOTE_ADDR": IP}).status_code == 200
