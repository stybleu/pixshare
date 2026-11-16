def test_healthz_is_ok_and_light(make_app):
    app = make_app()
    resp = app.test_client().get("/healthz")
    assert resp.status_code == 200 and resp.get_data(as_text=True) == "ok"
    assert resp.headers["Cache-Control"] == "no-store"


def test_healthz_reports_broken_storage(make_app):
    app = make_app()
    app.config["UPLOAD_FOLDER"] = "/dossier/qui/n/existe/pas"
    assert app.test_client().get("/healthz").status_code == 503
