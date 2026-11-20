"""Pages d'erreur : lien expiré, page introuvable, et réponses courtes pour les images intégrées ailleurs."""


def test_expired_link_page(make_app):
    c = make_app().test_client()
    resp = c.get("/file/AbCdEf12345", headers={"Accept": "text/html", "Sec-Fetch-Dest": "document"})
    page = resp.get_data(as_text=True)
    assert resp.status_code == 404
    assert "plus disponible" in page and "Partager vos photos" in page
    assert "Attrape les photos" in page and 'content="noindex, nofollow"' in page


def test_raw_image_embedded_elsewhere_stays_short(make_app):
    c = make_app().test_client()
    for headers in ({"Accept": "image/avif,image/webp,*/*;q=0.8", "Sec-Fetch-Dest": "image"},
                    {"Accept": "image/avif,image/webp,*/*;q=0.8"}, {"Accept": "*/*"}):
        resp = c.get("/view/AbCdEf12345", headers=headers)
        # image affichée dans un forum : une vignette « Image indisponible » au lieu d'une image cassée
        assert resp.status_code == 404 and resp.mimetype == "image/png", headers
        assert resp.data[:8] == b"\x89PNG\r\n\x1a\n" and "noimageindex" in resp.headers["X-Robots-Tag"]
    resp = c.get("/view/AbCdEf12345", headers={"Accept": "application/json"})
    assert resp.status_code == 404 and resp.mimetype == "text/plain"
    resp = c.get("/view/AbCdEf12345", headers={"Accept": "text/html", "Sec-Fetch-Dest": "document"})
    assert resp.status_code == 404 and "plus disponible" in resp.get_data(as_text=True)
    resp = c.get("/download/AbCdEf12345", headers={"Accept": "text/html,*/*", "Sec-Fetch-Dest": "document"})
    assert "plus disponible" in resp.get_data(as_text=True)


def test_unknown_page(make_app):
    c = make_app().test_client()
    resp = c.get("/nimporte-quoi", headers={"Accept": "text/html"})
    page = resp.get_data(as_text=True)
    assert resp.status_code == 404 and "Oups, page introuvable" in page and "Attrape les photos" in page
    assert "plus disponible" not in page
    assert c.get("/static/rien.png").mimetype == "text/plain"


def test_other_errors_have_no_game(make_app):
    app = make_app()

    @app.route("/boom-test")
    def boom():
        from flask import abort
        abort(429)
    page = app.test_client().get("/boom-test", headers={"Accept": "text/html"}).get_data(as_text=True)
    assert "Trop de demandes" in page and "Attrape les photos" not in page


def test_deleted_album_page(make_app):
    resp = make_app().test_client().get("/album/inconnu123", headers={"Accept": "text/html", "Sec-Fetch-Dest": "document"})
    page = resp.get_data(as_text=True)
    assert resp.status_code == 404 and "album n" in page and "plus disponible" in page and "Attrape les photos" in page
