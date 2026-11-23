"""QR code des images (et plein écran, comme pour les albums)."""
from test_accounts import records, upload


def test_file_qr_and_fullscreen(make_app):
    app = make_app()
    c = app.test_client()
    upload(c, "vacances.png")
    fid = next(iter(records(app)))
    page = c.get(f"/file/{fid}").get_data(as_text=True)
    assert f"/file/{fid}/qr.svg" in page and 'id="qrFull"' in page and "Afficher le QR code" in page
    svg = c.get(f"/file/{fid}/qr.svg")
    assert svg.status_code == 200 and svg.mimetype == "image/svg+xml" and b"<svg" in svg.data
    assert "noindex" in svg.headers["X-Robots-Tag"]
    png = c.get(f"/file/{fid}/qr.png")
    assert png.data.startswith(b"\x89PNG") and 'QR-vacances.png' in png.headers["Content-Disposition"]
    assert c.get("/file/inexistant/qr.svg").status_code == 404


def test_qr_points_to_share_page():
    from pixshare.services import qr_service
    assert qr_service.matrix("https://pixshare.fr/file/abc")   # encodage possible


def test_deleted_file_has_no_qr(make_app):
    app = make_app()
    c = app.test_client()
    upload(c, "a.png")
    fid = next(iter(records(app)))
    from conftest import csrf
    c.post(f"/delete/{fid}", data={"csrf_token": csrf(c)})
    assert c.get(f"/file/{fid}/qr.svg").status_code == 404
