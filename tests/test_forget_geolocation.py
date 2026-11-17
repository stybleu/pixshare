"""La base de géolocalisation (retirée) et les anciens pays/villes sont effacés au démarrage."""
import json
import os

from pixshare import create_app


def test_old_geolocation_is_erased_at_startup(tmp_path, monkeypatch):
    data = tmp_path / "disk"
    (data / "geoip").mkdir(parents=True)
    (data / "geoip" / "dbip-city-lite-2026-11.mmdb").write_bytes(b"x" * 100)
    (data / "visitor_stats.json").write_text(json.dumps({"days": {"2026-11-16": {
        "visitors": 1, "views": 2, "countries": {"FR": 1}, "cities": {"Chartres, FR": 1}, "devices": {"Mobile": 1}}}}))
    monkeypatch.setenv("PIXSHARE_DATA_DIR", str(data))
    create_app({"TESTING": True, "UPLOAD_FOLDER": str(tmp_path / "up")})
    assert not os.path.exists(data / "geoip")
    day = json.loads((data / "visitor_stats.json").read_text())["days"]["2026-11-16"]
    assert day == {"visitors": 1, "views": 2}
