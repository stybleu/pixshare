def test_cgu_describes_current_moderation(make_app):
    page = make_app().test_client().get("/cgu")
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    assert html.count("<h1") == 1
    for text in ("NudeNet", "Turnstile", "empreinte numérique", "24 heures, puis 7 jours, puis 30 jours",
                 "Réexamen humain", "formulaire de contact", "MP4 et MOV", "même entre adultes consentants, avec ou sans compte", "7. Comptes"):
        assert text in html, text
    assert "conservés sans expiration" not in html
    assert "aucun service tiers" not in html
