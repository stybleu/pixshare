"""Mentions légales : région d'hébergement (Francfort, UE) et garanties pour les prestataires américains."""


def test_legal_notice_names_the_hosting_region(make_app):
    html = make_app().test_client().get("/mentions-legales").get_data(as_text=True)
    assert "Francfort-sur-le-Main (Allemagne)" in html
    assert "Data Privacy Framework" in html and "clauses contractuelles types" in html
