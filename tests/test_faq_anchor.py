def test_faq_has_anchor_for_removed_image_question(make_app):
    html = make_app().test_client().get("/faq").get_data(as_text=True)
    assert 'id="image-retiree"' in html
    assert "Contester une décision de modération" in html


def test_admin_simple_delete_is_not_called_a_cgu_violation():
    from pixshare.services.moderation_service import removal_cause
    assert "conditions d'utilisation" not in removal_cause({"delete_reason": "admin_delete"})
    assert "conditions d'utilisation" in removal_cause({"delete_reason": "non_respect_cgu"})
