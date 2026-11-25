from tests.test_reports import setup


def test_image_page_shows_report_confirmation_next_to_the_button(make_app):
    app, file_id = setup(make_app)
    html = app.test_client().get(f"/image/{file_id}").get_data(as_text=True)
    assert 'id="reportForm"' in html and 'id="reportStatus"' in html and f"/report/{file_id}" in html
