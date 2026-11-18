"""Le même menu sur toutes les pages de l'admin (dont « Comptes »), avec la page en cours mise en avant."""
from conftest import login

PAGES = {
    "/admin": "Fichiers", "/admin/thumbnails": "Miniatures", "/admin/messages": "Messages",
    "/admin/comptes": "Comptes", "/admin/stats": "Statistiques", "/admin/live": "● En direct",
    "/admin/blocked-ips": "IP bloquées", "/admin/system": "Système", "/admin/settings": "Paramètres",
    "/admin/disque": "Système",
}


def test_same_menu_everywhere(make_app):
    admin = login(make_app().test_client())
    for path, current in PAGES.items():
        html = admin.get(path).get_data(as_text=True)
        assert html.count('aria-label="Menu de l\'admin"') == 1, path
        for label in ("Fichiers", "Miniatures", "Messages", "Comptes", "Statistiques", "IP bloquées", "Système", "Paramètres", "Déconnexion"):
            assert label in html, (path, label)
        assert f'aria-current="page" href' in html and f'>{current}</a>' in html, path
