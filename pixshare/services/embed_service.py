"""Codes prêts à copier pour partager ou intégrer une image ailleurs (forums, sites, GitHub, Discord…)."""
from __future__ import annotations

import os
import re

from markupsafe import escape


def _alt(name: str) -> str:
    """Texte alternatif : le nom du fichier sans extension, sans caractères qui casseraient les codes."""
    base = os.path.splitext(name or "")[0] or "image"
    return re.sub(r"[\[\]()<>\"`\r\n]", " ", base).strip()[:100] or "image"


def embed_codes(page_url: str, image_url: str, name: str) -> list[dict]:
    alt = _alt(name)
    html_alt = str(escape(alt))
    return [
        {"key": "page", "label": "Lien de la page", "hint": "à envoyer à quelqu'un", "code": page_url},
        {"key": "direct", "label": "Lien direct de l'image", "hint": "Discord, WhatsApp, messageries", "code": image_url},
        {"key": "html", "label": "HTML", "hint": "site web, blog", "code": f'<img src="{image_url}" alt="{html_alt}">'},
        {"key": "html_link", "label": "HTML cliquable", "hint": "l'image ouvre la page PixShare",
         "code": f'<a href="{page_url}"><img src="{image_url}" alt="{html_alt}"></a>'},
        {"key": "bbcode", "label": "BBCode", "hint": "forums (phpBB, vBulletin, jeuxvideo.com…)", "code": f"[img]{image_url}[/img]"},
        {"key": "bbcode_link", "label": "BBCode cliquable", "hint": "forums, l'image ouvre la page",
         "code": f"[url={page_url}][img]{image_url}[/img][/url]"},
        {"key": "markdown", "label": "Markdown", "hint": "GitHub, Reddit, documentation", "code": f"![{alt}]({image_url})"},
        {"key": "markdown_link", "label": "Markdown cliquable", "hint": "GitHub, Reddit, l'image ouvre la page",
         "code": f"[![{alt}]({image_url})]({page_url})"},
    ]
