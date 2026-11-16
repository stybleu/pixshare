"""Anti-robots Cloudflare Turnstile (gratuit, invisible pour la plupart des humains).

Activé seulement si les deux variables Render existent : TURNSTILE_SITE_KEY et TURNSTILE_SECRET_KEY
(Cloudflare → Turnstile → Add widget, domaine pixshare.fr). L'admin connecté n'est jamais vérifié.
"""
from __future__ import annotations

import logging
import os

import requests

from pixshare.services.auth_service import is_admin

_log = logging.getLogger(__name__)
VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
SCRIPT_URL = "https://challenges.cloudflare.com/turnstile/v0/api.js"


def site_key() -> str:
    key = (os.environ.get("TURNSTILE_SITE_KEY") or "").strip()
    secret = (os.environ.get("TURNSTILE_SECRET_KEY") or "").strip()
    return key if key and secret else ""


def turnstile_required() -> bool:
    return bool(site_key()) and not is_admin()


def turnstile_ok(form, ip: str) -> bool:
    """Vérifie le jeton du formulaire auprès de Cloudflare.

    Si Cloudflare est injoignable, on laisse passer (le site ne doit pas tomber avec Cloudflare) :
    CSRF, limites d'envoi et NudeNet protègent toujours.
    """
    if not turnstile_required():
        return True
    token = (form.get("cf-turnstile-response") or "").strip()
    if not token:
        return False
    try:
        resp = requests.post(
            VERIFY_URL,
            data={"secret": os.environ["TURNSTILE_SECRET_KEY"].strip(), "response": token, "remoteip": ip or ""},
            timeout=5,
        )
        return bool(resp.json().get("success"))
    except Exception as exc:
        _log.warning("Turnstile injoignable, envoi accepté : %s", type(exc).__name__)
        return True
