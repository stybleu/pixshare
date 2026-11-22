"""IndexNow : prévient Bing (et Yandex, Seznam, Naver…) dès que les pages publiques changent,
au lieu d'attendre leur prochain passage.

- La clé est servie à la racine du site : https://pixshare.fr/<clé>.txt (c'est ainsi que Bing
  vérifie que l'envoi vient bien du site). Elle n'a rien de secret : elle est dérivée de la clé
  de l'appli, ou prise dans la variable INDEXNOW_KEY si tu en veux une à toi.
- Après chaque déploiement (nouveau commit sur Render), les pages du sitemap sont envoyées une
  seule fois, après la réponse de la première visite : aucune page n'attend.
- Seules les pages publiques partent : jamais les images, les albums ni l'admin.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import urllib.error
import urllib.request

ENDPOINT = "https://api.indexnow.org/indexnow"
STATE_DOC = "indexnow_state.json"
_KEY_RE = re.compile(r"^[A-Za-z0-9-]{8,128}$")
_lock = threading.Lock()
_checked = False

# Les pages publiques (les mêmes que le sitemap), avec leur version anglaise.
PUBLIC_PATHS = ["/", "/album-souvenir", "/faq", "/mentions-legales", "/cgu", "/contact"]


def site_url() -> str:
    return (os.environ.get("SITE_URL") or os.environ.get("MAIL_SITE_URL") or "https://pixshare.fr").strip().rstrip("/")


def key() -> str:
    env = (os.environ.get("INDEXNOW_KEY") or "").strip()
    if _KEY_RE.match(env):
        return env
    from flask import current_app
    secret = str(current_app.config.get("SECRET_KEY") or "pixshare")
    return hashlib.sha256(f"indexnow:{secret}".encode()).hexdigest()[:32]


def public_urls() -> list[str]:
    base = site_url()
    urls = [base + p for p in PUBLIC_PATHS]
    return urls + [base + p + "?lang=en" for p in PUBLIC_PATHS]


def _state() -> dict:
    from .json_services import load_json
    return load_json(STATE_DOC, {}) or {}


def _save(**values) -> None:
    from .json_services import load_json, save_json
    state = load_json(STATE_DOC, {}) or {}
    state.update(values)
    save_json(STATE_DOC, state)


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def status() -> dict:
    s = _state()
    return {"key": key(), "key_url": f"{site_url()}/{key()}.txt", **s}


def submit(urls: list[str] | None = None, timeout: float = 15) -> tuple[bool, str]:
    """Envoie la liste à IndexNow. Renvoie (réussi, message lisible)."""
    urls = urls or public_urls()
    host = site_url().split("://", 1)[-1]
    body = json.dumps({"host": host, "key": key(), "keyLocation": f"{site_url()}/{key()}.txt",
                       "urlList": urls}).encode()
    req = urllib.request.Request(ENDPOINT, data=body, method="POST",
                                 headers={"Content-Type": "application/json; charset=utf-8",
                                          "User-Agent": "PixShare-IndexNow"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:  # réseau indisponible…
        msg = f"envoi impossible ({type(e).__name__})"
        _save(last_at=_now_iso(), last_ok=False, last_message=msg)
        return False, msg
    messages = {200: "reçu ✅", 202: "reçu ✅ (clé en cours de vérification par Bing)",
                400: "demande refusée (format)", 403: "clé refusée : le fichier de clé n'est pas lisible",
                422: "adresses refusées (elles ne correspondent pas au site)", 429: "trop d'envois, réessaie plus tard"}
    ok = code in (200, 202)
    msg = messages.get(code, f"réponse {code}")
    _save(last_at=_now_iso(), last_ok=ok, last_message=msg, last_count=len(urls))
    return ok, msg


def _version(app) -> str:
    return (os.environ.get("RENDER_GIT_COMMIT") or str(app.config.get("APP_VERSION") or "")).strip()


def should_check() -> bool:
    """Vrai une seule fois par processus (à la première visite après un démarrage)."""
    global _checked
    if _checked:
        return False
    _checked = True
    return True


def maybe_submit_after_deploy(app) -> None:
    """Nouvelle version en ligne → les pages publiques sont envoyées une fois (tous processus confondus)."""
    with app.app_context():
        version = _version(app)
        if not version or version == "dev" or os.environ.get("INDEXNOW_DISABLED"):
            return
        with _lock:
            if _state().get("version") == version:
                return
            _save(version=version)          # noté avant l'envoi : un autre processus ne renverra pas
        submit()
