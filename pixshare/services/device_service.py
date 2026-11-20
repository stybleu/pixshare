"""Appareils reconnus des membres + vérification par mail sur un nouvel appareil.

- L'appareil qui confirme l'inscription (ou qui ouvre un lien « mot de passe oublié ») est reconnu d'office :
  il a prouvé qu'il a accès à la boîte mail.
- Un autre appareil (en fait : un autre navigateur) doit, après le bon mot de passe, taper un code à 6 chiffres
  reçu par mail (10 minutes, 5 essais). Il devient ensuite reconnu.
- L'appareil est reconnu grâce à un cookie technique (pxs_appareil) qui contient un jeton tiré au hasard.
  Le site n'en garde que l'empreinte : même avec la base, impossible de fabriquer le cookie.
  Ce n'est PAS une empreinte du téléphone (qui se copie facilement et sert au pistage).
- La connexion est liée à l'appareil : le retirer dans « Mon compte » le déconnecte aussitôt.
- Le code n'est jamais dans le cookie de session (lisible par le navigateur) : il est gardé côté serveur,
  sous forme d'empreinte HMAC avec la clé secrète du site.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta

from flask import current_app, g, request, session

from pixshare.services.time_service import parse_dt, utcnow

COOKIE_NAME = "pxs_appareil"
COOKIE_DAYS = 400
MAX_DEVICES = 15
CODE_MINUTES = 10
CODE_TRIES = 5
CODES_PER_HOUR = 5
CHALLENGE_SESSION = "pxs_verif"


# ------------------------------------------------------------------ outils

def _now() -> str:
    return utcnow().isoformat(timespec="seconds")


def _token_hash(token: str) -> str:
    return hashlib.sha256(("pxs-appareil:" + (token or "")).encode("utf-8")).hexdigest()


def _code_hash(challenge_id: str, code: str) -> str:
    key = str(current_app.config.get("SECRET_KEY") or current_app.secret_key).encode("utf-8")
    return hmac.new(key, f"{challenge_id}:{code}".encode("utf-8"), hashlib.sha256).hexdigest()


def label_from_user_agent(ua: str) -> str:
    """« Chrome sur Android », « Safari sur iPhone »… (rien de plus précis : pas de pistage)."""
    ua = (ua or "").lower()
    if "samsungbrowser" in ua:
        browser = "Samsung Internet"
    elif "edg/" in ua or "edga/" in ua or "edgios" in ua:
        browser = "Edge"
    elif "opr/" in ua or "opera" in ua:
        browser = "Opera"
    elif "firefox" in ua or "fxios" in ua:
        browser = "Firefox"
    elif "chrome" in ua or "crios" in ua:
        browser = "Chrome"
    elif "safari" in ua:
        browser = "Safari"
    else:
        browser = "Navigateur"
    if "iphone" in ua:
        system = "iPhone"
    elif "ipad" in ua:
        system = "iPad"
    elif "android" in ua:
        system = "Android"
    elif "windows" in ua:
        system = "Windows"
    elif "mac os" in ua or "macintosh" in ua:
        system = "Mac"
    elif "linux" in ua:
        system = "Linux"
    else:
        system = "appareil inconnu"
    return f"{browser} sur {system}"


def mask_email(email: str) -> str:
    local, _at, domain = (email or "").partition("@")
    if not domain:
        return "votre adresse"
    return (local[:1] + "•••" + (local[-1:] if len(local) > 2 else "")) + "@" + domain


# ------------------------------------------------------------------ appareils

def devices(rec: dict | None) -> list[dict]:
    items = (rec or {}).get("devices") or []
    return [d for d in items if isinstance(d, dict) and d.get("id") and d.get("h")]


def _cookie_token() -> str:
    token = (request.cookies.get(COOKIE_NAME) or "").strip()
    return token if 20 <= len(token) <= 100 else ""


def current_device_id(rec: dict | None) -> str:
    """Identifiant de l'appareil reconnu qui fait la requête (ou "")."""
    token = _cookie_token()
    if not token or not rec:
        return ""
    wanted = _token_hash(token)
    for d in devices(rec):
        if hmac.compare_digest(str(d["h"]), wanted):
            return str(d["id"])
    return ""


def has_device(rec: dict | None, device_id: str) -> bool:
    return bool(device_id) and any(d["id"] == device_id for d in devices(rec))


def trust_current(account_id: str) -> str:
    """Reconnaît l'appareil qui fait la requête (le cookie est posé avec la réponse). Renvoie son identifiant."""
    from pixshare.services import account_service as accounts
    rec = accounts.get_account(account_id)
    if not rec:
        return ""
    known = current_device_id(rec)
    if known:
        touch(account_id, known, force=True)
        return known
    token = secrets.token_urlsafe(32)
    device = {"id": secrets.token_urlsafe(9), "h": _token_hash(token),
              "label": label_from_user_agent(request.headers.get("User-Agent", "")),
              "added": _now(), "seen": _now()}
    items = sorted(devices(rec), key=lambda d: d.get("seen") or "", reverse=True)[:MAX_DEVICES - 1]
    accounts._update(account_id, devices=items + [device])
    g.pxs_new_device_token = token
    return device["id"]


def touch(account_id: str, device_id: str, force: bool = False) -> None:
    """Date de dernière visite (au plus une écriture par jour)."""
    from pixshare.services import account_service as accounts
    rec = accounts.get_account(account_id)
    today = _now()[:10]
    items = devices(rec)
    for d in items:
        if d["id"] == device_id and (force or (d.get("seen") or "")[:10] != today):
            d["seen"] = _now()
            accounts._update(account_id, devices=items)
            return


def remove(account_id: str, device_id: str) -> bool:
    from pixshare.services import account_service as accounts
    rec = accounts.get_account(account_id)
    items = devices(rec)
    kept = [d for d in items if d["id"] != device_id]
    if len(kept) == len(items):
        return False
    accounts._update(account_id, devices=kept)
    return True


def remove_all_but(account_id: str, keep_id: str = "") -> int:
    from pixshare.services import account_service as accounts
    items = devices(accounts.get_account(account_id))
    kept = [d for d in items if keep_id and d["id"] == keep_id]
    accounts._update(account_id, devices=kept, login_challenges={})
    return len(items) - len(kept)


def set_cookie_if_needed(response):
    token = g.pop("pxs_new_device_token", None)
    if token:
        response.set_cookie(COOKIE_NAME, token, max_age=COOKIE_DAYS * 86400, httponly=True,
                            secure=bool(current_app.config.get("SESSION_COOKIE_SECURE", True)), samesite="Lax")
    return response


# ------------------------------------------------------------------ code par mail

def _challenges(rec: dict) -> dict:
    items = (rec or {}).get("login_challenges") or {}
    now = utcnow()
    out = {}
    for cid, ch in items.items():
        try:
            if isinstance(ch, dict) and parse_dt(ch.get("exp") or "") > now:
                out[cid] = ch
        except Exception:
            continue
    return out


def codes_sent_last_hour(rec: dict) -> int:
    now = utcnow()
    count = 0
    for at in (rec or {}).get("codes_sent") or []:
        try:
            if now - parse_dt(at) < timedelta(hours=1):
                count += 1
        except Exception:
            continue
    return count


def start_challenge(rec: dict) -> tuple[bool, str]:
    """Envoie un code à 6 chiffres. (True, "") si parti, sinon (False, message pour la personne)."""
    from pixshare.services import account_service as accounts
    if codes_sent_last_hour(rec) >= CODES_PER_HOUR:
        return False, "Trop de codes envoyés pour ce compte. Réessayez dans une heure."
    code = f"{secrets.randbelow(1_000_000):06d}"
    cid = secrets.token_urlsafe(16)
    exp = (utcnow() + timedelta(minutes=CODE_MINUTES)).isoformat(timespec="seconds")
    challenges = _challenges(rec)
    challenges = dict(sorted(challenges.items(), key=lambda kv: kv[1].get("exp") or "")[-2:])  # 3 au plus
    challenges[cid] = {"code": _code_hash(cid, code), "exp": exp, "tries": 0}
    sent = [at for at in (rec.get("codes_sent") or [])][-10:] + [_now()]
    accounts._update(rec["id"], login_challenges=challenges, codes_sent=sent)
    if not accounts.send_login_code(rec, code, label_from_user_agent(request.headers.get("User-Agent", ""))):
        return False, "Le mail avec le code n'a pas pu partir. Réessayez dans quelques minutes."
    session[CHALLENGE_SESSION] = {"a": rec["id"], "c": cid, "v": int(rec.get("pw_ver") or 0)}
    return True, ""


def pending() -> tuple[dict | None, str]:
    """(compte, identifiant du code) de la vérification en cours dans ce navigateur, sinon (None, "")."""
    from pixshare.services import account_service as accounts
    info = session.get(CHALLENGE_SESSION)
    if not isinstance(info, dict):
        return None, ""
    rec = accounts.get_account(str(info.get("a") or ""))
    if (not rec or int(rec.get("pw_ver") or 0) != int(info.get("v") or -1)
            or str(info.get("c") or "") not in _challenges(rec)):
        session.pop(CHALLENGE_SESSION, None)
        return None, ""
    return rec, str(info["c"])


def check_code(code: str) -> tuple[dict | None, str]:
    """(compte, "") si le code est bon (il ne resservira pas), sinon (None, message)."""
    from pixshare.services import account_service as accounts
    rec, cid = pending()
    if not rec:
        return None, "La vérification a expiré. Reconnectez-vous."
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    challenges = _challenges(rec)
    ch = challenges.get(cid) or {}
    if len(code) == 6 and hmac.compare_digest(str(ch.get("code") or ""), _code_hash(cid, code)):
        challenges.pop(cid, None)
        accounts._update(rec["id"], login_challenges=challenges)
        session.pop(CHALLENGE_SESSION, None)
        return rec, ""
    ch["tries"] = int(ch.get("tries") or 0) + 1
    if ch["tries"] >= CODE_TRIES:
        challenges.pop(cid, None)
        session.pop(CHALLENGE_SESSION, None)
        accounts._update(rec["id"], login_challenges=challenges)
        return None, "Trop d'essais : ce code ne marche plus. Reconnectez-vous pour en recevoir un nouveau."
    challenges[cid] = ch
    accounts._update(rec["id"], login_challenges=challenges)
    left = CODE_TRIES - ch["tries"]
    return None, f"Code incorrect. Encore {left} essai(s)."
