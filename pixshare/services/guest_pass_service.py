"""« Options avancées » sans compte : un visiteur peut utiliser toutes les options des membres
(taille et durée des comptes, mot de passe, limite de vues, amélioration, filtres, scanner de
documents, sons) pour quelques envois par heure seulement. Les albums restent réservés aux comptes.

Le compteur est gardé en mémoire, par adresse IP (comme la limite d'envois), et n'est jamais
enregistré. La modération n'est pas concernée : elle se base sur le compte du fichier, et un
envoi sans compte garde le filtre des visiteurs.
"""
from __future__ import annotations

import os

from flask import g, request

PASS_KEY = "guest_pass_per_hour"


def per_hour() -> int:
    from .settings_service import load_settings
    try:
        return max(0, int(load_settings().get(PASS_KEY) or 0))
    except (TypeError, ValueError):
        return 0


def offered() -> bool:
    """Les options avancées sont-elles proposées aux visiteurs sans compte ?"""
    return per_hour() > 0


def active() -> bool:
    """Cet envoi utilise un passage « options avancées » accordé pour cette requête."""
    try:
        return bool(getattr(g, "pixshare_guest_pass", False))
    except RuntimeError:
        return False


def features_unlocked() -> bool:
    """Options des membres disponibles pour cette requête (membre, admin, ou passage accordé)."""
    from .account_service import is_member
    return is_member() or active()


def _truthy(name: str) -> bool:
    return (request.form.get(name) or "").strip().lower() in {"1", "on", "true", "yes"}


def wants_advanced(files) -> bool:
    """L'envoi d'un visiteur demande-t-il une option réservée d'habitude aux comptes ?"""
    from .file_service import AUDIO_EXTENSIONS
    from .settings_service import get_max_lifetime, get_max_upload_size_mb
    if (request.form.get("file_password") or "") or _truthy("view_limit_enabled"):
        return True
    if _truthy("enhance_quality") or (request.form.get("photo_filter") or "").strip():
        return True
    if any(os.path.splitext(f.filename or "")[1].lower() in AUDIO_EXTENSIONS for f in files or []):
        return True
    try:
        if int(request.form.get("lifetime") or 0) > get_max_lifetime(False):
            return True
    except (TypeError, ValueError):
        pass
    # Un peu de marge : l'en-tête d'un formulaire ajoute quelques Ko à la taille du fichier.
    guest_bytes = get_max_upload_size_mb(False) * 1024 * 1024
    return (request.content_length or 0) > guest_bytes + 64 * 1024


def _key(ip: str, guest_token: str) -> str:
    return f"pass:{ip}" if ip else f"pass:tok:{guest_token or 'anonyme'}"


def usage(ip: str, guest_token: str) -> dict:
    """Compteur affiché aux visiteurs, à la façon des assistants en ligne :
    utilisations restantes et heure de recharge (heure de Paris)."""
    from datetime import datetime, timedelta
    from zoneinfo import ZoneInfo
    from .upload_limit_service import peek_upload_rate
    limit = per_hour()
    remaining, wait = peek_upload_rate(_key(ip, guest_token), limit)
    refill = ""
    if wait:
        at = datetime.now(ZoneInfo("Europe/Paris")) + timedelta(seconds=wait)
        refill = f"{at.hour} h {at.minute:02d}"
    return {"limit": limit, "remaining": remaining, "used": limit - remaining, "refill": refill,
            "percent": int(round(100 * remaining / limit)) if limit else 0}


def try_unlock(ip: str, guest_token: str):
    """Compte un passage. Renvoie None si accordé (et l'active pour la requête), sinon le message à afficher."""
    from .upload_limit_service import check_upload_rate, format_wait, format_window
    limit = per_hour()
    if limit <= 0:
        return None
    info = check_upload_rate(_key(ip, guest_token), limit=limit)
    if info.allowed:
        g.pixshare_guest_pass = True
        return None
    times = "1 utilisation" if limit == 1 else f"{limit} utilisations"
    return (f"Vous avez utilisé vos options avancées ({times} par {format_window(info.window)} sans compte). "
            f"Elles se rechargent dans {format_wait(info.retry_after)}. D'ici là, vous pouvez envoyer sans ces "
            f"options, ou créer un compte gratuit pour les utiliser sans limite.")
