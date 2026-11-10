import ipaddress
import logging

from flask import current_app, request

_log = logging.getLogger(__name__)


def _valid_ip(value: str) -> str:
    value = (value or "").strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def ip_source() -> tuple[str, str]:
    """Retourne (IP du visiteur, d'où elle vient) : sert aussi à la page Système.

    Ordre de confiance :
      1. ``TRUSTED_PROXY_COUNT`` si tu l'as défini sur Render (réglage manuel) ;
      2. ``CF-Connecting-IP`` : Render passe par Cloudflare, qui écrase toujours
         cet en-tête avec la vraie IP du visiteur (le visiteur ne peut pas le
         falsifier) ;
      3. la DERNIÈRE entrée de ``X-Forwarded-For`` : elle est ajoutée par le
         proxy le plus proche ; les entrées de gauche peuvent être inventées
         par le visiteur, on les ignore ;
      4. l'adresse de connexion directe.
    """
    xff = request.headers.get("X-Forwarded-For", "")
    parts = [p.strip() for p in xff.split(",") if p.strip()]
    trusted = current_app.config.get("TRUSTED_PROXY_COUNT")

    if trusted is not None:
        if trusted > 0 and parts:
            pick = parts[-trusted] if len(parts) >= trusted else parts[0]
            ip = _valid_ip(pick)
            if ip:
                return ip, f"X-Forwarded-For (TRUSTED_PROXY_COUNT={trusted})"
        return (request.remote_addr or "").strip(), "connexion directe (TRUSTED_PROXY_COUNT)"

    cf = _valid_ip(request.headers.get("CF-Connecting-IP", ""))
    if cf:
        return cf, "CF-Connecting-IP (Cloudflare)"

    if parts:
        ip = _valid_ip(parts[-1])
        if ip:
            return ip, "X-Forwarded-For (derniere entree)"

    return (request.remote_addr or "").strip(), "connexion directe"


def get_client_ip() -> str:
    """IP du visiteur, impossible à choisir avec un faux en-tête X-Forwarded-For."""
    return ip_source()[0]
