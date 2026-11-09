import logging

from flask import current_app, request

_log = logging.getLogger(__name__)
_warned_legacy_xff = False


def get_client_ip() -> str:
    """Retourne l'IP du visiteur.

    ``X-Forwarded-For`` est une valeur que le client peut falsifier : sans
    précaution, n'importe qui peut choisir l'IP qui sera enregistrée (et donc
    contourner le blocage d'IP, les limites de création de clés, le verrouillage
    admin...).

    Configuration via la variable d'environnement ``TRUSTED_PROXY_COUNT`` :
      - ``0``  : aucun proxy devant l'app, on ignore ``X-Forwarded-For``.
      - ``N``  : N proxys de confiance ajoutent chacun une entrée à droite de
                 l'en-tête ; l'IP du visiteur est la N-ième entrée en partant de
                 la droite (les entrées ajoutées par le client, à gauche, sont
                 ignorées).
      - non défini : ancien comportement (première entrée, falsifiable) conservé
                 pour ne rien casser, avec un avertissement dans les logs.
    """
    global _warned_legacy_xff

    xff = request.headers.get("X-Forwarded-For", "")
    trusted = current_app.config.get("TRUSTED_PROXY_COUNT")

    if trusted is None:
        if xff:
            if not _warned_legacy_xff:
                _warned_legacy_xff = True
                _log.warning(
                    "TRUSTED_PROXY_COUNT n'est pas défini : l'IP lue dans X-Forwarded-For "
                    "peut être falsifiée par le client. Définis TRUSTED_PROXY_COUNT "
                    "(0 sans proxy, 1 derrière un seul proxy...)."
                )
            return xff.split(",")[0].strip()
        return (request.remote_addr or "").strip()

    if trusted <= 0 or not xff:
        return (request.remote_addr or "").strip()

    parts = [p.strip() for p in xff.split(",") if p.strip()]
    if not parts:
        return (request.remote_addr or "").strip()
    if len(parts) >= trusted:
        return parts[-trusted]
    return parts[0]
