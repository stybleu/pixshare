"""Alerte par mail quand le disque se remplit (80 %, puis 95 %).

Un mail quand un palier est franchi, puis au plus un rappel par jour tant que le disque reste au-dessus.
Rien n'est envoyé sans disque persistant (le disque du conteneur n'est pas celui des images) ni sans mail configuré.
"""
from __future__ import annotations

import logging
import time
from datetime import timedelta

from pixshare.services.time_service import parse_dt, utcnow

_log = logging.getLogger(__name__)
STATE_DOC = "disk_alert.json"
LEVELS = (95, 80)
REMIND_HOURS = 24
_last_check: float | None = None


def level_for(percent: float | None) -> int:
    if percent is None:
        return 0
    for level in LEVELS:
        if percent >= level:
            return level
    return 0


def should_check(every_seconds: int = 600) -> bool:
    global _last_check
    now = time.monotonic()
    if _last_check is not None and now - _last_check < every_seconds:
        return False
    _last_check = now
    return True


def check_and_alert(app) -> str:
    """Vérifie le disque et envoie l'alerte si besoin. Renvoie ce qui a été fait (pour les tests et le journal)."""
    from pixshare.services.json_services import load_json, save_json
    from pixshare.services.mail_service import mail_configured, send_mail_now
    from pixshare.services.system_service import get_storage_usage

    with app.app_context():
        usage = get_storage_usage()
        if not usage.get("ok") or not usage.get("persistent"):
            return "pas de disque persistant"
        level = level_for(usage.get("percent"))
        state = load_json(STATE_DOC, {}) or {}
        if not level:
            return "ok"
        sent_at = state.get("sent_at") or ""
        try:
            recent = bool(sent_at) and utcnow() - parse_dt(sent_at) < timedelta(hours=REMIND_HOURS)
        except Exception:
            recent = False
        # Dans les 24 h qui suivent un mail : seulement si un palier plus haut est franchi
        # (pas de mails en rafale quand le disque oscille autour de 80 %).
        if recent and level <= int(state.get("level") or 0):
            return "déjà prévenu"
        if not mail_configured():
            return "mail non configuré"
        total = usage.get("total_mb") or 0
        used = usage.get("used_mb") or 0
        subject = f"PixShare : disque plein à {usage['percent']:.0f} %"
        body = (
            f"Le disque de PixShare est rempli à {usage['percent']:.0f} % ({used:.0f} Mo sur {total:.0f} Mo, "
            f"il reste {usage.get('free_mb', 0):.0f} Mo).\n\n"
            + ("Au-delà de la réserve, les nouveaux envois seront refusés (« Le stockage est plein »).\n\n" if level >= 95 else "")
            + "Pour libérer de la place ou en gagner :\n"
            "- Admin → Système → Disque : voir ce qui prend de la place ;\n"
            "- réduire la durée maximale des fichiers ou la taille des albums dans les réglages ;\n"
            "- agrandir le disque sur Render (Disks → Size).\n\n"
            f"Prochain rappel au plus tôt dans {REMIND_HOURS} heures si le disque reste au-dessus de {level} %."
        )
        ok, error = send_mail_now(subject, body)
        if ok:
            save_json(STATE_DOC, {"level": level, "sent_at": utcnow().isoformat(timespec="seconds")})
            return f"alerte {level} % envoyée"
        _log.warning("Alerte disque non envoyée : %s", error)
        return "échec de l'envoi"


def check_later(app) -> None:
    try:
        check_and_alert(app)
    except Exception:  # pragma: no cover
        _log.exception("Vérification du disque impossible")
