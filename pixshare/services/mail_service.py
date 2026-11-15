"""Alerte par e-mail pour l'admin : une image part en « à vérifier ».

Réglé par des variables d'environnement (Render) : MAIL_SMTP_HOST, MAIL_SMTP_USER, MAIL_SMTP_PASS,
MAIL_TO (destinataire), et en option MAIL_SMTP_PORT (587 par défaut ; 465 = SSL), MAIL_FROM, MAIL_SITE_URL.
L'envoi ne bloque jamais la modération : en cas d'échec, on écrit seulement un avertissement dans les logs.
Les alertes sont groupées : un mail liste toutes les images en attente, au plus un toutes les 5 minutes.
"""
from __future__ import annotations

import logging
import os
import smtplib
import ssl
import threading
import time
from email.message import EmailMessage

from flask import current_app

from pixshare.services.json_services import load_db
from pixshare.services.settings_service import nsfw_class_label

_log = logging.getLogger(__name__)

DELAY = 30           # secondes d'attente avant le 1er mail (laisse le temps aux autres images du lot)
MIN_INTERVAL = 300   # secondes minimum entre deux mails
MAX_LISTED = 10      # images listées dans un mail

_lock = threading.Lock()
_last_sent = None
_timer = None


def _cfg() -> dict:
    env = os.environ
    try:
        port = int(env.get("MAIL_SMTP_PORT") or 587)
    except ValueError:
        port = 587
    user = (env.get("MAIL_SMTP_USER") or "").strip()
    to = (env.get("MAIL_TO") or "").strip()
    return {
        "host": (env.get("MAIL_SMTP_HOST") or "").strip(),
        "port": port,
        "user": user,
        "password": env.get("MAIL_SMTP_PASS") or "",
        "to": to,
        "sender": (env.get("MAIL_FROM") or "").strip() or user or to,
        "site": (env.get("MAIL_SITE_URL") or "https://pixshare.fr").strip().rstrip("/"),
    }


def mail_configured() -> bool:
    cfg = _cfg()
    return bool(cfg["host"] and cfg["to"])


def send_mail_now(subject: str, body: str) -> tuple[bool, str]:
    """Envoie un mail tout de suite. Renvoie (réussi, message d'erreur)."""
    cfg = _cfg()
    if not (cfg["host"] and cfg["to"]):
        return False, "variables MAIL_SMTP_HOST et MAIL_TO manquantes"
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["sender"]
    msg["To"] = cfg["to"]
    msg.set_content(body)
    try:
        context = ssl.create_default_context()
        if cfg["port"] == 465:
            server = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=15, context=context)
        else:
            server = smtplib.SMTP(cfg["host"], cfg["port"], timeout=15)
        with server:
            if cfg["port"] != 465:
                server.starttls(context=context)
            if cfg["user"]:
                server.login(cfg["user"], cfg["password"])
            server.send_message(msg)
        return True, ""
    except Exception as exc:
        _log.warning("Envoi du mail impossible: %s: %s", type(exc).__name__, exc)
        return False, f"{type(exc).__name__}: {exc}"[:200]


def _build_summary(app) -> tuple[str, str] | None:
    with app.app_context():
        waiting = [
            (file_id, meta) for file_id, meta in load_db().items()
            if isinstance(meta, dict)
            and str(meta.get("status") or "").lower() == "pending"
            and str(meta.get("moderation_decision") or "").lower() == "manual_review"
        ]
    if not waiting:
        return None
    waiting.sort(key=lambda item: str(item[1].get("moderated_at") or ""), reverse=True)
    lines = []
    for file_id, meta in waiting[:MAX_LISTED]:
        raw_label = str(meta.get("moderation_label") or "")
        label = "analyse impossible" if raw_label == "analyse_impossible" else (nsfw_class_label(raw_label) or "—")
        score = meta.get("moderation_score")
        score_txt = f" · score {float(score):.2f}" if isinstance(score, (int, float)) else ""
        name = str(meta.get("original_name") or file_id).replace("\n", " ")[:80]
        lines.append(f"- {name} : {label}{score_txt}")
    count = len(waiting)
    if count > MAX_LISTED:
        lines.append(f"... et {count - MAX_LISTED} autre(s).")
    site = _cfg()["site"]
    subject = f"PixShare : {count} image{'s' if count > 1 else ''} à vérifier"
    body = (
        "NudeNet a mis de côté "
        + ("des images qui attendent" if count > 1 else "une image qui attend")
        + " ta décision (elles restent privées en attendant) :\n\n"
        + "\n".join(lines)
        + f"\n\nÀ traiter ici : {site}/admin\n"
    )
    return subject, body


def _flush(app) -> None:
    global _last_sent, _timer
    with _lock:
        _timer = None
        _last_sent = time.monotonic()
    try:
        mail = _build_summary(app)
        if mail:
            send_mail_now(*mail)
    except Exception:
        _log.exception("Alerte mail interrompue")


def notify_review() -> None:
    """Prévient l'admin qu'une image attend sa décision (mail groupé, jamais bloquant)."""
    global _timer
    if not mail_configured():
        return
    app = current_app._get_current_object()
    with _lock:
        if _timer is not None:
            return  # un mail est déjà prévu : il listera aussi cette image
        since = (time.monotonic() - _last_sent) if _last_sent is not None else MIN_INTERVAL
        delay = max(DELAY, MIN_INTERVAL - since)
        _timer = threading.Timer(delay, _flush, args=(app,))
        _timer.daemon = True
        _timer.start()
