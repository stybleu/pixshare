"""Alerte par e-mail pour l'admin : une image part en « à vérifier ».

Réglé par des variables d'environnement (Render) : MAIL_SMTP_HOST, MAIL_SMTP_USER, MAIL_SMTP_PASS,
MAIL_TO (destinataire), et en option MAIL_SMTP_PORT (587 par défaut ; 465 = SSL), MAIL_FROM, MAIL_SITE_URL.
L'envoi ne bloque jamais la modération : en cas d'échec, on écrit seulement un avertissement dans les logs.

Mails des comptes (confirmation, mot de passe oublié) : envoyés aux membres avec les mêmes réglages,
ou avec une autre boîte si ACCOUNT_MAIL_SMTP_HOST est défini (ACCOUNT_MAIL_SMTP_USER, ACCOUNT_MAIL_SMTP_PASS,
ACCOUNT_MAIL_SMTP_PORT, ACCOUNT_MAIL_FROM). L'adresse d'envoi est visible par les membres.
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


def _cfg(prefix: str = "MAIL_") -> dict:
    env = os.environ
    try:
        port = int(env.get(prefix + "SMTP_PORT") or 587)
    except ValueError:
        port = 587
    user = (env.get(prefix + "SMTP_USER") or "").strip()
    to = (env.get("MAIL_TO") or "").strip()
    return {
        "host": (env.get(prefix + "SMTP_HOST") or "").strip(),
        "port": port,
        "user": user,
        "password": env.get(prefix + "SMTP_PASS") or "",
        "to": to,
        "sender": (env.get(prefix + "FROM") or "").strip() or user or (to if prefix == "MAIL_" else ""),
        "site": (env.get("MAIL_SITE_URL") or "https://pixshare.fr").strip().rstrip("/"),
    }


def mail_configured() -> bool:
    cfg = _cfg()
    return bool(cfg["host"] and cfg["to"])


def _account_cfg() -> dict:
    return _cfg("ACCOUNT_MAIL_") if (os.environ.get("ACCOUNT_MAIL_SMTP_HOST") or "").strip() else _cfg()


def account_mail_configured() -> bool:
    cfg = _account_cfg()
    return bool(cfg["host"] and cfg["sender"])


def send_account_mail(to: str, subject: str, body: str, html: str | None = None) -> tuple[bool, str]:
    """Mail à un membre (confirmation, mot de passe oublié)."""
    cfg = _account_cfg()
    if not (cfg["host"] and cfg["sender"]):
        return False, "envoi de mails non configuré"
    return send_mail_now(subject, body, html=html, cfg=dict(cfg, to=to))


def send_mail_now(subject: str, body: str, html: str | None = None, images: dict | None = None,
                  cfg: dict | None = None) -> tuple[bool, str]:
    """Envoie un mail tout de suite (texte, et HTML avec images intégrées si fourni). Renvoie (réussi, erreur)."""
    cfg = cfg or _cfg()
    if not (cfg["host"] and cfg["to"]):
        return False, "variables MAIL_SMTP_HOST et MAIL_TO manquantes"
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["sender"]
    msg["To"] = cfg["to"]
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
        html_part = msg.get_payload()[-1]
        for cid, data in (images or {}).items():
            html_part.add_related(data, "image", "jpeg", cid=f"<{cid}>")
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


def _build_summary(app):
    """(sujet, texte, html, images) : une carte par image avec l'aperçu et les boutons Approuver / Supprimer."""
    from html import escape

    from pixshare.services import review_link_service as rl

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
        site = _cfg()["site"]
        mode = rl.mail_image_mode()
        lines, cards, images = [], [], {}
        for index, (file_id, meta) in enumerate(waiting[:MAX_LISTED]):
            raw_label = str(meta.get("moderation_label") or "")
            label = nsfw_class_label(raw_label) or "—"
            score = meta.get("moderation_score")
            score_txt = f" · score {float(score):.2f}" if isinstance(score, (int, float)) else ""
            name = str(meta.get("original_name") or file_id).replace("\n", " ")[:80]
            link = f"{site}/moderation/{rl.make_token(file_id)}"
            lines.append(f"- {name} : {label}{score_txt}\n  Approuver : {link}?a=approve\n  Supprimer : {link}?a=delete")
            thumb = rl.mail_thumbnail(meta, mode)
            img_html = ""
            if thumb:
                cid = f"pixshare-review-{index}"
                images[cid] = thumb
                img_html = f'<img src="cid:{cid}" alt="Aperçu" style="max-width:100%;max-height:360px;border-radius:6px;display:block;margin:0 auto 10px">'
            cards.append(
                '<div style="border:1px solid #ddd;border-radius:10px;padding:12px;margin:0 0 14px">'
                f"{img_html}"
                f'<div style="font-size:14px;margin-bottom:10px"><b>{escape(name)}</b> · {escape(label)}{escape(score_txt)}</div>'
                f'<a href="{link}?a=approve" style="display:inline-block;background:#198754;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none;margin-right:8px">✅ Approuver</a>'
                f'<a href="{link}?a=delete" style="display:inline-block;background:#dc3545;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none">🗑️ Supprimer</a>'
                "</div>"
            )
    count = len(waiting)
    more = f"... et {count - MAX_LISTED} autre(s) dans l'admin." if count > MAX_LISTED else ""
    subject = f"PixShare : {count} image{'s' if count > 1 else ''} à vérifier"
    intro = ("NudeNet ou les signalements des visiteurs ont mis de côté "
             + ("des images qui attendent" if count > 1 else "une image qui attend")
             + " ta décision (elles restent privées en attendant).")
    body = intro + "\n\n" + "\n".join(lines) + (f"\n{more}" if more else "") + f"\n\nAdmin : {site}/admin\n"
    html = (
        '<div style="font-family:system-ui,Arial,sans-serif;max-width:560px;margin:auto">'
        f"<p>{escape(intro)}</p>" + "".join(cards)
        + (f"<p>{escape(more)}</p>" if more else "")
        + '<p style="font-size:12px;color:#666">Chaque bouton ouvre une page de confirmation (lien personnel valable 48 h, '
          f'sans connexion). <a href="{site}/admin">Ouvrir l\'admin</a></p></div>'
    )
    return subject, body, html, images


def _flush(app) -> None:
    global _last_sent, _timer
    with _lock:
        _timer = None
        _last_sent = time.monotonic()
    try:
        mail = _build_summary(app)
        if mail:
            subject, body, html, images = mail
            send_mail_now(subject, body, html=html, images=images)
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
