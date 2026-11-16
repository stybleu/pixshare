"""Signalement en un clic : après plusieurs signalements de visiteurs différents,
l'image est masquée et passe « à vérifier » (l'admin reçoit l'alerte par mail).

Réglage : variable Render REPORT_HIDE_THRESHOLD (3 par défaut ; 0 = jamais masquée automatiquement).
Les IP ne sont pas stockées : seulement une empreinte non réversible, pour compter une fois par visiteur.
"""
from __future__ import annotations

import hashlib
import os

from flask import current_app

from pixshare.services.json_services import _json_lock, load_db, save_db
from pixshare.services.moderation_service import mark_image_for_review

REPORT_LABEL = "signalement"
REPORT_REASONS = (
    ("nudite", "Nudité ou contenu sexuel"),
    ("violence", "Violence ou contenu choquant"),
    ("haine", "Haine ou harcèlement"),
    ("perso", "Données personnelles (photo, adresse…)"),
    ("illegal", "Autre contenu illégal"),
)
REASON_LABELS = dict(REPORT_REASONS)


def hide_threshold() -> int:
    try:
        return max(0, int(os.environ.get("REPORT_HIDE_THRESHOLD", "3")))
    except ValueError:
        return 3


def _reporter_key(ip: str) -> str:
    secret = str(current_app.config.get("SECRET_KEY") or "")
    return hashlib.sha256(f"{secret}|{ip}".encode()).hexdigest()[:16]


def report_file(file_id: str, ip: str, reason: str) -> str:
    """Enregistre un signalement. Retourne "recorded", "already", "hidden" ou "missing"."""
    reason = reason if reason in REASON_LABELS else "illegal"
    key = _reporter_key(ip or "?")
    with _json_lock:
        db = load_db()
        meta = db.get(file_id)
        if not isinstance(meta, dict) or (meta.get("status") or "active").lower() != "active":
            return "missing"
        reporters = list(meta.get("reports") or [])
        if key in reporters:
            return "already"
        reporters.append(key)
        meta["reports"] = reporters
        reasons = dict(meta.get("report_reasons") or {})
        reasons[reason] = int(reasons.get(reason, 0)) + 1
        meta["report_reasons"] = reasons
        threshold = hide_threshold()
        if threshold and len(reporters) >= threshold:
            mark_image_for_review(db, file_id, meta, REPORT_LABEL, None, REPORT_LABEL)  # masque + mail admin
            return "hidden"
        db[file_id] = meta
        save_db(db)
        return "recorded"


def reasons_summary(meta: dict) -> str:
    """« Violence ×2, Haine ×1 » pour l'admin."""
    reasons = (meta or {}).get("report_reasons") or {}
    parts = [f"{REASON_LABELS.get(k, k)} ×{n}" for k, n in sorted(reasons.items(), key=lambda kv: -kv[1])]
    return ", ".join(parts)
