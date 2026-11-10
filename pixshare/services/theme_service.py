"""Thèmes de saison : le site change de décor tout seul selon la date.

Ordre de priorité :
  1. le choix enregistré dans Admin > Réglages (perdu à chaque déploiement
     sans disque) ;
  2. la variable d'environnement SEASON_THEME sur Render
     (auto, aucun, noel, nouvel_an, saint_valentin, paques, halloween,
     quatorze_juillet) ;
  3. « auto » : le thème dépend de la date du jour.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
    _PARIS = ZoneInfo("Europe/Paris")
except Exception:  # pragma: no cover - fuseau absent : on reste en UTC
    _PARIS = timezone.utc

# clé : (nom affiché, petit message en haut du site)
THEMES = {
    "noel": ("Noël", "Joyeuses fêtes de fin d'année 🎄"),
    "nouvel_an": ("Nouvel An", "Bonne année {year} ✨"),
    "saint_valentin": ("Saint-Valentin", "Joyeuse Saint-Valentin 💝"),
    "paques": ("Pâques", "Joyeuses Pâques 🐣"),
    "halloween": ("Halloween", "Joyeux Halloween 🎃"),
    "quatorze_juillet": ("14 Juillet", "Bonne fête nationale 🇫🇷"),
}

THEME_CHOICES = (("auto", "Automatique (selon la date)"), ("aucun", "Aucun thème")) + tuple(
    (key, label) for key, (label, _msg) in THEMES.items()
)


def easter(year: int) -> date:
    """Dimanche de Pâques (calendrier grégorien)."""
    a = year % 19
    b, c = divmod(year, 100)
    d, e = divmod(b, 4)
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = divmod(c, 4)
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    month = (h + l - 7 * m + 114) // 31
    day = (h + l - 7 * m + 114) % 31 + 1
    return date(year, month, day)


def theme_for_date(day: date) -> str:
    """Thème automatique du jour, ou "" s'il n'y en a pas."""
    m, d = day.month, day.day
    if (m == 12 and d >= 31) or (m == 1 and d <= 2):
        return "nouvel_an"
    if m == 12 or (m == 1 and d <= 6):
        return "noel"
    if m == 2 and 7 <= d <= 14:
        return "saint_valentin"
    sunday = easter(day.year)
    if sunday - timedelta(days=7) <= day <= sunday + timedelta(days=1):
        return "paques"
    if (m == 10 and d >= 24) or (m == 11 and d <= 1):
        return "halloween"
    if m == 7 and 13 <= d <= 14:
        return "quatorze_juillet"
    return ""


def clean_choice(value) -> str:
    value = str(value or "").strip().lower()
    return value if value in dict(THEME_CHOICES) else ""


def today_paris() -> date:
    return datetime.now(_PARIS).date()


def active_theme(saved_choice=None, day: date | None = None) -> str:
    choice = clean_choice(saved_choice) or clean_choice(os.environ.get("SEASON_THEME")) or "auto"
    if choice == "aucun":
        return ""
    if choice in THEMES:
        return choice
    return theme_for_date(day or today_paris())


def sky_enabled(saved=None) -> bool:
    """Ciel selon l'heure (lune la nuit, soleil et nuages le jour).

    Choix de l'admin s'il existe, sinon variable SKY_THEME (0 = coupé), sinon activé.
    """
    if isinstance(saved, bool):
        return saved
    return (os.environ.get("SKY_THEME", "1").strip() or "1") != "0"


def theme_message(theme: str, day: date | None = None) -> str:
    if theme not in THEMES:
        return ""
    day = day or today_paris()
    year = day.year + 1 if day.month == 12 else day.year
    return THEMES[theme][1].format(year=year)
