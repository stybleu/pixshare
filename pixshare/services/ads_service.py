"""Emplacements publicitaires : annonces Google AdSense (avec le message de consentement certifié de Google)
ou bannières directes (image + lien d'un partenaire, sans aucun pistage). Tout est coupé par défaut.

Jamais de publicité dans l'admin, les pages de compte, les pages d'erreur ou les pages légales.
"""
from __future__ import annotations

import io
import os
import re
from urllib.parse import urlparse

from pixshare.services.json_services import _get_data_dir, load_json, save_json

ADS_FILE = "ads.json"
SLOTS = {
    "accueil": "Accueil, sous l'envoi et la liste des fichiers",
    "partage": "Page de partage d'une image ou d'un fichier, sous le contenu",
    "pied": "Bas des pages avec publicité (au-dessus du pied de page)",
}
MODES = ("off", "google", "direct")
# Seules ces pages peuvent afficher de la publicité.
AD_ENDPOINTS = frozenset({"public.index", "public.image_page", "public.public_file"})

CLIENT_RE = re.compile(r"^ca-pub-\d{10,20}$")
AD_SLOT_RE = re.compile(r"^\d{5,20}$")
BANNER_FORMATS = {"PNG": "png", "JPEG": "jpg", "WEBP": "webp", "GIF": "gif"}
BANNER_MAX_BYTES = 2 * 1024 * 1024
BANNER_TYPES = {"png": "image/png", "jpg": "image/jpeg", "webp": "image/webp", "gif": "image/gif"}

# Ce que Google AdSense et son message de consentement ont besoin de charger (politique de sécurité du site).
GOOGLE_CSP = {
    "script-src": "https://pagead2.googlesyndication.com https://*.googlesyndication.com https://*.google.com "
                  "https://fundingchoicesmessages.google.com https://*.gstatic.com https://*.adtrafficquality.google "
                  "https://*.doubleclick.net https://*.googletagservices.com",
    "frame-src": "https://*.doubleclick.net https://*.googlesyndication.com https://*.google.com "
                 "https://fundingchoicesmessages.google.com https://*.adtrafficquality.google",
    "connect-src": "'self' https://*.google.com https://*.googlesyndication.com https://*.doubleclick.net "
                   "https://*.adtrafficquality.google https://fundingchoicesmessages.google.com https://*.gstatic.com",
}


def _empty_slot() -> dict:
    return {"mode": "off", "ad_slot": "", "link": "", "alt": "", "image": ""}


def clean_link(value) -> str:
    """Lien d'une bannière directe : https uniquement, adresse normale."""
    value = str(value or "").strip()
    if not value or len(value) > 500 or any(c in value for c in " \"'<>\\\n\r\t"):
        return ""
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or "@" in parsed.netloc:
        return ""
    return value


def clean(data) -> dict:
    data = data if isinstance(data, dict) else {}
    client = str(data.get("adsense_client") or "").strip()
    out = {
        "enabled": bool(data.get("enabled", False)),
        "adsense_client": client if CLIENT_RE.match(client) else "",
        "auto_ads": bool(data.get("auto_ads", False)),
        "hide_for_members": True if data.get("hide_for_members") is None else bool(data.get("hide_for_members")),
        "slots": {},
        "clicks": {},
    }
    slots = data.get("slots") if isinstance(data.get("slots"), dict) else {}
    clicks = data.get("clicks") if isinstance(data.get("clicks"), dict) else {}
    for name in SLOTS:
        raw = slots.get(name) if isinstance(slots.get(name), dict) else {}
        slot = _empty_slot()
        mode = raw.get("mode")
        slot["mode"] = mode if mode in MODES else "off"
        ad_slot = str(raw.get("ad_slot") or "").strip()
        slot["ad_slot"] = ad_slot if AD_SLOT_RE.match(ad_slot) else ""
        slot["link"] = clean_link(raw.get("link"))
        slot["alt"] = str(raw.get("alt") or "").strip()[:120]
        image = str(raw.get("image") or "")
        slot["image"] = image if re.fullmatch(rf"{name}\.(png|jpg|webp|gif)", image) else ""
        out["slots"][name] = slot
        try:
            out["clicks"][name] = max(0, int(clicks.get(name) or 0))
        except (TypeError, ValueError):
            out["clicks"][name] = 0
    return out


def load() -> dict:
    return clean(load_json(ADS_FILE, {}))


def save(data: dict) -> dict:
    data = clean(data)
    save_json(ADS_FILE, data)
    return data


def slot_ready(cfg: dict, name: str) -> bool:
    slot = cfg["slots"].get(name) or {}
    if slot.get("mode") == "google":
        return bool(cfg["adsense_client"] and slot.get("ad_slot"))
    if slot.get("mode") == "direct":
        return bool(slot.get("image") and slot.get("link") and os.path.isfile(banner_path(slot["image"])))
    return False


def google_on(cfg: dict) -> bool:
    if not cfg["enabled"] or not cfg["adsense_client"]:
        return False
    return cfg["auto_ads"] or any(cfg["slots"][n]["mode"] == "google" and slot_ready(cfg, n) for n in SLOTS)


def for_page(endpoint: str | None, member: bool) -> dict | None:
    """Publicités à afficher sur cette page, ou None."""
    if endpoint not in AD_ENDPOINTS:
        return None
    cfg = load()
    if not cfg["enabled"] or (member and cfg["hide_for_members"]):
        return None
    slots = {n: cfg["slots"][n] for n in SLOTS if slot_ready(cfg, n)}
    google = google_on(cfg)
    if not slots and not google:
        return None
    return {"google": google, "client": cfg["adsense_client"], "slots": slots}


def site_info() -> dict:
    """Pour les mentions légales et le tableau des comptes."""
    cfg = load()
    on = cfg["enabled"] and (google_on(cfg) or any(slot_ready(cfg, n) for n in SLOTS))
    return {"enabled": on, "google": on and google_on(cfg),
            "direct": on and any(cfg["slots"][n]["mode"] == "direct" and slot_ready(cfg, n) for n in SLOTS),
            "hide_for_members": cfg["hide_for_members"]}


def ads_txt() -> str:
    cfg = load()
    if not cfg["adsense_client"]:
        return ""
    # Ligne officielle de Google : identifiant d'éditeur sans « ca- », puis l'identifiant de Google.
    return f"google.com, {cfg['adsense_client'][3:]}, DIRECT, f08c47fec0942fa0\n"


def csp(base: str) -> str:
    """Politique de sécurité élargie aux domaines de Google, seulement sur les pages avec annonces Google."""
    parts = [p.strip() for p in base.split(";") if p.strip()]
    seen = set()
    out = []
    for part in parts:
        name = part.split()[0]
        seen.add(name)
        if name in GOOGLE_CSP:
            extra = GOOGLE_CSP[name].replace("'self' ", "") if "'self'" in part else GOOGLE_CSP[name]
            part = f"{part} {extra}"
        out.append(part)
    for name, value in GOOGLE_CSP.items():
        if name not in seen:
            out.append(f"{name} {value}")
    return "; ".join(out) + ";"


# ------------------------------------------------------------------ bannières directes

def banner_dir() -> str:
    path = os.path.join(_get_data_dir(), "pub")
    os.makedirs(path, exist_ok=True)
    return path


def banner_path(filename: str) -> str:
    return os.path.join(banner_dir(), os.path.basename(filename))


def save_banner(name: str, data: bytes) -> str:
    """Vérifie que c'est bien une image et l'enregistre sous « <emplacement>.<ext> ». Renvoie une erreur ou ""."""
    if name not in SLOTS:
        return "Emplacement inconnu."
    if not data or len(data) > BANNER_MAX_BYTES:
        return "Image vide ou trop lourde (2 Mo maximum)."
    from PIL import Image
    try:
        with Image.open(io.BytesIO(data)) as im:
            fmt = im.format
            im.verify()
    except Exception:
        return "Ce fichier n'est pas une image lisible."
    ext = BANNER_FORMATS.get(fmt or "")
    if not ext:
        return "Format refusé : PNG, JPEG, WebP ou GIF."
    for old in BANNER_TYPES:
        try:
            os.remove(banner_path(f"{name}.{old}"))
        except FileNotFoundError:
            pass
    with open(banner_path(f"{name}.{ext}"), "wb") as f:
        f.write(data)
    cfg = load()
    cfg["slots"][name]["image"] = f"{name}.{ext}"
    save(cfg)
    return ""


def remove_banner(name: str) -> None:
    cfg = load()
    image = cfg["slots"].get(name, {}).get("image")
    if image:
        try:
            os.remove(banner_path(image))
        except FileNotFoundError:
            pass
        cfg["slots"][name]["image"] = ""
        save(cfg)


def count_click(name: str) -> None:
    """Un clic de plus, sans rien savoir de la personne (ni IP, ni cookie)."""
    cfg = load()
    cfg["clicks"][name] = cfg["clicks"].get(name, 0) + 1
    save(cfg)
