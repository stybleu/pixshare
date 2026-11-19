"""Albums photo des membres : une page à partager par QR code (mariage, fête, sortie…).

* Seul un membre peut créer un album. Les invités qui ont le lien (ou le QR code) voient les photos et,
  si le membre l'autorise, ajoutent les leurs, sans compte.
* Les photos d'un album suivent la durée maximale du compte du membre (1 an par défaut).
* Les photos des invités passent par le même filtre que les visiteurs sans compte, et ne comptent jamais
  d'avertissement sur le compte du membre.
"""
from __future__ import annotations

import secrets
from datetime import timedelta

from flask import session
from werkzeug.security import check_password_hash, generate_password_hash

from pixshare.services.json_services import _json_lock, load_db, load_json, save_db, save_json
from pixshare.services.time_service import parse_dt, utcnow

ALBUMS_FILE = "albums.json"
NAME_MAX = 80
DESCRIPTION_MAX = 300
PASSWORD_MIN, PASSWORD_MAX = 4, 128
OWNER_UPLOADS_PER_HOUR = 300    # le membre qui remplit son album
HUMAN_CHECK_HOURS = 3           # anti-robot validé une fois pour une série d'envois


# Mises en page proposées (couleurs, police, petit symbole). Le membre peut ensuite changer la couleur
# principale, la police et choisir une photo de couverture.
THEMES = {
    "classique": {"label": "Classique", "emoji": "📷", "bg": "#f6f7fb", "card": "#ffffff", "text": "#1f2430",
                  "muted": "#6b7280", "accent": "#2563eb", "font": "moderne"},
    "mariage": {"label": "Mariage", "emoji": "💍", "bg": "#fbf7f0", "card": "#fffdf9", "text": "#3b3024",
                "muted": "#8a7a66", "accent": "#b08d57", "font": "elegante"},
    "anniversaire": {"label": "Anniversaire", "emoji": "🎂", "bg": "#fff4f8", "card": "#ffffff", "text": "#2d1b2e",
                     "muted": "#7c6a7d", "accent": "#e4578f", "font": "ronde"},
    "naissance": {"label": "Naissance, baptême", "emoji": "🍼", "bg": "#f2f8fc", "card": "#ffffff", "text": "#22313f",
                  "muted": "#6c7f8f", "accent": "#6aa9d8", "font": "ronde"},
    "hommage": {"label": "Hommage, obsèques", "emoji": "🕊️", "bg": "#f3f3f1", "card": "#fbfbfa", "text": "#2b2b2b",
                "muted": "#707070", "accent": "#5d6670", "font": "elegante"},
    "fete": {"label": "Fête, soirée", "emoji": "🎉", "bg": "#14121f", "card": "#1f1c2e", "text": "#f3f0ff",
             "muted": "#a9a3c7", "accent": "#a855f7", "font": "moderne"},
    "voyage": {"label": "Voyage, vacances", "emoji": "🌴", "bg": "#f1f7f6", "card": "#ffffff", "text": "#1d3331",
               "muted": "#5f7a77", "accent": "#0f9b8e", "font": "moderne"},
    "sport": {"label": "Sport, association", "emoji": "🏆", "bg": "#f4f6f2", "card": "#ffffff", "text": "#1d2a18",
              "muted": "#64735c", "accent": "#3f8f2f", "font": "moderne"},
}
FONTS = {
    "moderne": ("Moderne", "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"),
    "elegante": ("Élégante", "Georgia, 'Times New Roman', serif"),
    "manuscrite": ("Manuscrite", "'Segoe Script', 'Brush Script MT', 'Lucida Handwriting', cursive"),
    "ronde": ("Ronde", "'Trebuchet MS', 'Comic Sans MS', 'Segoe UI', sans-serif"),
}
LAYOUTS = {"grille": "Grille régulière", "mosaique": "Mosaïque (photos entières)"}
_COLOR = __import__("re").compile(r"^#[0-9a-fA-F]{6}$")


def style(album: dict) -> dict:
    """Mise en page de l'album : thème choisi, puis réglages du membre."""
    theme = THEMES.get(album.get("theme") or "", THEMES["classique"])
    font_key = album.get("font") if album.get("font") in FONTS else theme["font"]
    accent = album.get("accent") if _COLOR.match(str(album.get("accent") or "")) else theme["accent"]
    layout = album.get("layout") if album.get("layout") in LAYOUTS else "grille"
    return {**theme, "accent": accent, "font_key": font_key, "font_css": FONTS[font_key][1], "layout": layout,
            "key": album.get("theme") if album.get("theme") in THEMES else "classique"}


def set_style(album_id: str, theme=None, accent=None, font=None, layout=None, cover=None) -> dict:
    with _json_lock:
        data = _load()
        album = data.get(album_id)
        if not album:
            raise AlbumError("Album introuvable.")
        if theme in THEMES:
            if album.get("theme") != theme:
                album["accent"] = ""  # nouveau thème : sa couleur, sauf si le membre en rechoisit une
            album["theme"] = theme
        if accent is not None:
            album["accent"] = accent if _COLOR.match(str(accent)) else ""
        if font is not None:
            album["font"] = font if font in FONTS else ""
        if layout is not None:
            album["layout"] = layout if layout in LAYOUTS else "grille"
        if cover is not None:
            album["cover"] = cover if cover and any(m["id"] == cover for m in photos(album_id)) else ""
        data[album_id] = album
        save_json(ALBUMS_FILE, data)
        return album


# ------------------------------------------------------------------ animations : défis, livre d'or, réactions

REACTIONS = ("❤️", "😂", "😍", "👏", "🥹")
CHALLENGES_MAX = 12
CHALLENGE_MAX_LEN = 80
GUESTBOOK_FILE = "album_guestbook.json"
GUESTBOOK_MAX = 300
GUESTBOOK_TEXT_MAX = 500
SUGGESTED_CHALLENGES = {
    "mariage": ["Un éclat de rire", "Les mariés", "La plus belle tenue", "La décoration", "Sur la piste de danse",
                "Un selfie avec les mariés", "Le gâteau", "Un moment d'émotion"],
    "anniversaire": ["Le gâteau et les bougies", "Un fou rire", "Le plus beau cadeau", "Une photo de groupe",
                     "Un selfie avec la personne fêtée"],
    "naissance": ["Les petits pieds", "Un sourire", "La famille réunie", "Le doudou"],
    "hommage": ["Un souvenir partagé", "Une photo d'autrefois", "Un lieu qu'il ou elle aimait"],
    "fete": ["Sur la piste de danse", "La meilleure grimace", "Une photo de groupe", "Le cocktail du soir"],
    "voyage": ["Le plus beau paysage", "Le meilleur repas", "Une photo de groupe", "Un moment insolite"],
    "sport": ["L'action du jour", "L'équipe au complet", "La victoire", "Les supporters"],
    "classique": ["Une photo de groupe", "Un sourire", "Un moment drôle"],
}


def clean_challenges(raw) -> list[str]:
    lines = raw.splitlines() if isinstance(raw, str) else list(raw or [])
    out = []
    for line in lines:
        text = _clean_text(line, CHALLENGE_MAX_LEN)
        if text and text not in out:
            out.append(text)
    return out[:CHALLENGES_MAX]


def set_animations(album_id: str, challenges=None, guestbook=None, reactions=None) -> dict:
    with _json_lock:
        data = _load()
        album = data.get(album_id)
        if not album:
            raise AlbumError("Album introuvable.")
        if challenges is not None:
            album["challenges"] = clean_challenges(challenges)
        if guestbook is not None:
            album["guestbook"] = bool(guestbook)
        if reactions is not None:
            album["reactions"] = bool(reactions)
        data[album_id] = album
        save_json(ALBUMS_FILE, data)
        return album


def challenge_counts(album: dict, items: list[dict]) -> list[dict]:
    challenges = album.get("challenges") or []
    out = [{"index": i, "text": c, "count": 0} for i, c in enumerate(challenges)]
    for meta in items:
        i = meta.get("album_challenge")
        if isinstance(i, int) and 0 <= i < len(out) and meta.get("album_challenge_text") == out[i]["text"]:
            out[i]["count"] += 1
    return out


def photo_challenge(album: dict, meta: dict) -> str:
    """Texte du défi de la photo (vide si le défi a été retiré ou modifié depuis)."""
    challenges = album.get("challenges") or []
    i = meta.get("album_challenge")
    if isinstance(i, int) and 0 <= i < len(challenges) and meta.get("album_challenge_text") == challenges[i]:
        return challenges[i]
    return ""


def react(album: dict, file_id: str, emoji: str) -> dict | None:
    """Ajoute ou retire la réaction de cette personne (une par emoji et par photo). Renvoie les totaux."""
    if emoji not in REACTIONS or not album.get("reactions", True):
        return None
    mine = list(session.get("album_reacted") or [])
    key = f"{file_id}:{REACTIONS.index(emoji)}"
    db = load_db()
    meta = db.get(file_id)
    if not isinstance(meta, dict) or meta.get("album_id") != album["id"] or (meta.get("status") or "") != "active":
        return None
    counts = {e: int(n) for e, n in (meta.get("album_reactions") or {}).items() if e in REACTIONS}
    if key in mine:
        counts[emoji] = max(0, counts.get(emoji, 0) - 1)
        mine.remove(key)
    else:
        counts[emoji] = counts.get(emoji, 0) + 1
        mine = (mine + [key])[-500:]
    meta["album_reactions"] = {e: n for e, n in counts.items() if n}
    db[file_id] = meta
    save_db(db)
    session["album_reacted"] = mine
    return {"counts": meta["album_reactions"], "mine": [e for i, e in enumerate(REACTIONS) if f"{file_id}:{i}" in mine]}


def my_reactions(file_id: str) -> list[str]:
    mine = session.get("album_reacted") or []
    return [e for i, e in enumerate(REACTIONS) if f"{file_id}:{i}" in mine]


def _gb_load() -> dict:
    data = load_json(GUESTBOOK_FILE, {})
    return data if isinstance(data, dict) else {}


def guestbook(album_id: str) -> list[dict]:
    items = _gb_load().get(album_id) or []
    return sorted([m for m in items if isinstance(m, dict)], key=lambda m: m.get("at", ""), reverse=True)


def sign_guestbook(album: dict, name, text) -> dict:
    if not album.get("guestbook", True):
        raise AlbumError("Le livre d'or de cet album est fermé.")
    name = clean_contributor(name)
    text = " ".join(str(text or "").split())[:GUESTBOOK_TEXT_MAX]
    text = "".join(c for c in text if c not in "<>")
    if len(text) < 2:
        raise AlbumError("Écrivez quelques mots avant d'envoyer.")
    low = text.lower()
    if "http" in low or "www." in low or ".com" in low:
        raise AlbumError("Les liens ne sont pas acceptés dans le livre d'or.")
    with _json_lock:
        data = _gb_load()
        items = data.get(album["id"]) or []
        if len(items) >= GUESTBOOK_MAX:
            raise AlbumError("Le livre d'or est complet.")
        entry = {"id": secrets.token_urlsafe(6), "name": name, "text": text,
                 "at": utcnow().isoformat(timespec="seconds")}
        items.append(entry)
        data[album["id"]] = items
        save_json(GUESTBOOK_FILE, data)
    return entry


def remove_guestbook_entry(album_id: str, entry_id: str) -> bool:
    with _json_lock:
        data = _gb_load()
        items = data.get(album_id) or []
        kept = [m for m in items if m.get("id") != entry_id]
        if len(kept) == len(items):
            return False
        data[album_id] = kept
        save_json(GUESTBOOK_FILE, data)
        return True


def drop_guestbook(album_id: str) -> None:
    with _json_lock:
        data = _gb_load()
        if data.pop(album_id, None) is not None:
            save_json(GUESTBOOK_FILE, data)


class AlbumError(Exception):
    """Message à montrer tel quel à la personne."""


def enabled() -> bool:
    from pixshare.services.settings_service import load_settings
    return bool(load_settings().get("albums_enabled", True))


def limits(owner: dict | None) -> dict:
    """Limites des albums : réglages de l'admin, puis formule personnalisée du compte s'il en a une."""
    from pixshare.services.account_service import active_plan
    from pixshare.services.settings_service import load_settings
    s = load_settings()
    plan = active_plan(owner) if owner else {}
    return {
        "albums": int(plan["albums"]) if "albums" in plan else int(s.get("albums_per_member", 20)),
        "photos": int(s.get("album_max_photos", 500)),
        "mb": int(plan.get("album_mb") or s.get("album_max_mb", 200)),
        "guest_per_hour": int(s.get("album_guest_per_hour", 60)),
        "book_per_hour": int(s.get("album_guestbook_per_hour", 5)),
    }


def usage_bytes(album_id: str) -> int:
    """Place occupée sur le disque par les photos de l'album (en attente comprises)."""
    import os
    from flask import current_app
    folder = current_app.config["UPLOAD_FOLDER"]
    total = 0
    for meta in photos(album_id, include_pending=True):
        try:
            total += os.path.getsize(os.path.join(folder, os.path.basename(meta.get("server_name") or "")))
        except OSError:
            pass
    return total


def usage(album: dict, owner: dict | None = None) -> dict:
    lim = limits(owner)
    used = usage_bytes(album["id"])
    count = counts(album["id"])["total"]
    return {"mb": round(used / 1024 / 1024, 1), "max_mb": lim["mb"], "photos": count, "max_photos": lim["photos"],
            "pct": min(100, round(used * 100 / (lim["mb"] * 1024 * 1024))) if lim["mb"] else 0,
            "full": used >= lim["mb"] * 1024 * 1024 or count >= lim["photos"]}


def _clean_text(value, limit: int) -> str:
    text = " ".join(str(value or "").split())[:limit]
    return "".join(c for c in text if c not in "<>")


def _load() -> dict:
    data = load_json(ALBUMS_FILE, {})
    return data if isinstance(data, dict) else {}


def get(album_id: str) -> dict | None:
    album = _load().get(str(album_id or ""))
    return album if isinstance(album, dict) else None


def list_for(owner_id: str) -> list[dict]:
    albums = [a for a in _load().values() if isinstance(a, dict) and a.get("owner") == owner_id]
    return sorted(albums, key=lambda a: a.get("created_at", ""), reverse=True)


def create(owner: dict, name, description="", password="", guests_can_add=True, theme="classique") -> dict:
    name = _clean_text(name, NAME_MAX)
    if not name:
        raise AlbumError("Donnez un nom à l'album.")
    if not enabled():
        raise AlbumError("La création d'albums est suspendue pour le moment.")
    max_albums = limits(owner)["albums"]
    if len(list_for(owner["id"])) >= max_albums:
        raise AlbumError(f"Vous avez déjà {max_albums} album(s), le maximum pour votre compte : supprimez-en un pour en créer un autre."
                         if max_albums else "La création d'albums n'est pas ouverte pour votre compte.")
    password = str(password or "")
    if password and not PASSWORD_MIN <= len(password) <= PASSWORD_MAX:
        raise AlbumError(f"Le mot de passe de l'album doit faire entre {PASSWORD_MIN} et {PASSWORD_MAX} caractères.")
    with _json_lock:
        data = _load()
        album_id = secrets.token_urlsafe(8)
        while album_id in data:
            album_id = secrets.token_urlsafe(8)
        album = {
            "id": album_id,
            "owner": owner["id"],
            "name": name,
            "description": _clean_text(description, DESCRIPTION_MAX),
            "created_at": utcnow().isoformat(timespec="seconds"),
            "guests_can_add": bool(guests_can_add),
            "password_hash": generate_password_hash(password) if password else "",
            "theme": theme if theme in THEMES else "classique",
            "accent": "", "font": "", "layout": "grille", "cover": "",
            "challenges": list(SUGGESTED_CHALLENGES.get(theme if theme in THEMES else "classique", [])),
            "guestbook": True, "reactions": True,
        }
        data[album_id] = album
        save_json(ALBUMS_FILE, data)
    return album


def update(album_id: str, *, name=None, description=None, guests_can_add=None, password=None,
           remove_password=False) -> dict:
    with _json_lock:
        data = _load()
        album = data.get(album_id)
        if not album:
            raise AlbumError("Album introuvable.")
        if name is not None:
            clean = _clean_text(name, NAME_MAX)
            if not clean:
                raise AlbumError("Donnez un nom à l'album.")
            album["name"] = clean
        if description is not None:
            album["description"] = _clean_text(description, DESCRIPTION_MAX)
        if guests_can_add is not None:
            album["guests_can_add"] = bool(guests_can_add)
        if remove_password:
            album["password_hash"] = ""
        elif password:
            if not PASSWORD_MIN <= len(password) <= PASSWORD_MAX:
                raise AlbumError(f"Le mot de passe de l'album doit faire entre {PASSWORD_MIN} et {PASSWORD_MAX} caractères.")
            album["password_hash"] = generate_password_hash(password)
        data[album_id] = album
        save_json(ALBUMS_FILE, data)
        return album


def photos(album_id: str, include_pending: bool = False) -> list[dict]:
    """Photos de l'album (les plus anciennes d'abord), sans celles expirées ou supprimées."""
    now = utcnow()
    out = []
    for file_id, meta in load_db().items():
        if not isinstance(meta, dict) or meta.get("album_id") != album_id:
            continue
        status = (meta.get("status") or "").lower()
        if status not in ("active", "pending") or (status == "pending" and not include_pending):
            continue
        try:
            if meta.get("expires_at") and parse_dt(meta["expires_at"]) <= now:
                continue
        except Exception:
            pass
        out.append({**meta, "id": file_id})
    return sorted(out, key=lambda m: m.get("uploaded_at", ""))


def counts(album_id: str) -> dict:
    items = photos(album_id, include_pending=True)
    active = sum(1 for m in items if (m.get("status") or "") == "active")
    return {"active": active, "pending": len(items) - active, "total": len(items)}


def delete(album_id: str) -> int:
    """Supprime l'album et toutes ses photos (celles des invités comprises)."""
    from pixshare.services.file_service import delete_by_id
    removed = 0
    for meta in photos(album_id, include_pending=True):
        if delete_by_id(meta["id"], reason="album_deleted"):
            removed += 1
    with _json_lock:
        data = _load()
        data.pop(album_id, None)
        save_json(ALBUMS_FILE, data)
    drop_guestbook(album_id)
    return removed


def delete_all_for(owner_id: str) -> int:
    return sum(delete(a["id"]) for a in list_for(owner_id))


# ------------------------------------------------------------------ accès

def is_owner(album: dict, account: dict | None) -> bool:
    return bool(account and album and account.get("id") == album.get("owner"))


def unlocked(album: dict, account: dict | None = None) -> bool:
    from pixshare.services.auth_service import is_admin
    if not album.get("password_hash") or is_owner(album, account) or is_admin():
        return True
    return album["id"] in (session.get("albums_ok") or [])


def unlock(album: dict, password: str) -> bool:
    if not album.get("password_hash") or not check_password_hash(album["password_hash"], password or ""):
        return False
    ok = list(session.get("albums_ok") or [])
    if album["id"] not in ok:
        ok = (ok + [album["id"]])[-50:]
    session["albums_ok"] = ok
    return True


def human_checked(album_id: str) -> bool:
    stamp = (session.get("albums_human") or {}).get(album_id)
    try:
        return bool(stamp) and utcnow() - parse_dt(stamp) < timedelta(hours=HUMAN_CHECK_HOURS)
    except Exception:
        return False


def mark_human(album_id: str) -> None:
    marks = dict(session.get("albums_human") or {})
    marks[album_id] = utcnow().isoformat(timespec="seconds")
    session["albums_human"] = dict(list(marks.items())[-20:])


# ------------------------------------------------------------------ ajout d'une photo

CONTRIBUTOR_MAX = 40


def clean_contributor(value) -> str:
    return _clean_text(value, CONTRIBUTOR_MAX)


def contributors(items: list[dict]) -> list[tuple[str, int]]:
    """Noms des personnes qui ont ajouté des photos, avec leur nombre (pour filtrer l'album)."""
    counts_by_name: dict[str, int] = {}
    for meta in items:
        name = meta.get("album_contributor") or ""
        if name:
            counts_by_name[name] = counts_by_name.get(name, 0) + 1
    return sorted(counts_by_name.items(), key=lambda kv: (-kv[1], kv[0].lower()))


def finalize_photo(file_id: str, album: dict, owner: dict, by_owner: bool, contributor: str = "",
                   challenge: int | None = None) -> None:
    """Rattache la photo à l'album et lui donne la durée maximale du compte du membre."""
    from pixshare.services.settings_service import get_max_lifetime
    lifetime = get_max_lifetime(owner)
    db = load_db()
    meta = db.get(file_id)
    if not isinstance(meta, dict):
        return
    meta["album_id"] = album["id"]
    meta["album_owner"] = owner["id"]
    meta["album_guest"] = not by_owner
    meta["album_contributor"] = clean_contributor(contributor)
    challenges = album.get("challenges") or []
    if isinstance(challenge, int) and 0 <= challenge < len(challenges):
        meta["album_challenge"] = challenge
        meta["album_challenge_text"] = challenges[challenge]
    try:
        start = parse_dt(meta.get("uploaded_at") or "")
        meta["expires_at"] = (start + timedelta(minutes=int(lifetime))).isoformat(timespec="seconds")
        meta["permanent"] = False
    except Exception:
        pass
    db[file_id] = meta
    save_db(db)


def room_left(album_id: str, owner: dict | None = None) -> int:
    return max(0, limits(owner)["photos"] - counts(album_id)["total"])


def bytes_left(album_id: str, owner: dict | None = None) -> int:
    return max(0, limits(owner)["mb"] * 1024 * 1024 - usage_bytes(album_id))
