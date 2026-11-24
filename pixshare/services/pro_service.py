"""Espace entreprise (essai) : machines, interventions et photos de maintenance.

- Entièrement privé : seuls les comptes autorisés y accèdent (voir `allowed()`).
- Aucune expiration : rien n'est supprimé automatiquement.
- Tout est chiffré sur le disque (pro_crypto) : les photos (dossier pro/) et les données
  (machines, interventions, commentaires) gardées dans le document pro_data.json.
- Séparé du site public : autre dossier, autre document, pas de modération publique, pas de lien public.
"""
from __future__ import annotations

import io
import os
import secrets
import threading
from datetime import datetime, timezone

from PIL import Image, ImageOps

from . import pro_crypto

DOC = "pro_data.json"
MAX_PHOTOS = 30            # par intervention
MAX_SIDE = 2560            # photos réduites à 2560 px de côté (largement assez pour un rapport)
KINDS = ("avant", "apres", "autre")
_lock = threading.Lock()

try:  # photos HEIC des iPhone
    from pillow_heif import register_heif_opener
    register_heif_opener()
except Exception:
    pass


# ------------------------------------------------------------------ accès

def enterprise_mode() -> bool:
    from flask import current_app
    return bool(current_app.config.get("ENTERPRISE_MODE"))


def allowed() -> bool:
    """Qui peut ouvrir l'espace entreprise ?
    - Mode entreprise (site séparé) : les comptes actifs de l'entreprise. L'admin du site (l'hébergeur)
      n'y a PAS accès (secret professionnel), SAUF si un responsable de l'entreprise lui ouvre un accès
      de dépannage limité dans le temps ; chacun de ses passages est alors noté dans un journal que
      l'entreprise peut lire.
    - Sur pixshare.fr (essai) : l'admin seulement, pour tester avec ses propres photos."""
    from .account_service import current_account
    from .auth_service import is_admin
    if not enterprise_mode():
        return is_admin()
    rec = current_account()
    if rec and rec.get("status") == "active":
        return True
    return is_admin() and support_open()


def is_manager() -> bool:
    """Responsable (dirigeant) de l'entreprise : adresses listées dans ENTERPRISE_MANAGERS."""
    from flask import current_app
    from .account_service import current_account
    rec = current_account()
    if not rec or rec.get("status") != "active":
        return False
    managers = {e.strip().lower() for e in str(current_app.config.get("ENTERPRISE_MANAGERS") or "").split(",") if e.strip()}
    return str(rec.get("email") or "").lower() in managers


def support_open() -> bool:
    until = load().get("support_until") or ""
    return bool(until) and until > _now()


def set_support(hours: int) -> str:
    """Le responsable ouvre (hours > 0) ou ferme (0) l'accès de dépannage de l'hébergeur."""
    from datetime import timedelta
    hours = max(0, min(int(hours or 0), 72))
    until = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat(timespec="seconds") if hours else ""
    with _lock:
        data = load()
        data["support_until"] = until
        data.setdefault("journal", []).append({"at": _now(), "who": who(),
                                               "what": f"accès de dépannage ouvert {hours} h" if hours else "accès de dépannage fermé"})
        data["journal"] = data["journal"][-500:]
        _save(data)
    return until


def note_support_visit(path: str) -> None:
    """Chaque page vue par l'hébergeur pendant un accès de dépannage est notée."""
    from .auth_service import is_admin
    from .account_service import current_account
    if not (enterprise_mode() and is_admin() and not current_account()):
        return
    with _lock:
        data = load()
        data.setdefault("journal", []).append({"at": _now(), "who": "hébergeur (dépannage)", "what": path[:200]})
        data["journal"] = data["journal"][-500:]
        _save(data)


def journal() -> list[dict]:
    return list(reversed(load().get("journal", [])))


def who() -> str:
    from .account_service import current_account
    from .auth_service import is_admin
    rec = current_account()
    if rec:
        return str(rec.get("email") or rec.get("id"))
    return "admin (essai)" if is_admin() else ""


# ------------------------------------------------------------------ stockage chiffré

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id() -> str:
    return secrets.token_urlsafe(9)


def _photo_dir() -> str:
    from .json_services import _get_data_dir
    path = os.path.join(_get_data_dir(), "pro")
    os.makedirs(path, exist_ok=True)
    return path


def load() -> dict:
    from .json_services import load_json
    stored = load_json(DOC, {}) or {}
    data = pro_crypto.decrypt_json(stored["enc"], "pro-data") if stored.get("enc") else {}
    data.setdefault("machines", {})
    data.setdefault("interventions", {})
    return data


def _save(data: dict) -> None:
    from .json_services import save_json
    save_json(DOC, {"v": 1, "enc": pro_crypto.encrypt_json(data, "pro-data")})


# ------------------------------------------------------------------ machines

def create_machine(name: str, location: str = "") -> dict:
    name = (name or "").strip()[:80]
    if not name:
        raise ValueError("Donnez un nom à la machine.")
    machine = {"id": _new_id(), "name": name, "location": (location or "").strip()[:120],
               "created_at": _now(), "created_by": who()}
    with _lock:
        data = load()
        data["machines"][machine["id"]] = machine
        _save(data)
    return machine


def machines() -> list[dict]:
    data = load()
    out = []
    for m in data["machines"].values():
        items = [i for i in data["interventions"].values() if i["machine_id"] == m["id"]]
        out.append(dict(m, count=len(items), last=max((i["created_at"] for i in items), default="")))
    return sorted(out, key=lambda m: (m["last"] or m["created_at"]), reverse=True)


def machine(machine_id: str) -> dict | None:
    return load()["machines"].get(machine_id)


def history(machine_id: str) -> list[dict]:
    items = [i for i in load()["interventions"].values() if i["machine_id"] == machine_id]
    return sorted(items, key=lambda i: i["created_at"], reverse=True)


def recent(limit: int = 10) -> list[dict]:
    data = load()
    items = sorted(data["interventions"].values(), key=lambda i: i["created_at"], reverse=True)[:limit]
    return [dict(i, machine_name=data["machines"].get(i["machine_id"], {}).get("name", "?")) for i in items]


# ------------------------------------------------------------------ photos

def _prepare_photo(file_storage) -> tuple[bytes, int, int]:
    """Vraie image seulement ; remise dans le bon sens ; réduite ; JPEG sans métadonnées (ni GPS ni appareil)."""
    from .file_service import detect_media_kinds
    stream = file_storage.stream
    head = stream.read(32)
    stream.seek(0)
    if "image" not in detect_media_kinds(head):
        raise ValueError(f"« {file_storage.filename} » n'est pas une photo.")
    with Image.open(stream) as src:
        img = ImageOps.exif_transpose(src) or src.copy()
        img = img.convert("RGB")
        img.thumbnail((MAX_SIDE, MAX_SIDE), Image.LANCZOS)
        out = io.BytesIO()
        img.save(out, "JPEG", quality=88, optimize=True)
        return out.getvalue(), img.width, img.height


def _store_photo(jpeg: bytes) -> str:
    photo_id = _new_id()
    with open(os.path.join(_photo_dir(), f"{photo_id}.bin"), "wb") as fh:
        fh.write(pro_crypto.encrypt(jpeg, f"photo:{photo_id}"))
    return photo_id


def photo_bytes(photo_id: str, size: int | None = None) -> bytes:
    if not photo_id.replace("-", "").replace("_", "").isalnum():
        raise FileNotFoundError(photo_id)
    with open(os.path.join(_photo_dir(), f"{photo_id}.bin"), "rb") as fh:
        jpeg = pro_crypto.decrypt(fh.read(), f"photo:{photo_id}")
    if not size:
        return jpeg
    with Image.open(io.BytesIO(jpeg)) as img:
        img.thumbnail((size, size), Image.LANCZOS)
        out = io.BytesIO()
        img.convert("RGB").save(out, "JPEG", quality=80)
        return out.getvalue()


def photo_owner(photo_id: str) -> dict | None:
    for item in load()["interventions"].values():
        if any(p["id"] == photo_id for p in item["photos"]):
            return item
    return None


# ------------------------------------------------------------------ interventions

def create_intervention(machine_id: str, ref: str, comment: str, files_by_kind: dict) -> dict:
    if not machine(machine_id):
        raise ValueError("Machine introuvable.")
    uploads = [(kind, f) for kind in KINDS for f in files_by_kind.get(kind, []) if f and f.filename]
    if not uploads and not (comment or "").strip():
        raise ValueError("Ajoutez au moins une photo ou un commentaire.")
    if len(uploads) > MAX_PHOTOS:
        raise ValueError(f"{MAX_PHOTOS} photos au maximum par intervention.")
    photos, written = [], []
    try:
        for kind, f in uploads:
            jpeg, w, h = _prepare_photo(f)
            pid = _store_photo(jpeg)
            written.append(pid)
            photos.append({"id": pid, "kind": kind, "w": w, "h": h, "name": os.path.basename(f.filename)[:120]})
    except Exception:
        for pid in written:      # rien à moitié : on efface ce qui a déjà été écrit
            try:
                os.remove(os.path.join(_photo_dir(), f"{pid}.bin"))
            except OSError:
                pass
        raise
    item = {"id": _new_id(), "machine_id": machine_id, "ref": (ref or "").strip()[:60],
            "comment": (comment or "").strip()[:4000], "created_at": _now(), "author": who(), "photos": photos}
    with _lock:
        data = load()
        data["interventions"][item["id"]] = item
        _save(data)
    from .legal_log_service import CREATION, record as legal_record
    legal_record(CREATION, f"pro/{item['id']}")
    return item


def intervention(intervention_id: str) -> dict | None:
    data = load()
    item = data["interventions"].get(intervention_id)
    if item:
        item = dict(item, machine=data["machines"].get(item["machine_id"], {}))
    return item
