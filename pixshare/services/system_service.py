import os

try:
    import psutil
except Exception:
    psutil = None


_HUGE = 1 << 50  # « pas de limite » dans les cgroups


def _read_int(path):
    try:
        with open(path) as f:
            raw = f.read().strip()
        return None if raw in ("", "max") else int(raw)
    except Exception:
        return None


def _inactive_file(stat_path):
    """Cache disque récupérable (non compté, comme le fait Render/Kubernetes)."""
    try:
        with open(stat_path) as f:
            for line in f:
                key, _, value = line.partition(" ")
                if key in ("inactive_file", "total_inactive_file"):
                    return int(value)
    except Exception:
        pass
    return 0


def get_ram_limit_bytes():
    """Limite de RAM réelle du service (formule Render : 512 Mo en Starter).

    Lue dans le conteneur (cgroup v2 puis v1) ; sinon variable RAM_LIMIT_MB ; sinon 512 Mo.
    """
    for path in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        value = _read_int(path)
        if value and value < _HUGE:
            return value
    try:
        return int(float(os.environ.get("RAM_LIMIT_MB", "512")) * 1024 * 1024)
    except ValueError:
        return 512 * 1024 * 1024


def get_container_ram_usage():
    """Mémoire utilisée par tout le service (tous les processus), comparée à la limite de la formule."""
    limit = get_ram_limit_bytes()
    used = None
    for current, stat in (("/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory.stat"),
                          ("/sys/fs/cgroup/memory/memory.usage_in_bytes", "/sys/fs/cgroup/memory/memory.stat")):
        value = _read_int(current)
        if value is not None:
            used = max(0, value - _inactive_file(stat))
            break
    source = "conteneur"
    if used is None and psutil is not None:
        try:  # hors conteneur : somme des processus de l'appli (ce processus et ses enfants)
            me = psutil.Process(os.getpid())
            used = me.memory_info().rss + sum(c.memory_info().rss for c in me.children(recursive=True))
            source = "processus"
        except Exception:
            used = None
    if used is None:
        return {"ok": False, "error": "mesure impossible"}
    percent = round(100 * used / limit, 1) if limit else None
    return {
        "ok": True,
        "used_mb": round(used / (1024 * 1024), 1),
        "limit_mb": round(limit / (1024 * 1024)),
        "available_mb": round(max(0, limit - used) / (1024 * 1024), 1),
        "percent": percent,
        "source": source,
    }


def get_process_ram_usage():
    if psutil is None:
        return {
            "ok": False,
            "rss_mb": None,
            "vms_mb": None,
            "percent": None,
            "error": "psutil non installé",
        }

    try:
        process = psutil.Process(os.getpid())
        mem_info = process.memory_info()
        rss_mb = round(mem_info.rss / (1024 * 1024), 1)
        vms_mb = round(mem_info.vms / (1024 * 1024), 1)

        # Pourcentage de la limite de la formule Render (pas de la RAM de toute la machine).
        limit = get_ram_limit_bytes()
        percent = round((mem_info.rss / limit) * 100, 1) if limit else None

        return {
            "ok": True,
            "rss_mb": rss_mb,
            "vms_mb": vms_mb,
            "percent": percent,
        }
    except Exception as e:
        return {
            "ok": False,
            "rss_mb": None,
            "vms_mb": None,
            "percent": None,
            "error": str(e),
        }


def get_system_ram_usage():
    if psutil is None:
        return {
            "ok": False,
            "total_mb": None,
            "used_mb": None,
            "available_mb": None,
            "percent": None,
            "error": "psutil non installé",
        }

    try:
        mem = psutil.virtual_memory()
        return {
            "ok": True,
            "total_mb": round(mem.total / (1024 * 1024), 1),
            "used_mb": round(mem.used / (1024 * 1024), 1),
            "available_mb": round(mem.available / (1024 * 1024), 1),
            "percent": round(mem.percent, 1),
        }
    except Exception as e:
        return {
            "ok": False,
            "total_mb": None,
            "used_mb": None,
            "available_mb": None,
            "percent": None,
            "error": str(e),
        }


def get_storage_usage():
    """Place du stockage des images (disque persistant s'il y en a un)."""
    import shutil

    from flask import current_app

    try:
        usage = shutil.disk_usage(current_app.config["UPLOAD_FOLDER"])
        return {
            "ok": True,
            "persistent": bool(current_app.config.get("PERSISTENT_DIR")),
            "total_mb": round(usage.total / (1024 * 1024), 1),
            "used_mb": round(usage.used / (1024 * 1024), 1),
            "free_mb": round(usage.free / (1024 * 1024), 1),
            "percent": round(100 * usage.used / usage.total, 1) if usage.total else None,
        }
    except Exception as e:
        return {"ok": False, "persistent": False, "error": str(e)}


def has_room_for(size_bytes: int | None) -> bool:
    """Assez de place pour cet envoi en gardant la réserve DISK_RESERVE_MB ?"""
    import shutil

    from flask import current_app

    try:
        free = shutil.disk_usage(current_app.config["UPLOAD_FOLDER"]).free
    except Exception:
        return True
    reserve = int(current_app.config.get("DISK_RESERVE_MB", 50)) * 1024 * 1024
    return free - int(size_bytes or 0) > reserve


def get_system_stats():
    return {
        "process_ram": get_process_ram_usage(),
        "system_ram": get_system_ram_usage(),
        "container_ram": get_container_ram_usage(),
        "storage": get_storage_usage(),
    }

# ------------------------------------------------------------------ contenu du disque

_DESCRIPTIONS = {
    "fichiers": "Images et fichiers envoyés (originaux + aperçus)",
    "mod_thumbs": "Miniatures de modération (effacées après un court délai)",
    "translations": "Textes du site (français, anglais)",
    "geoip": "Ancienne base de localisation (à effacer)",
    "lost+found": "Dossier du système de fichiers (normal, à laisser)",
    "files.json": "Liste des fichiers envoyés",
    "settings.json": "Réglages de l'admin",
    "accounts.json": "Comptes membres",
    "visitor_stats.json": "Statistiques de visite (sans IP)",
    "nsfw_stats.json": "Statistiques de NudeNet",
    "banned_images.json": "Empreintes des images refusées",
    "auto_block_history.json": "Historique des blocages automatiques",
    "auto_block_offenses.json": "Images refusées par IP (24 h)",
    "blocked_ips.json": "IP bloquées",
    "blocked_ips_info.json": "Durée et motif des blocages d'IP",
    "messages.json": "Messages du formulaire de contact",
    "contacts.json": "Messages du formulaire de contact",
    "reports.json": "Signalements",
    "moderation.json": "Journal de modération",
    "moderation_notices.json": "Messages de modération à afficher",
    "thumbnails.json": "Liste des miniatures",
    "failed_logins.json": "Essais de connexion ratés",
    "image_usage.json": "Compteurs d'utilisation des images",
    "views.json": "Compteurs de vues",
    "logs.json": "Journal technique",
    "history.json": "Historique",
}
_MAX_FILES = 50000  # au-delà, on arrête de compter (disque énorme)


def _kind(name: str) -> str:
    if name.endswith("_m.webp"):
        return "aperçus .webp"
    ext = os.path.splitext(name)[1].lower().lstrip(".")
    return f".{ext}" if ext else "sans extension"


def _folder_summary(path: str, budget: list) -> dict:
    size = count = 0
    newest = 0.0
    kinds: dict = {}
    subdirs = 0
    for current, dirs, files in os.walk(path):
        subdirs += len(dirs)
        for name in files:
            if budget[0] <= 0:
                return {"size": size, "count": count, "newest": newest, "kinds": kinds, "subdirs": subdirs, "partial": True}
            budget[0] -= 1
            try:
                st = os.stat(os.path.join(current, name))
            except OSError:
                continue
            size += st.st_size
            count += 1
            newest = max(newest, st.st_mtime)
            k = kinds.setdefault(_kind(name), {"count": 0, "size": 0})
            k["count"] += 1
            k["size"] += st.st_size
    return {"size": size, "count": count, "newest": newest, "kinds": kinds, "subdirs": subdirs, "partial": False}


def _human(size: int) -> str:
    for unit in ("o", "Ko", "Mo", "Go"):
        if size < 1024 or unit == "Go":
            return f"{size:.0f} {unit}" if unit == "o" else f"{size:.1f} {unit}".replace(".", ",")
        size /= 1024
    return str(size)


def get_disk_contents() -> dict:
    """Contenu du disque persistant, dossier par dossier (tailles et nombres de fichiers,
    jamais le nom des fichiers envoyés par les visiteurs)."""
    from datetime import datetime

    from flask import current_app

    from pixshare.services.json_services import _get_data_dir

    root = (current_app.config.get("PERSISTENT_DIR") or "").strip() or _get_data_dir()
    try:
        names = sorted(os.listdir(root))
    except OSError as e:
        return {"ok": False, "root": root, "error": str(e)}

    from zoneinfo import ZoneInfo

    def when(ts: float) -> str:  # heure de Paris (le serveur Render est en UTC)
        return datetime.fromtimestamp(ts, ZoneInfo("Europe/Paris")).strftime("%d/%m/%Y %H:%M") if ts else ""

    budget = [_MAX_FILES]
    folders, files = [], []
    total = 0
    for name in names:
        path = os.path.join(root, name)
        if os.path.islink(path):
            continue
        if os.path.isdir(path):
            info = _folder_summary(path, budget)
            kinds = sorted(info["kinds"].items(), key=lambda kv: -kv[1]["size"])
            folders.append({
                "name": name, "desc": _DESCRIPTIONS.get(name, ""), "size": info["size"], "size_h": _human(info["size"]),
                "count": info["count"], "subdirs": info["subdirs"], "newest": when(info["newest"]), "partial": info["partial"],
                "kinds": [{"name": k, "count": v["count"], "size_h": _human(v["size"])} for k, v in kinds],
            })
            total += info["size"]
        else:
            try:
                st = os.stat(path)
            except OSError:
                continue
            files.append({"name": name, "desc": _DESCRIPTIONS.get(name, ""), "size": st.st_size,
                          "size_h": _human(st.st_size), "newest": when(st.st_mtime)})
            total += st.st_size
    folders.sort(key=lambda f: -f["size"])
    files.sort(key=lambda f: -f["size"])
    for item in folders + files:
        item["pct"] = round(100 * item["size"] / total, 1) if total else 0
    return {"ok": True, "root": root, "folders": folders, "files": files, "total_h": _human(total),
            "files_total_h": _human(sum(f["size"] for f in files)), "partial": budget[0] <= 0}


# ------------------------------------------------------------------ explorateur (lecture seule)

EXPLORER_PAGE = 200


def disk_root() -> str:
    from flask import current_app

    from pixshare.services.json_services import _get_data_dir

    return os.path.realpath((current_app.config.get("PERSISTENT_DIR") or "").strip() or _get_data_dir())


def resolve_disk_path(rel: str) -> str | None:
    """Chemin réel dans le disque, ou None s'il sort du disque (../, lien symbolique…)."""
    root = disk_root()
    rel = (rel or "").replace("\\", "/").strip("/")
    path = os.path.realpath(os.path.join(root, rel))
    try:
        if os.path.commonpath([root, path]) != root:
            return None
    except ValueError:
        return None
    return path if os.path.exists(path) else None


def list_disk_dir(rel: str, sort: str = "nom", page: int = 1) -> dict | None:
    from datetime import datetime
    from zoneinfo import ZoneInfo

    from flask import current_app

    from pixshare.services.json_services import load_db

    path = resolve_disk_path(rel)
    if not path or not os.path.isdir(path):
        return None
    root = disk_root()
    rel = os.path.relpath(path, root).replace(os.sep, "/")
    rel = "" if rel == "." else rel
    tz = ZoneInfo("Europe/Paris")
    uploads = os.path.realpath(current_app.config["UPLOAD_FOLDER"])
    db = load_db() if path == uploads else {}

    dirs, files = [], []
    budget = [_MAX_FILES]
    for name in os.listdir(path):
        full = os.path.join(path, name)
        if os.path.islink(full):
            continue
        try:
            st = os.stat(full)
        except OSError:
            continue
        item = {"name": name, "rel": f"{rel}/{name}".strip("/"), "mtime": st.st_mtime,
                "date": datetime.fromtimestamp(st.st_mtime, tz).strftime("%d/%m/%Y %H:%M"),
                "desc": _DESCRIPTIONS.get(name, "") if not rel else ""}
        if os.path.isdir(full):
            info = _folder_summary(full, budget)
            item.update(size=info["size"], count=info["count"], partial=info["partial"])
            dirs.append(item)
        else:
            item.update(size=st.st_size, kind=_kind(name))
            if db:
                stem = os.path.splitext(name)[0]
                file_id = stem[:-2] if stem.endswith("_m") else stem
                meta = db.get(file_id)
                if isinstance(meta, dict):
                    expires = ""
                    try:
                        from pixshare.services.time_service import parse_dt
                        expires = parse_dt(meta.get("expires_at") or "").astimezone(tz).strftime("%d/%m/%Y %H:%M")
                    except Exception:
                        pass
                    item.update(file_id=file_id, original=meta.get("original_name", ""),
                                status=(meta.get("status") or "active"), expires=expires,
                                preview=stem.endswith("_m"))
                else:
                    item["orphan"] = True
            files.append(item)

    keys = {"taille": lambda i: -i["size"], "date": lambda i: -i["mtime"]}
    key = keys.get(sort, lambda i: i["name"].lower())
    dirs.sort(key=key)
    files.sort(key=key)
    for item in dirs + files:
        item["size_h"] = _human(item["size"])

    pages = max(1, -(-len(files) // EXPLORER_PAGE))
    page = max(1, min(int(page or 1), pages))
    crumbs = []
    acc = ""
    for part in [p for p in rel.split("/") if p]:
        acc = f"{acc}/{part}".strip("/")
        crumbs.append({"name": part, "rel": acc})
    return {
        "rel": rel, "root": root, "crumbs": crumbs, "parent": "/".join(rel.split("/")[:-1]) if rel else None,
        "dirs": dirs, "files": files[(page - 1) * EXPLORER_PAGE: page * EXPLORER_PAGE], "file_count": len(files),
        "page": page, "pages": pages, "sort": sort if sort in keys else "nom",
        "total_h": _human(sum(i["size"] for i in dirs + files)), "partial": budget[0] <= 0,
        "is_uploads": path == uploads,
    }
