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