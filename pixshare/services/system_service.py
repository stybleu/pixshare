import os

try:
    import psutil
except Exception:
    psutil = None


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

        percent = None
        try:
            total_mem = psutil.virtual_memory().total
            if total_mem:
                percent = round((mem_info.rss / total_mem) * 100, 1)
        except Exception:
            percent = None

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
        "storage": get_storage_usage(),
    }