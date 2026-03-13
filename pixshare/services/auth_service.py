import time
from functools import wraps
from flask import current_app, flash, redirect, session, url_for
from .json_services import load_failed_logins, save_failed_logins
from .request_service import get_client_ip


def _now_ts() -> int:
    return int(time.time())


def is_admin() -> bool:
    return bool(session.get("is_admin"))


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_admin():
            flash("Connexion admin requise.", "warning")
            return redirect(url_for("admin.admin_login"))
        return fn(*args, **kwargs)
    return wrapper


def cleanup_failed_logins(data: dict) -> dict:
    now = _now_ts()
    out = {}
    for ip, rec in data.items():
        if not isinstance(rec, dict):
            continue
        locked_until = int(rec.get("locked_until", 0) or 0)
        first_fail = int(rec.get("first_fail", 0) or 0)
        last_fail = int(rec.get("last_fail", 0) or 0)
        in_lock = locked_until > now
        in_window = (now - last_fail) <= current_app.config["FAILED_WINDOW_SEC"] and first_fail > 0
        if in_lock or in_window:
            out[ip] = {
                "count": int(rec.get("count", 0) or 0),
                "first_fail": first_fail,
                "last_fail": last_fail,
                "locked_until": locked_until,
            }
    return out


def is_admin_locked(ip: str) -> tuple[bool, int]:
    data = cleanup_failed_logins(load_failed_logins())
    now = _now_ts()
    rec = data.get(ip, {})
    locked_until = int(rec.get("locked_until", 0) or 0)
    if locked_until > now:
        save_failed_logins(data)
        return True, locked_until - now
    save_failed_logins(data)
    return False, 0


def register_admin_fail(ip: str) -> tuple[int, int]:
    now = _now_ts()
    data = cleanup_failed_logins(load_failed_logins())
    rec = data.get(ip)
    if not isinstance(rec, dict):
        rec = {"count": 0, "first_fail": 0, "last_fail": 0, "locked_until": 0}

    last_fail = int(rec.get("last_fail", 0) or 0)
    if last_fail == 0 or (now - last_fail) > current_app.config["FAILED_WINDOW_SEC"]:
        rec["count"] = 0
        rec["first_fail"] = now

    rec["count"] = int(rec.get("count", 0) or 0) + 1
    rec["last_fail"] = now

    lock_remaining = 0
    if rec["count"] >= current_app.config["MAX_FAILED_LOGINS"]:
        rec["locked_until"] = now + current_app.config["LOCKOUT_SEC"]
        lock_remaining = current_app.config["LOCKOUT_SEC"]

    data[ip] = rec
    save_failed_logins(data)
    return rec["count"], lock_remaining


def reset_admin_fail(ip: str) -> None:
    data = load_failed_logins()
    data.pop(ip, None)
    save_failed_logins(data)


def process_admin_login(username: str, password: str) -> tuple[bool, int | None]:
    ip = get_client_ip()
    locked, _secs = is_admin_locked(ip)
    if locked:
        return False, 429

    if username == current_app.config["ADMIN_USER"] and password == current_app.config["ADMIN_PASS"]:
        reset_admin_fail(ip)
        session["is_admin"] = True
        return True, None

    time.sleep(0.6)
    _count, lock_sec = register_admin_fail(ip)
    if lock_sec > 0:
        return False, 429
    return False, 401
