import hmac
import logging
import time
from functools import wraps

from flask import current_app, flash, redirect, session, url_for

from .json_services import load_failed_logins, save_failed_logins
from .request_service import get_client_ip

_log = logging.getLogger(__name__)

# Clé du compteur global (toutes IP confondues) dans failed_logins.json.
_GLOBAL_KEY = "__global__"


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


# ---------------------------------------------------------------------------
# Limiteur d'essais (réutilisable : admin, connexion API...)
# ---------------------------------------------------------------------------

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


def is_locked(key: str) -> tuple[bool, int]:
    """Indique si ``key`` (une IP, ou un préfixe + IP) est verrouillée."""
    data = cleanup_failed_logins(load_failed_logins())
    now = _now_ts()
    locked_until = int(data.get(key, {}).get("locked_until", 0) or 0)
    save_failed_logins(data)
    if locked_until > now:
        return True, locked_until - now
    return False, 0


def register_fail(key: str, max_failures: int | None = None) -> tuple[int, int]:
    """Enregistre un échec pour ``key`` ; retourne (nb d'échecs, secondes de verrou)."""
    now = _now_ts()
    limit = max_failures or current_app.config["MAX_FAILED_LOGINS"]
    data = cleanup_failed_logins(load_failed_logins())
    rec = data.get(key)
    if not isinstance(rec, dict):
        rec = {"count": 0, "first_fail": 0, "last_fail": 0, "locked_until": 0}

    last_fail = int(rec.get("last_fail", 0) or 0)
    if last_fail == 0 or (now - last_fail) > current_app.config["FAILED_WINDOW_SEC"]:
        rec["count"] = 0
        rec["first_fail"] = now

    rec["count"] = int(rec.get("count", 0) or 0) + 1
    rec["last_fail"] = now

    lock_remaining = 0
    if rec["count"] >= limit:
        rec["locked_until"] = now + current_app.config["LOCKOUT_SEC"]
        lock_remaining = current_app.config["LOCKOUT_SEC"]

    data[key] = rec
    save_failed_logins(data)
    return rec["count"], lock_remaining


def reset_fail(key: str) -> None:
    data = load_failed_logins()
    data.pop(key, None)
    save_failed_logins(data)


# Anciens noms, conservés pour compatibilité.
def is_admin_locked(ip: str) -> tuple[bool, int]:
    return is_locked(ip)


def register_admin_fail(ip: str) -> tuple[int, int]:
    return register_fail(ip)


def reset_admin_fail(ip: str) -> None:
    reset_fail(ip)


# ---------------------------------------------------------------------------
# Connexion admin
# ---------------------------------------------------------------------------

def _same(a: str, b: str) -> bool:
    """Comparaison en temps constant (évite de deviner le mot de passe au timing)."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def admin_credentials_are_default() -> bool:
    cfg = current_app.config
    return cfg["ADMIN_USER"] == "0" and cfg["ADMIN_PASS"] == "0"


def check_admin_config() -> None:
    """À appeler au démarrage : prévient si l'admin est protégé par le couple 0/0."""
    if admin_credentials_are_default():
        _log.warning(
            "ADMIN_USER/ADMIN_PASS ne sont pas définis (valeur par défaut 0/0). "
            "La connexion admin est REFUSÉE tant que ce n'est pas corrigé "
            "(ou ALLOW_DEFAULT_ADMIN=1 pour du développement local)."
        )


def process_admin_login(username: str, password: str) -> tuple[bool, int | None]:
    cfg = current_app.config

    # Identifiants par défaut : on n'ouvre jamais l'admin d'un site en ligne avec 0/0.
    if admin_credentials_are_default() and not (cfg.get("ALLOW_DEFAULT_ADMIN") or current_app.debug):
        return False, 503

    ip = get_client_ip()
    locked, _secs = is_locked(ip)
    if locked:
        return False, 429

    # Verrou global : si trop d'échecs au total (IP qui change à chaque essai),
    # plus personne ne peut tenter de se connecter pendant le délai de blocage.
    global_locked, _secs = is_locked(_GLOBAL_KEY)
    if global_locked:
        return False, 429

    user_ok = _same(username, cfg["ADMIN_USER"])
    pass_ok = _same(password, cfg["ADMIN_PASS"])
    if user_ok and pass_ok:
        reset_fail(ip)
        session["is_admin"] = True
        return True, None

    time.sleep(0.6)
    _count, lock_sec = register_fail(ip)
    register_fail(_GLOBAL_KEY, max_failures=cfg["GLOBAL_MAX_FAILED_LOGINS"])
    if lock_sec > 0:
        return False, 429
    return False, 401
