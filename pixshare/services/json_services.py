import json
import logging
import os
import threading
import time

_json_lock = threading.RLock()
_log = logging.getLogger(__name__)


def _get_base_dir():
    return os.path.dirname(os.path.dirname(__file__))


def _get_data_dir():
    # PIXSHARE_DATA_DIR permet de pointer vers un disque persistant (ex. Render)
    # ou vers un dossier temporaire pour les tests.
    data_dir = os.environ.get("PIXSHARE_DATA_DIR") or os.path.join(_get_base_dir(), "data")
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


def _ensure_parent_dir(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def _write_json_file(path, data):
    """Écriture atomique : on écrit dans un fichier temporaire unique puis on
    remplace. Un lecteur concurrent voit donc toujours l'ancienne version
    complète ou la nouvelle, jamais un fichier tronqué."""
    _ensure_parent_dir(path)
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        with _json_lock:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def _backup_corrupt_file(path):
    """Garde une copie d'un fichier illisible au lieu de l'écraser."""
    backup = f"{path}.corrupt-{int(time.time())}"
    try:
        os.replace(path, backup)
        _log.error("Fichier JSON illisible déplacé vers %s", backup)
    except OSError:
        pass


def _read_json_file(path, default):
    _ensure_parent_dir(path)

    if not os.path.exists(path):
        _write_json_file(path, default)
        return default

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
    except OSError:
        # Lecture impossible : on ne touche pas au fichier.
        return default

    if not content:
        # Fichier vide (ancien crash) : rien à perdre, on repart sur le défaut.
        return default

    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError, TypeError):
        # Avant : le fichier était écrasé par la valeur par défaut, ce qui
        # effaçait toutes les données en cas de lecture concurrente d'une
        # écriture. On conserve maintenant une copie pour pouvoir récupérer.
        _backup_corrupt_file(path)
        return default

    if isinstance(default, list) and not isinstance(data, list):
        return default
    if isinstance(default, dict) and not isinstance(data, dict):
        return default

    return data


def _json_path(filename):
    return os.path.join(_get_data_dir(), filename)


def json_exists(filename):
    return os.path.exists(_json_path(filename))


def load_json(filename, default=None):
    if default is None:
        default = {}
    return _read_json_file(_json_path(filename), default)


def save_json(filename, data):
    _write_json_file(_json_path(filename), data)


# =========================================================
# FICHIERS PRINCIPAUX
# =========================================================

def load_db():
    return _read_json_file(_json_path("files.json"), {})


def save_db(data):
    _write_json_file(_json_path("files.json"), data)


def load_files():
    return load_db()


def save_files(data):
    save_db(data)


# =========================================================
# VUES
# =========================================================

def load_views():
    return _read_json_file(_json_path("views.json"), {})


def save_views(data):
    _write_json_file(_json_path("views.json"), data)


# =========================================================
# CONTACTS
# =========================================================

def load_contacts():
    return _read_json_file(_json_path("contacts.json"), [])


def save_contacts(data):
    _write_json_file(_json_path("contacts.json"), data)


# =========================================================
# MESSAGES
# =========================================================

def load_messages():
    return _read_json_file(_json_path("messages.json"), [])


def save_messages(data):
    _write_json_file(_json_path("messages.json"), data)


# =========================================================
# IP BLOQUÉES
# =========================================================

def load_blocked_ips():
    return _read_json_file(_json_path("blocked_ips.json"), [])


def save_blocked_ips(data):
    _write_json_file(_json_path("blocked_ips.json"), data)


# Alias compatibles avec le reste du projet
def load_blocked():
    return load_blocked_ips()


def save_blocked(data):
    save_blocked_ips(data)


# =========================================================
# TENTATIVES DE CONNEXION ÉCHOUÉES
# =========================================================

def load_failed_logins():
    return _read_json_file(_json_path("failed_logins.json"), {})


def save_failed_logins(data):
    _write_json_file(_json_path("failed_logins.json"), data)


def load_failed_attempts():
    return load_failed_logins()


def save_failed_attempts(data):
    save_failed_logins(data)


# =========================================================
# CLÉS API
# =========================================================

def load_api_keys():
    data = _read_json_file(_json_path("api_keys.json"), {})
    if not isinstance(data, dict):
        return {}
    return data
    
    
def save_api_keys(data):
    _write_json_file(_json_path("api_keys.json"), data)


def load_admin_api_keys():
    return load_api_keys()


def save_admin_api_keys(data):
    save_api_keys(data)


# =========================================================
# PARAMÈTRES
# =========================================================

def load_settings():
    return _read_json_file(_json_path("settings.json"), {})


def save_settings(data):
    _write_json_file(_json_path("settings.json"), data)


def load_config():
    return load_settings()


def save_config(data):
    save_settings(data)


# =========================================================
# ROOMS
# =========================================================

def load_rooms():
    return _read_json_file(_json_path("rooms.json"), [])


def save_rooms(data):
    _write_json_file(_json_path("rooms.json"), data)


# =========================================================
# MINIATURES
# =========================================================

def load_thumbnails():
    return _read_json_file(_json_path("thumbnails.json"), {})


def save_thumbnails(data):
    _write_json_file(_json_path("thumbnails.json"), data)


# =========================================================
# SIGNALÉS / MODÉRATION
# =========================================================

def load_reports():
    return _read_json_file(_json_path("reports.json"), [])


def save_reports(data):
    _write_json_file(_json_path("reports.json"), data)


def load_moderation():
    return _read_json_file(_json_path("moderation.json"), {})


def save_moderation(data):
    _write_json_file(_json_path("moderation.json"), data)


# =========================================================
# HISTORIQUE / LOGS
# =========================================================

def load_history():
    return _read_json_file(_json_path("history.json"), [])


def save_history(data):
    _write_json_file(_json_path("history.json"), data)


def load_logs():
    return _read_json_file(_json_path("logs.json"), [])


def save_logs(data):
    _write_json_file(_json_path("logs.json"), data)


# =========================================================
# UTILISATEURS / SESSIONS
# =========================================================

def load_users():
    return _read_json_file(_json_path("users.json"), [])


def save_users(data):
    _write_json_file(_json_path("users.json"), data)


def load_sessions():
    return _read_json_file(_json_path("sessions.json"), {})


def save_sessions(data):
    _write_json_file(_json_path("sessions.json"), data)


# =========================================================
# STATISTIQUES
# =========================================================

def load_stats():
    return _read_json_file(_json_path("stats.json"), {})


def save_stats(data):
    _write_json_file(_json_path("stats.json"), data)


# =========================================================
# TRADUCTIONS
# =========================================================

def _translations_dir():
    path = os.path.join(_get_data_dir(), "translations")
    os.makedirs(path, exist_ok=True)
    return path


def load_translations(lang_code):
    path = os.path.join(_translations_dir(), f"{lang_code}.json")
    return _read_json_file(path, {})


def save_translations(lang_code, data):
    path = os.path.join(_translations_dir(), f"{lang_code}.json")
    _write_json_file(path, data)


# =========================================================
# FONCTIONS GÉNÉRIQUES PAR NOM
# =========================================================

def load_named_list(filename):
    return _read_json_file(_json_path(filename), [])


def save_named_list(filename, data):
    _write_json_file(_json_path(filename), data)


def load_named_dict(filename):
    return _read_json_file(_json_path(filename), {})


def save_named_dict(filename, data):
    _write_json_file(_json_path(filename), data)

# =========================================================
# NOTICES DE MODÉRATION
# =========================================================

def load_moderation_notices():
    return _read_json_file(_json_path("moderation_notices.json"), [])


def save_moderation_notices(data):
    _write_json_file(_json_path("moderation_notices.json"), data)


# =========================================================
# UTILISATION / SOURCES DES IMAGES
# =========================================================

def load_usage():
    return _read_json_file(_json_path("image_usage.json"), {})

def save_usage(data):
    _write_json_file(_json_path("image_usage.json"), data)
