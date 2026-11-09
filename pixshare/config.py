import logging
import os
import secrets

_log = logging.getLogger(__name__)


def _env_int(name: str):
    """Retourne un entier lu dans l'environnement, ou None s'il est absent/invalide."""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        _log.warning("%s=%r est invalide (entier attendu), valeur ignorée.", name, raw)
        return None


def _env_float(name: str, default: float) -> float:
    """Retourne un nombre lu dans l'environnement, ou `default` s'il est absent/invalide."""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        _log.warning("%s=%r est invalide (nombre attendu), valeur par défaut utilisée.", name, raw)
        return default


def _load_or_create_secret_key() -> str:
    """Clé de signature des sessions.

    Priorité à la variable d'environnement SECRET_KEY. Sinon on génère une clé
    UNE fois et on la garde dans un fichier : avant, chaque processus (donc
    chaque worker gunicorn et chaque redémarrage) tirait une clé différente, ce
    qui invalidait les sessions admin/API et les jetons CSRF en cours.
    """
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key

    data_dir = os.environ.get("PIXSHARE_DATA_DIR") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data"
    )
    key_path = os.path.join(data_dir, ".secret_key")

    try:
        os.makedirs(data_dir, exist_ok=True)
        try:
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            with open(key_path, "r", encoding="utf-8") as f:
                existing = f.read().strip()
            if existing:
                return existing
            # fichier vide laissé par un autre worker en cours d'écriture
            return secrets.token_hex(32)
        key = secrets.token_hex(32)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(key)
        return key
    except OSError:
        _log.warning("Impossible de persister la clé secrète ; définis la variable SECRET_KEY.")
        return secrets.token_hex(32)


class Config:
    ADMIN_USER = os.environ.get("ADMIN_USER") or "0"
    ADMIN_PASS = os.environ.get("ADMIN_PASS") or "0"
    MODERATION_API_KEY = os.environ.get("MODERATION_API_KEY", "")
    MODERATION_PENDING_IMAGES = (os.environ.get("MODERATION_PENDING_IMAGES", "1") == "1")
    # NudeNet intégré au site : analyse les images en attente juste après l'envoi.
    NSFW_AUTO_MODERATION = (os.environ.get("NSFW_AUTO_MODERATION", "1") == "1")
    NSFW_REVIEW_THRESHOLD = _env_float("NSFW_REVIEW_THRESHOLD", 0.60)
    NSFW_BLOCK_THRESHOLD = _env_float("NSFW_BLOCK_THRESHOLD", 0.85)

    DATA_DIR = "data"
    DB_FILE = os.path.join(DATA_DIR, "files.json")
    BLOCKED_FILE = os.path.join(DATA_DIR, "blocked_ips.json")
    FAILED_LOGINS_FILE = os.path.join(DATA_DIR, "failed_logins.json")
    VIEWS_FILE = os.path.join(DATA_DIR, "views.json")
    CONTACTS_FILE = os.path.join(DATA_DIR, "contacts.json")
    API_KEYS_FILE = os.path.join(DATA_DIR, "api_keys.json")
    THUMBNAIL_FOLDER = os.path.join(DATA_DIR, "mod_thumbs")

    UPLOAD_FOLDER = "tmp/fichiers"
    APP_VERSION = (os.environ.get("RENDER_GIT_COMMIT", "")[:7] or "dev")

    MAX_CONTENT_LENGTH = 1000 * 1024 * 1024
    VISITOR_COOKIE_NAME = "visitor_token"
    GUEST_COOKIE_NAME = "guest_token"
    GUEST_COOKIE_MAX_AGE = 60 * 60 * 24 * 30

    MAX_FAILED_LOGINS = 5
    FAILED_WINDOW_SEC = 10 * 60
    LOCKOUT_SEC = 15 * 60

    ALLOWED_EXTENSIONS = {
        "png", "jpg", "jpeg", "gif", "webp",
        "tif", "tiff", "bmp", "jfif", "jpe", "apng",
        "mp4", "webm", "avi", "heic", "heif"
    }

    MAX_LIFETIME_MIN = 10080
    DEFAULT_LIFETIME_MIN = 5

    PERMANENT_UPLOADS_ENABLED = (os.environ.get("PERMANENT_UPLOADS", "0") == "0")
    PERMANENT_UPLOADS_ADMIN_ONLY = (os.environ.get("PERMANENT_UPLOADS_ADMIN_ONLY", "1") == "0")

    SECRET_KEY = _load_or_create_secret_key()
    SESSION_COOKIE_HTTPONLY = True
    # Mettre SESSION_COOKIE_SECURE=0 uniquement pour tester en HTTP (hors localhost).
    SESSION_COOKIE_SECURE = (os.environ.get("SESSION_COOKIE_SECURE", "1") != "0")
    SESSION_COOKIE_SAMESITE = "Lax"

    # Nombre de proxys de confiance devant l'app (voir services/request_service.py).
    # None = non défini (ancien comportement, avec avertissement).
    TRUSTED_PROXY_COUNT = _env_int("TRUSTED_PROXY_COUNT")

    # Autorise le couple admin par défaut 0/0 (développement local uniquement).
    ALLOW_DEFAULT_ADMIN = (os.environ.get("ALLOW_DEFAULT_ADMIN", "0") == "1")

    # Plafond global d'échecs de connexion admin, toutes IP confondues
    # (protège contre un attaquant qui change d'IP à chaque essai).
    GLOBAL_MAX_FAILED_LOGINS = 30

    API_DEFAULT_MAX_FILE_SIZE_MB = 10
    
    API_MAX_DIMENSION = 6000
    
