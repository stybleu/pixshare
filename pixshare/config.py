import os
import secrets


class Config:
    ADMIN_USER = os.environ.get("ADMIN_USER") or "dev"
    ADMIN_PASS = os.environ.get("ADMIN_PASS") or "dev"

    DATA_DIR = "data"
    DB_FILE = os.path.join(DATA_DIR, "files.json")
    BLOCKED_FILE = os.path.join(DATA_DIR, "blocked_ips.json")
    FAILED_LOGINS_FILE = os.path.join(DATA_DIR, "failed_logins.json")
    VIEWS_FILE = os.path.join(DATA_DIR, "views.json")
    CONTACTS_FILE = os.path.join(DATA_DIR, "contacts.json")
    VOTES_FILE = os.path.join(DATA_DIR, "votes.json")

    UPLOAD_FOLDER = "tmp/fichiers"
    APP_VERSION = (os.environ.get("RENDER_GIT_COMMIT", "")[:7] or "dev")

    MAX_CONTENT_LENGTH = 100 * 1024 * 1024
    VISITOR_COOKIE_NAME = "visitor_token"

    MAX_FAILED_LOGINS = 5
    FAILED_WINDOW_SEC = 10 * 60
    LOCKOUT_SEC = 15 * 60

    ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "webp",
    "tif", "tiff",
    "mp4", "webm", "avi",".heic", ".heif"
}

    MAX_LIFETIME_MIN = 120
    DEFAULT_LIFETIME_MIN = 5

    PERMANENT_UPLOADS_ENABLED = (os.environ.get("PERMANENT_UPLOADS", "0") == "0")
    PERMANENT_UPLOADS_ADMIN_ONLY = (os.environ.get("PERMANENT_UPLOADS_ADMIN_ONLY", "1") == "0")

    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Lax"
