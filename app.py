import os
import json
import time
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask, request, render_template, redirect, url_for,
    flash, abort, session, send_from_directory, make_response
)
from werkzeug.utils import secure_filename

# -----------------------
# Configuration
# -----------------------
ADMIN_USER = os.environ.get("ADMIN_USER") or "dev"
ADMIN_PASS = os.environ.get("ADMIN_PASS") or "dev"

UPLOAD_FOLDER = "tmp/fichiers"
DB_FILE = "files.json"
BLOCKED_FILE = "blocked_ips.json"
APP_VERSION = (os.environ.get("RENDER_GIT_COMMIT", "")[:7] or "dev")

MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 Mo

FAILED_LOGINS_FILE = "failed_logins.json"

MAX_FAILED_LOGINS = 5          # ✅ 5 essais
FAILED_WINDOW_SEC = 10 * 60    # fenêtre 10 min
LOCKOUT_SEC = 15 * 60          # lock 15 min

# ✅ Liste blanche d'extensions autorisées (sans le point)
ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "webp",
    "mp4", "webm", "avi"
}

# Durée de vie max des fichiers (minutes)
MAX_LIFETIME_MIN = 120
DEFAULT_LIFETIME_MIN = 5

# Option "ne pas supprimer" (uploads permanents)
PERMANENT_UPLOADS_ENABLED = (os.environ.get("PERMANENT_UPLOADS", "0") == "1")
PERMANENT_UPLOADS_ADMIN_ONLY = (os.environ.get("PERMANENT_UPLOADS_ADMIN_ONLY", "1") == "1")

# -----------------------
# Flask init
# -----------------------
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' data: https://cdn.jsdelivr.net; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none';"
    )
    return response
# -----------------------
# Sécurité cookies session
# -----------------------
app.config["SESSION_COOKIE_HTTPONLY"] = True      # JS ne peut pas lire le cookie
app.config["SESSION_COOKIE_SECURE"] = True        # Cookie envoyé uniquement en HTTPS
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"     # Protection CSRF basique

def _now_ts() -> int:
    return int(time.time())

def load_failed_logins() -> dict:
    try:
        with open(FAILED_LOGINS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}

def save_failed_logins(data: dict) -> None:
    tmp = FAILED_LOGINS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, FAILED_LOGINS_FILE)

def cleanup_failed_logins(data: dict) -> dict:
    """Nettoie les entrées expirées pour éviter que le fichier grossisse."""
    now = _now_ts()
    out = {}
    for ip, rec in data.items():
        if not isinstance(rec, dict):
            continue
        # garde si encore utile : soit en lockout, soit des fails récents
        locked_until = int(rec.get("locked_until", 0) or 0)
        first_fail = int(rec.get("first_fail", 0) or 0)
        last_fail = int(rec.get("last_fail", 0) or 0)

        in_lock = locked_until > now
        in_window = (now - last_fail) <= FAILED_WINDOW_SEC and first_fail > 0
        if in_lock or in_window:
            out[ip] = {
                "count": int(rec.get("count", 0) or 0),
                "first_fail": first_fail,
                "last_fail": last_fail,
                "locked_until": locked_until
            }
    return out

def is_admin_locked(ip: str) -> tuple[bool, int]:
    """Retourne (locked?, secondes_restantes)."""
    data = load_failed_logins()
    data = cleanup_failed_logins(data)
    now = _now_ts()

    rec = data.get(ip, {})
    locked_until = int(rec.get("locked_until", 0) or 0)
    if locked_until > now:
        # sauvegarde nettoyage au passage
        save_failed_logins(data)
        return True, locked_until - now

    # sauvegarde nettoyage au passage
    save_failed_logins(data)
    return False, 0

def register_admin_fail(ip: str) -> tuple[int, int]:
    """
    Incrémente les échecs. Retourne (count, lock_seconds_remaining).
    Si lock déclenché, lock_seconds_remaining = LOCKOUT_SEC.
    """
    now = _now_ts()
    data = load_failed_logins()
    data = cleanup_failed_logins(data)

    rec = data.get(ip)
    if not isinstance(rec, dict):
        rec = {"count": 0, "first_fail": 0, "last_fail": 0, "locked_until": 0}

    # si la dernière tentative est trop vieille, on repart à zéro (nouvelle fenêtre)
    last_fail = int(rec.get("last_fail", 0) or 0)
    if last_fail == 0 or (now - last_fail) > FAILED_WINDOW_SEC:
        rec["count"] = 0
        rec["first_fail"] = now

    rec["count"] = int(rec.get("count", 0) or 0) + 1
    rec["last_fail"] = now

    lock_remaining = 0
    if rec["count"] >= MAX_FAILED_LOGINS:
        rec["locked_until"] = now + LOCKOUT_SEC
        lock_remaining = LOCKOUT_SEC

    data[ip] = rec
    save_failed_logins(data)
    return rec["count"], lock_remaining

def reset_admin_fail(ip: str) -> None:
    data = load_failed_logins()
    data.pop(ip, None)
    save_failed_logins(data)
# -----------------------
# Utils time
# -----------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def parse_dt(s: str) -> datetime:
    """
    Parse ISO8601.
    Accepte 'Z' et ajoute UTC si tzinfo absent.
    """
    if not s:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt

# -----------------------
# Paths
# -----------------------
def _db_path() -> str:
    return os.path.join(app.root_path, DB_FILE)

def _blocked_path() -> str:
    return os.path.join(app.root_path, BLOCKED_FILE)

# -----------------------
# DB files.json
# { file_id: { original_name, server_name, uploaded_at, expires_at, ip, guest_token } }
# -----------------------
def load_db() -> dict:
    path = _db_path()
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def save_db(db: dict) -> None:
    path = _db_path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def cleanup_expired() -> int:
    """
    Supprime:
    - fichiers expirés sur disque
    - entrées DB associées
    """
    db = load_db()
    now = utcnow()
    to_delete = []

    for file_id, meta in db.items():
        # ✅ uploads permanents: pas d'expiration
        if meta.get("permanent") or not meta.get("expires_at"):
            continue
        exp = parse_dt(meta.get("expires_at", ""))
        if exp <= now:
            to_delete.append(file_id)

    removed = 0
    for file_id in to_delete:
        meta = db.get(file_id, {})
        server_name = os.path.basename(meta.get("server_name", ""))
        path = os.path.join(app.config["UPLOAD_FOLDER"], server_name)

        try:
            if server_name and os.path.isfile(path):
                os.remove(path)
        except Exception:
            pass

        db.pop(file_id, None)
        removed += 1

    if removed:
        save_db(db)

    return removed

# -----------------------
# blocked_ips.json
# -----------------------
def load_blocked() -> list:
    path = _blocked_path()
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []

def save_blocked(blocked: list) -> None:
    path = _blocked_path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(blocked, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

# -----------------------
# Helpers
# -----------------------
def human_size(n: int) -> str:
    units = ["o", "Ko", "Mo", "Go", "To"]
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    return f"{f:.2f} {units[i]}" if i > 0 else f"{int(f)} {units[i]}"

def safe_ext(filename: str) -> str:
    _, ext = os.path.splitext(filename)
    ext = (ext or "").lower()
    if len(ext) > 12:
        return ""
    return ext

def allowed_file(filename: str) -> bool:
    ext = safe_ext(filename)
    if not ext:
        return False
    return ext[1:] in ALLOWED_EXTENSIONS

def generate_file_id() -> str:
    return secrets.token_urlsafe(8).replace("-", "").replace("_", "")

def get_guest_token() -> str:
    """
    Identifiant anonyme (cookie technique de session Flask).
    Permet de lister les fichiers uploadés par CE navigateur.
    """
    tok = session.get("guest_token")
    if not tok:
        tok = secrets.token_urlsafe(16)
        session["guest_token"] = tok
    return tok

def get_client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return (request.remote_addr or "").strip()

def is_admin() -> bool:
    return bool(session.get("is_admin"))

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_admin():
            flash("Connexion admin requise.", "warning")
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)
    return wrapper

# -----------------------
# File meta/list
# -----------------------
def file_meta(file_id: str):
    cleanup_expired()
    if not file_id:
        return None

    db = load_db()
    meta = db.get(file_id)
    if not meta:
        return None

    server_name = os.path.basename(meta.get("server_name", ""))
    if not server_name:
        return None

    path = os.path.join(app.config["UPLOAD_FOLDER"], server_name)
    if not os.path.isfile(path):
        return None

    stat = os.stat(path)
    ext = os.path.splitext(server_name)[1].lower()
    previewable = ext in {".png", ".jpg", ".jpeg", ".gif", ".webp"}

    permanent = bool(meta.get("permanent")) or (not meta.get("expires_at"))

    if permanent:
        remaining_h = "∞"
    else:
        exp = parse_dt(meta.get("expires_at", ""))
        remaining_s = max(0, int((exp - utcnow()).total_seconds()))
        remaining_min = remaining_s // 60
        remaining_sec = remaining_s % 60
        remaining_h = f"{remaining_min:02d}:{remaining_sec:02d}"

    return {
        "id": file_id,
        "original": meta.get("original_name", "unknown"),
        "server": server_name,
        "uploaded_at": meta.get("uploaded_at", ""),
        "expires_at": meta.get("expires_at", ""),
        "remaining_h": remaining_h,
        "permanent": permanent,
        "ip": meta.get("ip", ""),
        "size_h": human_size(stat.st_size),
        "mtime_h": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
        "download_url": url_for("download", file_id=file_id, _external=True),
        "view_url": url_for("public_file", file_id=file_id, _external=True),
        "previewable": previewable,
    }

def list_all_files():
    cleanup_expired()
    db = load_db()
    items = []
    for file_id in db.keys():
        fm = file_meta(file_id)
        if fm:
            items.append(fm)
    items.sort(key=lambda x: x.get("mtime_h", ""), reverse=True)
    return items

def list_guest_files():
    """
    ✅ IMPORTANT: Liste UNIQUEMENT les fichiers avec guest_token == session guest_token
    """
    cleanup_expired()
    db = load_db()
    guest_token = get_guest_token()

    items = []
    for file_id, meta in db.items():
        if meta.get("guest_token") != guest_token:
            continue
        fm = file_meta(file_id)
        if fm:
            items.append(fm)

    items.sort(key=lambda x: x.get("mtime_h", ""), reverse=True)
    return items

def delete_by_id(file_id: str) -> bool:
    cleanup_expired()
    db = load_db()
    meta = db.get(file_id)
    if not meta:
        return False

    server_name = os.path.basename(meta.get("server_name", ""))
    path = os.path.join(app.config["UPLOAD_FOLDER"], server_name)

    try:
        if server_name and os.path.isfile(path):
            os.remove(path)
    except Exception:
        pass

    db.pop(file_id, None)
    save_db(db)
    return True

# -----------------------
# SEO routes
# -----------------------
@app.route("/robots.txt")
def robots():
    base = request.url_root.rstrip("/")
    content = f"""User-agent: *
Allow: /

Sitemap: {base}/sitemap.xml
"""
    return content, 200, {"Content-Type": "text/plain; charset=utf-8"}

@app.route("/sitemap.xml")
def sitemap():
    base = request.url_root.rstrip("/")
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>{base}/</loc>
  </url>
</urlset>
"""
    return xml, 200, {"Content-Type": "application/xml; charset=utf-8"}

# -----------------------
# ✅ INDEX (vérifié)
# -----------------------
@app.route("/", methods=["GET", "POST"])
def index():
    cleanup_expired()

    ip = get_client_ip()
    blocked = load_blocked()
    if ip and ip in blocked:
        return redirect("https://www.google.fr"), 302

    # ✅ crée/charge le token invité pour lister ses fichiers
    guest_token = get_guest_token()

    if request.method == "POST":
        f = request.files.get("file")
        if not f or f.filename == "":
            flash("Aucun fichier sélectionné.", "warning")
            return redirect(url_for("index"))

        original = f.filename
        safe_name = secure_filename(original)
        if not safe_name:
            flash("Nom de fichier invalide.", "danger")
            return redirect(url_for("index"))

        if not allowed_file(safe_name):
            allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
            flash(f"Extension non autorisée. Autorisées : {allowed}", "danger")
            return redirect(url_for("index"))

        # ✅ durée choisie par l'utilisateur (max 30 min)
        # + option "ne pas supprimer" (si activée)
        keep = (request.form.get("keep", "") in {"1", "on", "true", "yes"})
        allow_keep = PERMANENT_UPLOADS_ENABLED and (not PERMANENT_UPLOADS_ADMIN_ONLY or is_admin())

        if keep and allow_keep:
            lifetime = None
            permanent = True
        else:
            permanent = False
            try:
                lifetime = int(request.form.get("lifetime", DEFAULT_LIFETIME_MIN))
            except ValueError:
                lifetime = DEFAULT_LIFETIME_MIN
            lifetime = max(1, min(lifetime, MAX_LIFETIME_MIN))

        file_id = generate_file_id()
        ext = safe_ext(safe_name)
        server_name = f"{file_id}{ext}"
        dest = os.path.join(app.config["UPLOAD_FOLDER"], server_name)

        while os.path.exists(dest):
            file_id = generate_file_id()
            server_name = f"{file_id}{ext}"
            dest = os.path.join(app.config["UPLOAD_FOLDER"], server_name)

        f.save(dest)

        uploaded_at = utcnow()
        if permanent:
            expires_at = None
        else:
            expires_at = uploaded_at + timedelta(minutes=int(lifetime))

        db = load_db()
        db[file_id] = {
            "original_name": original,
            "server_name": server_name,
            "uploaded_at": uploaded_at.isoformat(timespec="seconds"),
            "expires_at": (expires_at.isoformat(timespec="seconds") if expires_at else ""),
            "permanent": bool(permanent),
            "ip": ip,
            "guest_token": guest_token,   # ✅ lien invité -> fichiers
        }
        save_db(db)

        if permanent:
            flash("Fichier upload ✅ (sans expiration)", "success")
        else:
            flash(f"Fichier upload ✅ (expiration: {lifetime} min)", "success")
        return redirect(url_for("index"))

    # ✅ CRUCIAL: on envoie UNIQUEMENT les fichiers de l'invité au template
    guest_files = list_guest_files()

    return render_template(
        "index.html",
        guest_files=guest_files,
        max_mb=int(MAX_CONTENT_LENGTH / (1024 * 1024)),
        admin=is_admin(),
        version=APP_VERSION,
        can_keep=(PERMANENT_UPLOADS_ENABLED and (not PERMANENT_UPLOADS_ADMIN_ONLY or is_admin()))
    )

# -----------------------
# Public file routes
# -----------------------
@app.route("/view/<file_id>")
def view_file(file_id):
    cleanup_expired()

    db = load_db()
    meta = db.get(file_id)
    if not meta:
        abort(404)

    server_name = os.path.basename(meta.get("server_name", ""))
    path = os.path.join(app.config["UPLOAD_FOLDER"], server_name)
    if not os.path.isfile(path):
        abort(404)

    return send_from_directory(app.config["UPLOAD_FOLDER"], server_name, as_attachment=False)

@app.route("/download/<file_id>")
def download(file_id):
    cleanup_expired()

    db = load_db()
    meta = db.get(file_id)
    if not meta:
        abort(404)

    server_name = os.path.basename(meta.get("server_name", ""))
    original_name = meta.get("original_name", "download")
    path = os.path.join(app.config["UPLOAD_FOLDER"], server_name)
    if not os.path.isfile(path):
        abort(404)

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        server_name,
        as_attachment=True,
        download_name=original_name
    )

@app.route("/file/<file_id>")
def public_file(file_id):
    cleanup_expired()

    db = load_db()
    meta = db.get(file_id)
    if not meta:
        abort(404)

    server_name = os.path.basename(meta.get("server_name", ""))
    path = os.path.join(app.config["UPLOAD_FOLDER"], server_name)
    if not os.path.isfile(path):
        abort(404)

    file_url = url_for("view_file", file_id=file_id)

    response = make_response(render_template(
        "file.html",
        file_url=file_url,
        original_name=meta.get("original_name", ""),
        version=APP_VERSION
    ))
    response.headers["X-Robots-Tag"] = "noindex, noimageindex"
    return response

# -----------------------
# Admin routes
# -----------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        ip = get_client_ip()

        locked, secs = is_admin_locked(ip)
        if locked:
            
            flash("Trop d’essais. Réessaie plus tard.", "danger")
            return render_template("admin_login.html"), 429

        user = (request.form.get("username") or "").strip()
        pwd = (request.form.get("password") or "")

        if user == ADMIN_USER and pwd == ADMIN_PASS:
            reset_admin_fail(ip)
            session["is_admin"] = True
            return redirect(url_for("admin_panel"))

        
        time.sleep(0.6)
        count, lock_sec = register_admin_fail(ip)

        if lock_sec > 0:
            
            flash("Trop d’essais. Accès bloqué temporairement.", "danger")
            return render_template("admin_login.html"), 429

        flash("Identifiants invalides.", "warning")
        return render_template("admin_login.html"), 401

    return render_template("admin_login.html")

@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("is_admin", None)
    flash("Déconnecté.", "success")
    return redirect(url_for("index"))

@app.route("/admin", methods=["GET"])
@admin_required
def admin_panel():
    cleanup_expired()
    return render_template("admin.html", files=list_all_files(), version=APP_VERSION)

@app.route("/admin/delete", methods=["POST"])
@admin_required
def admin_delete():
    file_id = (request.form.get("file_id") or "").strip()
    if not file_id:
        flash("ID manquant.", "warning")
        return redirect(url_for("admin_panel"))

    ok = delete_by_id(file_id)
    flash("Fichier supprimé ✅" if ok else "Fichier introuvable.", "success" if ok else "warning")
    return redirect(url_for("admin_panel"))

@app.route("/admin/block", methods=["POST"])
@admin_required
def admin_block_ip():
    ip = (request.form.get("ip") or "").strip()
    if not ip:
        flash("IP manquante.", "warning")
        return redirect(url_for("admin_panel"))

    blocked = load_blocked()
    if ip not in blocked:
        blocked.append(ip)
        save_blocked(blocked)
        flash(f"IP bloquée ✅ : {ip}", "success")
    else:
        flash(f"IP déjà bloquée : {ip}", "info")

    return redirect(url_for("admin_panel"))

# -----------------------
# Legal pages
# -----------------------
@app.route("/cgu")
def cgu():
    return render_template("cgu.html", version=APP_VERSION)

@app.route("/mentions-legales")
def mentions_legales():
    return render_template("mentions_legales.html", version=APP_VERSION)

@app.after_request
def add_robots_headers(resp):
    # Empêche l'indexation des pages admin (même si découvertes)
    if request.path.startswith("/admin"):
        resp.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    return resp

# -----------------------
# Run local
# -----------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
