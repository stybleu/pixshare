import os
import json
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask, request, render_template, redirect, url_for,
    flash, abort, session, send_from_directory
)
from werkzeug.utils import secure_filename

# -----------------------
# Configuration
# -----------------------
ADMIN_USER = os.environ.get("ADMIN_USER") or ""
ADMIN_PASS = os.environ.get("ADMIN_PASS") or ""

UPLOAD_FOLDER = "tmp/fichiers"
DB_FILE = "files.json"
BLOCKED_FILE = "blocked_ips.json"
APP_VERSION = os.environ.get("RENDER_GIT_COMMIT", "")[:7] or "dev"

MAX_CONTENT_LENGTH = 128 * 1024 * 1024  # 128 Mo

# ✅ Liste blanche d'extensions autorisées (sans le point)
ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "webp",
    "mp4", "webm", "avi"
}

# Durée de vie max des fichiers (minutes)
MAX_LIFETIME_MIN = 30
DEFAULT_LIFETIME_MIN = 10

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# -----------------------
# Time helpers
# -----------------------
def utcnow():
    return datetime.now(timezone.utc)

def parse_dt(s: str) -> datetime:
    """
    Parse une date ISO. Si elle est "naive" (sans timezone), on suppose UTC.
    Accepte aussi le format avec 'Z'.
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
# Paths helpers
# -----------------------
def _db_path() -> str:
    return os.path.join(app.root_path, DB_FILE)

def _blocked_path() -> str:
    return os.path.join(app.root_path, BLOCKED_FILE)

# -----------------------
# DB JSON (files)
# Format: { file_id: { original_name, server_name, uploaded_at, expires_at, ip } }
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
    Supprime les fichiers expirés :
    - fichier sur disque
    - entrée dans files.json
    Retourne le nombre de suppressions.
    """
    db = load_db()
    now = utcnow()

    removed = 0
    to_delete = []

    for file_id, meta in db.items():
        exp = parse_dt(meta.get("expires_at", ""))
        if exp <= now:
            to_delete.append(file_id)

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
# IP Blocklist JSON
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

def save_blocked(data: list) -> None:
    path = _blocked_path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

# -----------------------
# Utilitaires
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
    """Retourne l'extension AVEC le point (ex: '.png'), en minuscule."""
    _, ext = os.path.splitext(filename)
    ext = (ext or "").lower()
    if len(ext) > 12:
        return ""
    return ext

def allowed_file(filename: str) -> bool:
    """✅ Vérifie si l'extension du fichier est autorisée (liste blanche)."""
    ext = safe_ext(filename)  # ex: ".png"
    if not ext:
        return False
    return ext[1:] in ALLOWED_EXTENSIONS  # enlève le point

def generate_file_id() -> str:
    return secrets.token_urlsafe(8).replace("-", "").replace("_", "")

def get_client_ip() -> str:
    # Sur Render / proxy : X-Forwarded-For peut contenir "ip1, ip2"
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return (request.remote_addr or "").strip()

def delete_by_id(file_id: str) -> bool:
    """Supprime fichier + entrée DB. Retourne True si supprimé."""
    cleanup_expired()

    db = load_db()
    meta = db.get(file_id)
    if not meta:
        return False

    server_name = os.path.basename(meta.get("server_name", ""))
    path = os.path.join(app.config["UPLOAD_FOLDER"], server_name)

    try:
        if os.path.isfile(path):
            os.remove(path)
    except Exception:
        pass

    db.pop(file_id, None)
    save_db(db)
    return True

def file_meta(file_id: str):
    cleanup_expired()

    if not file_id:
        return None

    db = load_db()
    meta = db.get(file_id)
    if not meta:
        return None

    server_name = os.path.basename(meta.get("server_name", ""))
    path = os.path.join(app.config["UPLOAD_FOLDER"], server_name)
    if not os.path.isfile(path):
        return None

    stat = os.stat(path)
    ext = os.path.splitext(server_name)[1].lower()

    previewable = ext in {".png", ".jpg", ".jpeg", ".gif", ".webp"}

    # Temps restant (optionnel mais pratique)
    exp = parse_dt(meta.get("expires_at", ""))
    remaining_s = max(0, int((exp - utcnow()).total_seconds()))
    remaining_min = remaining_s // 60
    remaining_sec = remaining_s % 60

    return {
        "id": file_id,
        "original": meta.get("original_name", "unknown"),
        "server": server_name,
        "uploaded_at": meta.get("uploaded_at", ""),
        "expires_at": meta.get("expires_at", ""),
        "remaining_h": f"{remaining_min:02d}:{remaining_sec:02d}",
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
        meta = file_meta(file_id)
        if meta:
            items.append(meta)
    items.sort(key=lambda x: x.get("mtime_h", ""), reverse=True)
    return items

# -----------------------
# Admin auth
# -----------------------
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
# Google / SEO
# -----------------------
@app.route("/googlebe607fe93d5d66a4.html")
def google_verify():
    return send_from_directory("static", "googlebe607fe93d5d66a4.html")

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
# Routes INVITÉ (public)
# -----------------------
@app.route("/", methods=["GET", "POST"])
def index():
    cleanup_expired()

    ip = get_client_ip()
    blocked = load_blocked()
    if ip and ip in blocked:
        return redirect("https://www.google.fr"), 302

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

        # ✅ durée choisie par l'utilisateur, mais sécurisée côté serveur (max 30 min)
        try:
            lifetime = int(request.form.get("lifetime", DEFAULT_LIFETIME_MIN))
        except ValueError:
            lifetime = DEFAULT_LIFETIME_MIN
        lifetime = max(1, min(lifetime, MAX_LIFETIME_MIN))

        # On ne remplace plus un fichier "ancien" automatiquement ici,
        # on remet juste le "dernier fichier" du visiteur
        session["guest_file_id"] = None

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
        expires_at = uploaded_at + timedelta(minutes=lifetime)

        db = load_db()
        db[file_id] = {
            "original_name": original,
            "server_name": server_name,
            "uploaded_at": uploaded_at.isoformat(timespec="seconds"),
            "expires_at": expires_at.isoformat(timespec="seconds"),
            "ip": ip
        }
        save_db(db)

        session["guest_file_id"] = file_id
        flash(f"Fichier upload ✅ (expiration: {lifetime} min)", "success")
        return redirect(url_for("index"))

    guest_id = session.get("guest_file_id")
    guest_file = file_meta(guest_id) if guest_id else None

    return render_template(
        "index.html",
        guest_file=guest_file,
        max_mb=int(MAX_CONTENT_LENGTH / (1024 * 1024)),
        admin=is_admin(),
        version=APP_VERSION
    )

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
    original_name = meta.get("original_name", "")
    path = os.path.join(app.config["UPLOAD_FOLDER"], server_name)
    if not os.path.isfile(path):
        abort(404)

    file_url = url_for("view_file", file_id=file_id)
    return render_template("file.html", file_url=file_url, original_name=original_name)

# -----------------------
# Routes ADMIN (banque + suppression)
# -----------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        user = (request.form.get("user") or "").strip()
        pwd = (request.form.get("pass") or "").strip()

        if secrets.compare_digest(user, ADMIN_USER) and secrets.compare_digest(pwd, ADMIN_PASS):
            session["is_admin"] = True
            flash("Admin connecté ✅", "success")
            return redirect(url_for("admin_panel"))

        flash("Identifiants incorrects ❌", "danger")
        return redirect(url_for("admin_login"))

    return render_template("admin_login.html", version=APP_VERSION)

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
    cleanup_expired()

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
# Pages légales
# -----------------------
@app.route("/cgu")
def cgu():
    return render_template("cgu.html", version=APP_VERSION)

@app.route("/mentions-legales")
def mentions_legales():
    return render_template("mentions_legales.html", version=APP_VERSION)

# -----------------------
# Lancement (local uniquement)
# -----------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)