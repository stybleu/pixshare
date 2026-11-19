"""Albums photo des membres, partagés par lien ou QR code."""
import io
import os
import zipfile

from flask import (Blueprint, Response, abort, current_app, flash, jsonify, make_response, redirect,
                   render_template, request, session, stream_with_context, url_for)
from werkzeug.utils import secure_filename

from pixshare.security.csrf import validate_csrf
from pixshare.services import account_service as accounts
from pixshare.services import album_service as albums
from pixshare.services import qr_service
from pixshare.services.auth_service import is_admin
from pixshare.services.file_service import (attach_guest_cookie, delete_by_id, get_guest_token,
                                            is_image_filename, medium_path, save_uploaded_file)
from pixshare.services.image_ban_service import BannedImageError
from pixshare.services.json_services import load_blocked
from pixshare.services.request_service import get_client_ip
from pixshare.services.settings_service import get_max_upload_size_mb, upload_service_enabled
from pixshare.services.system_service import has_room_for
from pixshare.services.turnstile_service import turnstile_ok
from pixshare.services.upload_limit_service import check_upload_rate

album_bp = Blueprint("album", __name__)


def _noindex(response):
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noimageindex"
    response.headers["Cache-Control"] = "private, no-store"
    return response


def _album_or_404(album_id) -> dict:
    album = albums.get(album_id)
    if not album:
        abort(404)
    return album


def _owner_album_or_404(album_id) -> tuple[dict, dict]:
    album = _album_or_404(album_id)
    me = accounts.current_account()
    if not albums.is_owner(album, me):
        abort(404)
    return album, me


def album_url(album: dict) -> str:
    return url_for("album.view", album_id=album["id"], _external=True)


# ------------------------------------------------------------------ espace du membre

@album_bp.route("/mes-albums", methods=["GET", "POST"], endpoint="mine")
def mine():
    me = accounts.current_account()
    if not me:
        return redirect(url_for("account.login", next="/mes-albums"))
    if request.method == "POST":
        validate_csrf()
        try:
            album = albums.create(me, request.form.get("name"), request.form.get("description"),
                                  request.form.get("password"), request.form.get("guests_can_add") == "1",
                                  request.form.get("theme") or "classique")
            flash(f"Album « {album['name']} » créé ✅ Ajoutez vos photos, puis partagez le QR code.", "success")
            return redirect(url_for("album.view", album_id=album["id"]))
        except albums.AlbumError as exc:
            flash(str(exc), "warning")
        return redirect(url_for("album.mine"))
    items = [{**a, "counts": albums.counts(a["id"])} for a in albums.list_for(me["id"])]
    return _noindex(make_response(render_template(
        "albums_mine.html", items=items, max_albums=albums.ALBUMS_PER_ACCOUNT,
        max_photos=albums.PHOTOS_PER_ALBUM, themes=albums.THEMES, title="Mes albums – PixShare")))


@album_bp.route("/mes-albums/<album_id>/modifier", methods=["POST"], endpoint="edit")
def edit(album_id):
    validate_csrf()
    album, _me = _owner_album_or_404(album_id)
    try:
        albums.update(album["id"], name=request.form.get("name"), description=request.form.get("description"),
                      guests_can_add=request.form.get("guests_can_add") == "1",
                      password=request.form.get("password") or "",
                      remove_password=request.form.get("remove_password") == "1")
        flash("Album enregistré ✅", "success")
    except albums.AlbumError as exc:
        flash(str(exc), "warning")
    return redirect(url_for("album.mine") + f"#album-{album['id']}")


@album_bp.route("/album/<album_id>/apparence", methods=["POST"], endpoint="style")
def style(album_id):
    validate_csrf()
    album, _me = _owner_album_or_404(album_id)
    form = request.form
    try:
        if "cover" in form:
            albums.set_style(album["id"], cover=form.get("cover", ""))
            flash("Photo de couverture choisie ✅" if form.get("cover") else "Couverture retirée.", "success")
        else:
            accent = form.get("accent", "") if form.get("own_color") == "1" else ""
            albums.set_style(album["id"], theme=form.get("theme"), accent=accent, font=form.get("font", ""),
                             layout=form.get("layout", "grille"))
            flash("Mise en page enregistrée ✅", "success")
    except albums.AlbumError as exc:
        flash(str(exc), "warning")
    return redirect(url_for("album.view", album_id=album["id"]) + ("#perso" if "cover" not in form else ""))


@album_bp.route("/mes-albums/<album_id>/supprimer", methods=["POST"], endpoint="delete")
def delete(album_id):
    validate_csrf()
    album, _me = _owner_album_or_404(album_id)
    if request.form.get("confirm") != "1":
        flash("Cochez la case pour confirmer la suppression de l'album.", "warning")
        return redirect(url_for("album.mine") + f"#album-{album['id']}")
    removed = albums.delete(album["id"])
    flash(f"Album « {album['name']} » supprimé, avec ses {removed} photo(s).", "success")
    return redirect(url_for("album.mine"))


@album_bp.route("/album/<album_id>/photo/<file_id>/supprimer", methods=["POST"], endpoint="delete_photo")
def delete_photo(album_id, file_id):
    validate_csrf()
    album, _me = _owner_album_or_404(album_id)
    if not any(m["id"] == file_id for m in albums.photos(album["id"], include_pending=True)):
        abort(404)
    delete_by_id(file_id, reason="deleted")
    flash("Photo retirée de l'album.", "success")
    return redirect(url_for("album.view", album_id=album["id"]))


# ------------------------------------------------------------------ page publique de l'album

@album_bp.route("/album/<album_id>", methods=["GET"], endpoint="view")
def view(album_id):
    album = _album_or_404(album_id)
    me = accounts.current_account()
    if not albums.unlocked(album, me):
        return _noindex(make_response(render_template("album_locked.html", album=album, look=albums.style(album),
                                                      title=f"{album['name']} – PixShare")))
    owner = albums.is_owner(album, me)
    items = albums.photos(album["id"], include_pending=owner)
    people = albums.contributors(items)
    who = request.args.get("par", "")
    shown = [m for m in items if not who or m.get("album_contributor") == who]
    counts = albums.counts(album["id"])
    can_add = (owner or album.get("guests_can_add")) and upload_service_enabled()
    response = make_response(render_template(
        "album.html", album=album, photos=shown, people=people, who=who, owner=owner, counts=counts,
        can_add=can_add, room_left=albums.room_left(album["id"]),
        need_human=not owner and not albums.human_checked(album["id"]),
        contributor=session.get("album_name", ""),
        max_mb=get_max_upload_size_mb(accounts.get_account(album["owner"]) or True),
        share_url=album_url(album), look=albums.style(album), themes=albums.THEMES, fonts=albums.FONTS,
        layouts=albums.LAYOUTS, cover=next((m for m in items if m["id"] == album.get("cover")
                                            and m.get("status") == "active"), None),
        title=f"{album['name']} – PixShare"))
    return _noindex(attach_guest_cookie(response))


@album_bp.route("/album/<album_id>/deverrouiller", methods=["POST"], endpoint="unlock")
def unlock(album_id):
    validate_csrf()
    album = _album_or_404(album_id)
    rate = check_upload_rate(f"albumpw:{get_client_ip()}", limit=20)
    if not rate.allowed:
        flash("Trop d'essais. Réessayez dans une heure.", "warning")
    elif not albums.unlock(album, request.form.get("password", "")):
        flash("Mot de passe incorrect.", "warning")
    return redirect(url_for("album.view", album_id=album["id"]))


@album_bp.route("/album/<album_id>/photos.json", methods=["GET"], endpoint="photos_json")
def photos_json(album_id):
    """Liste des photos pour le diaporama (mise à jour pendant l'événement)."""
    album = _album_or_404(album_id)
    if not albums.unlocked(album, accounts.current_account()):
        abort(404)
    data = [{"src": url_for("public.view_file", file_id=m["id"], m=1) if os.path.isfile(medium_path(m["id"]))
             else url_for("public.view_file", file_id=m["id"], raw=1),
             "by": m.get("album_contributor") or ""} for m in albums.photos(album["id"])]
    return _noindex(jsonify(photos=data))


@album_bp.route("/album/<album_id>/diaporama", methods=["GET"], endpoint="slideshow")
def slideshow(album_id):
    album = _album_or_404(album_id)
    if not albums.unlocked(album, accounts.current_account()):
        return redirect(url_for("album.view", album_id=album["id"]))
    return _noindex(make_response(render_template("album_slideshow.html", album=album, look=albums.style(album))))


@album_bp.route("/album/<album_id>/ajouter", methods=["POST"], endpoint="add")
def add(album_id):
    """Ajoute une ou plusieurs photos. Le site envoie les photos une par une (barre de progression) ;
    sans JavaScript, le formulaire envoie tout d'un coup."""
    validate_csrf()
    wants_json = request.headers.get("X-Requested-With") == "pixshare"

    def done(message: str, level: str, status: int = 200, **extra):
        if wants_json:
            return attach_guest_cookie(make_response(jsonify(message=message, level=level, **extra), status))
        flash(message, level)
        return attach_guest_cookie(redirect(url_for("album.view", album_id=album_id)))

    album = _album_or_404(album_id)
    me = accounts.current_account()
    owner_rec = accounts.get_account(album["owner"])
    by_owner = albums.is_owner(album, me)
    ip = get_client_ip()
    if not owner_rec:
        abort(404)
    if ip and ip in load_blocked():
        return done("L'envoi n'est pas possible depuis votre connexion.", "danger", 403)
    if not upload_service_enabled():
        return done("L'envoi de fichiers est suspendu pour le moment. Réessayez plus tard.", "warning", 503)
    if not albums.unlocked(album, me):
        return done("Cet album est protégé par un mot de passe.", "warning", 403)
    if not by_owner and not album.get("guests_can_add"):
        return done("L'ajout de photos est fermé pour cet album.", "warning", 403)
    if not by_owner and not albums.human_checked(album["id"]):
        if not turnstile_ok(request.form, ip):
            return done("Vérification anti-robot échouée : cochez la case puis réessayez.", "warning", 400)
        albums.mark_human(album["id"])
    if not has_room_for(request.content_length):
        return done("Le stockage est plein pour le moment. Réessayez un peu plus tard.", "warning", 507)

    contributor = "" if by_owner else albums.clean_contributor(request.form.get("contributor"))
    if contributor:
        session["album_name"] = contributor
    files = [f for f in request.files.getlist("files") + request.files.getlist("file") if f and f.filename]
    if not files:
        return done("Choisissez au moins une photo.", "warning", 400)
    max_bytes = get_max_upload_size_mb(owner_rec) * 1024 * 1024
    guest_token = get_guest_token()
    added, errors = 0, []
    for f in files:
        name = f.filename
        if albums.room_left(album["id"]) <= 0:
            errors.append(f"L'album est complet ({albums.PHOTOS_PER_ALBUM} photos).")
            break
        if not secure_filename(name) or not is_image_filename(name):
            errors.append(f"{name} : seules les photos sont acceptées dans un album.")
            continue
        rate = check_upload_rate(f"album:{album['id']}:{'owner' if by_owner else ip}", exempt=is_admin(),
                                 limit=albums.OWNER_UPLOADS_PER_HOUR if by_owner else albums.GUEST_UPLOADS_PER_HOUR)
        if not rate.allowed:
            errors.append("Trop de photos envoyées d'un coup. Réessayez dans une heure.")
            break
        try:
            file_id, _lifetime, _permanent = save_uploaded_file(
                f, original_name=name, client_ip=ip, guest_token=guest_token, max_size_bytes=max_bytes)
        except BannedImageError:
            errors.append(f"{name} : cette image a déjà été refusée par la modération.")
            continue
        except Exception as exc:  # fichier trop gros ou illisible : on passe à la suite
            current_app.logger.info("Photo d'album refusée (%s) : %s", type(exc).__name__, exc)
            errors.append(f"{name} : fichier refusé (trop lourd, {get_max_upload_size_mb(owner_rec)} Mo maximum, ou illisible).")
            continue
        albums.finalize_photo(file_id, album, owner_rec, by_owner, contributor)
        added += 1
    if added and not errors:
        return done(f"{added} photo(s) ajoutée(s) ✅ Elles apparaissent dans l'album après la vérification automatique.",
                    "success", added=added)
    if added:
        return done(f"{added} photo(s) ajoutée(s), mais : " + " ".join(errors[:3]), "warning", added=added)
    return done(" ".join(errors[:3]) or "Aucune photo ajoutée.", "warning", 400, added=0)


# ------------------------------------------------------------------ partage : QR code, affiche, zip

@album_bp.route("/album/<album_id>/qr.svg", methods=["GET"], endpoint="qr_svg")
def qr_svg(album_id):
    album = _album_or_404(album_id)
    response = make_response(qr_service.svg(album_url(album)))
    response.headers["Content-Type"] = "image/svg+xml"
    return _noindex(response)


@album_bp.route("/album/<album_id>/qr.png", methods=["GET"], endpoint="qr_png")
def qr_png(album_id):
    album = _album_or_404(album_id)
    response = make_response(qr_service.png(album_url(album), scale=16))
    response.headers["Content-Type"] = "image/png"
    safe = secure_filename(album["name"]) or "album"
    response.headers["Content-Disposition"] = f'attachment; filename="QR-{safe}.png"'
    return _noindex(response)


@album_bp.route("/album/<album_id>/affiche", methods=["GET"], endpoint="poster")
def poster(album_id):
    album = _album_or_404(album_id)
    return _noindex(make_response(render_template("album_poster.html", album=album, share_url=album_url(album),
                                                  look=albums.style(album),
                                                  qr=qr_service.svg(album_url(album), scale=10))))


class _ZipSink(io.RawIOBase):
    """Flux d'écriture sans retour en arrière : le zip est envoyé au fur et à mesure, sans fichier temporaire."""

    def __init__(self):
        self.chunks: list[bytes] = []
        self.position = 0

    def writable(self):
        return True

    def write(self, data):
        self.chunks.append(bytes(data))
        self.position += len(data)
        return len(data)

    def tell(self):
        return self.position

    def take(self) -> bytes:
        out, self.chunks = b"".join(self.chunks), []
        return out


@album_bp.route("/album/<album_id>/tout.zip", methods=["GET"], endpoint="zip")
def zip_all(album_id):
    album = _album_or_404(album_id)
    if not albums.unlocked(album, accounts.current_account()):
        abort(404)
    items = albums.photos(album["id"])
    if not items:
        flash("L'album ne contient encore aucune photo.", "info")
        return redirect(url_for("album.view", album_id=album["id"]))
    folder = current_app.config["UPLOAD_FOLDER"]

    def generate():
        sink = _ZipSink()
        used = set()
        with zipfile.ZipFile(sink, "w", zipfile.ZIP_STORED) as archive:  # photos déjà compressées
            for n, meta in enumerate(items, 1):
                path = os.path.join(folder, os.path.basename(meta.get("server_name") or ""))
                if not os.path.isfile(path):
                    continue
                base = secure_filename(meta.get("original_name") or "") or f"photo{os.path.splitext(path)[1]}"
                name = f"{n:03d}-{base}"
                while name in used:
                    name = "x" + name
                used.add(name)
                with open(path, "rb") as src, archive.open(name, "w", force_zip64=True) as dest:
                    while True:
                        block = src.read(1024 * 1024)
                        if not block:
                            break
                        dest.write(block)
                        yield sink.take()
                yield sink.take()
        yield sink.take()

    safe = secure_filename(album["name"]) or "album"
    response = Response(stream_with_context(generate()), mimetype="application/zip")
    response.headers["Content-Disposition"] = f'attachment; filename="{safe}.zip"'
    return _noindex(response)
