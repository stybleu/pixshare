"""Pages des comptes : inscription, connexion, mot de passe oublié, page « Mon compte »,
aperçu privé des images pour leur propriétaire et remplacement d'une image en gardant son lien."""
from __future__ import annotations

import os
import time

from flask import (Blueprint, abort, current_app, flash, make_response, redirect, render_template, request,
                   send_from_directory, url_for)
from werkzeug.utils import secure_filename

from pixshare.security.csrf import validate_csrf
from pixshare.services import account_service as accounts
from pixshare.services.auth_service import is_admin, is_locked, register_fail, reset_fail
from pixshare.services.file_service import (
    FileTooLargeError,
    allowed_file,
    attach_guest_cookie,
    claim_device_files,
    get_guest_token,
    is_owner,
    medium_path,
    replace_file,
    requires_image_moderation,
)
from pixshare.services.image_ban_service import BannedImageError
from pixshare.services.json_services import load_blocked, load_db
from pixshare.services.request_service import get_client_ip
from pixshare.services.settings_service import (
    accounts_enabled,
    get_max_upload_size_bytes,
    get_max_upload_size_mb,
    get_uploads_per_hour,
    limits_table,
    upload_service_enabled,
)
from pixshare.services.system_service import has_room_for
from pixshare.services.turnstile_service import turnstile_ok
from pixshare.services.upload_limit_service import check_upload_rate, limit_message

account_bp = Blueprint("account", __name__)

SIGNUPS_PER_DAY = 5      # créations de compte par IP et par jour
MAILS_PER_HOUR = 5       # renvois de confirmation / mots de passe oubliés par IP et par heure
LOGIN_FAILS = 8          # essais ratés avant un blocage temporaire (par IP)
EMAIL_LOGIN_FAILS = 20   # essais ratés avant un blocage temporaire (par adresse)
SENT_MESSAGE = "C'est envoyé ! Regarde ta boîte mail (et les spams) : le lien est valable 48 heures."


def _rate_ok(name: str, ip: str, limit: int, window: int) -> bool:
    now = time.time()
    buckets = current_app.extensions.setdefault(f"pixshare_{name}", {})
    recent = [t for t in buckets.get(ip or "?", []) if now - t < window]
    if len(recent) >= limit:
        buckets[ip or "?"] = recent
        return False
    recent.append(now)
    buckets[ip or "?"] = recent
    if len(buckets) > 5000:
        for key in [k for k, v in buckets.items() if not v or now - v[-1] >= window]:
            buckets.pop(key, None)
    return True


def _blocked() -> bool:
    ip = get_client_ip()
    return bool(ip and ip in load_blocked())


def _page(template: str, **context):
    response = make_response(render_template(template, **context))
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    response.headers["Cache-Control"] = "private, no-store"
    return response


# ------------------------------------------------------------------ inscription

@account_bp.route("/inscription", methods=["GET", "POST"], endpoint="signup")
def signup():
    if accounts.current_account():
        return redirect(url_for("account.page"))
    if _blocked():
        abort(403)
    open_ = accounts_enabled() and accounts.mail_ready()
    email = ""
    if request.method == "POST" and open_:
        validate_csrf()
        ip = get_client_ip()
        email = (request.form.get("email") or "").strip()[:254]
        password = request.form.get("password") or ""
        if request.form.get("website"):  # champ piège invisible : seuls les robots le remplissent
            abort(400)
        if not turnstile_ok(request.form, ip):
            flash("Vérification anti-robot échouée : coche la case puis réessaie.", "warning")
        elif request.form.get("accept_cgu") != "1":
            flash("Tu dois accepter les conditions d'utilisation pour créer un compte.", "warning")
        elif password != (request.form.get("password2") or ""):
            flash("Les deux mots de passe ne sont pas identiques.", "warning")
        else:
            try:
                accounts.normalize_email(email)
                accounts.check_password_rules(password, email)
            except accounts.AccountError as exc:
                flash(str(exc), "warning")
            else:
                if not _rate_ok("signup", ip, SIGNUPS_PER_DAY, 86400):
                    flash("Trop de comptes créés depuis ta connexion aujourd'hui. Réessaie demain.", "warning")
                else:
                    rec, created = accounts.create_account(email, password)
                    sent = accounts.send_confirmation(rec) if created else accounts.send_already_registered(rec)
                    if not sent:
                        flash("Le mail n'a pas pu partir. Réessaie dans quelques minutes.", "danger")
                    else:
                        # Même message que l'adresse soit libre ou non : on ne révèle pas qui a un compte.
                        return _page("account_message.html", title="Vérifie ta boîte mail", heading="Vérifie ta boîte mail",
                                     text=SENT_MESSAGE)
    return _page("account_signup.html", title="Créer un compte", open_=open_, email=email,
                 accounts_on=accounts_enabled(), limits=limits_table(),
                 password_min=accounts.PASSWORD_MIN)


@account_bp.route("/inscription/confirmer/<token>", methods=["GET", "POST"], endpoint="confirm")
def confirm(token):
    rec, error = accounts.read_token("confirm", token)
    if not rec:
        return _page("account_message.html", title="Lien invalide", heading="Lien invalide", text=error), 400
    if request.method == "POST":
        # Clic sur le bouton : les messageries qui ouvrent les liens toutes seules ne confirment pas à la place.
        validate_csrf()
        rec = accounts.confirm_account(rec["id"])
        if rec.get("status") == "active":
            accounts.login(rec)
            get_guest_token()
            claimed = claim_device_files(rec["id"])
            flash("Adresse confirmée, ton compte est prêt ✅"
                  + (f" {claimed} fichier(s) envoyé(s) depuis ce navigateur y ont été ajoutés." if claimed else ""), "success")
            return attach_guest_cookie(redirect(url_for("account.page")))
        flash("Adresse confirmée.", "success")
        return redirect(url_for("account.login"))
    return _page("account_confirm.html", title="Confirmer mon adresse", email=rec.get("email", ""),
                 already=bool(rec.get("confirmed_at")))


@account_bp.route("/inscription/renvoyer", methods=["GET", "POST"], endpoint="resend")
def resend():
    if request.method == "POST":
        validate_csrf()
        ip = get_client_ip()
        if not turnstile_ok(request.form, ip):
            flash("Vérification anti-robot échouée : coche la case puis réessaie.", "warning")
        elif not _rate_ok("account_mail", ip, MAILS_PER_HOUR, 3600):
            flash("Trop de demandes. Réessaie dans une heure.", "warning")
        else:
            rec = accounts.find_by_email(request.form.get("email") or "")
            if rec and not rec.get("confirmed_at"):
                accounts.send_confirmation(rec)
            return _page("account_message.html", title="Vérifie ta boîte mail", heading="Vérifie ta boîte mail",
                         text="Si un compte attend une confirmation avec cette adresse, un nouveau lien vient de partir.")
    return _page("account_email_form.html", title="Renvoyer le mail de confirmation",
                 heading="Renvoyer le mail de confirmation", button="Renvoyer le lien",
                 action=url_for("account.resend"))


# ------------------------------------------------------------------ connexion

@account_bp.route("/connexion", methods=["GET", "POST"], endpoint="login")
def login():
    if accounts.current_account():
        return redirect(url_for("account.page"))
    email = ""
    status = 200
    if request.method == "POST":
        validate_csrf()
        ip = get_client_ip()
        email = (request.form.get("email") or "").strip()[:254]
        mail_key = "acctmail:" + accounts.email_key(email)
        if is_locked("acct:" + ip)[0] or is_locked(mail_key)[0]:
            flash("Trop d'essais ratés. Réessaie dans quelques minutes.", "danger")
            status = 429
        else:
            rec = accounts.authenticate(email, request.form.get("password") or "")
            if not rec:
                time.sleep(0.4)
                register_fail("acct:" + ip, max_failures=LOGIN_FAILS)
                register_fail(mail_key, max_failures=EMAIL_LOGIN_FAILS)
                flash("Adresse ou mot de passe incorrect.", "danger")
                status = 401
            elif not rec.get("confirmed_at"):
                flash("Confirme d'abord ton adresse avec le lien reçu par mail.", "warning")
                return redirect(url_for("account.resend"))
            elif rec.get("status") != "active":
                flash("Ce compte est suspendu. Écris-nous via le formulaire de contact si tu penses que c'est une erreur.", "danger")
                status = 403
            else:
                reset_fail("acct:" + ip)
                accounts.login(rec)
                get_guest_token()
                claimed = claim_device_files(rec["id"])
                flash("Connecté ✅" + (f" {claimed} fichier(s) de ce navigateur ajouté(s) à ton compte." if claimed else ""),
                      "success")
                target = request.args.get("next") or ""
                if not target.startswith("/") or target.startswith("//"):
                    target = url_for("public.index")
                return attach_guest_cookie(redirect(target))
    response = _page("account_login.html", title="Connexion", email=email, accounts_on=accounts_enabled())
    response.status_code = status
    return response


@account_bp.route("/deconnexion", methods=["POST"], endpoint="logout")
def logout():
    validate_csrf()
    accounts.logout()
    flash("Tu es déconnecté.", "info")
    return redirect(url_for("public.index"))


# ------------------------------------------------------------------ mot de passe oublié

@account_bp.route("/mot-de-passe-oublie", methods=["GET", "POST"], endpoint="forgot")
def forgot():
    if request.method == "POST":
        validate_csrf()
        ip = get_client_ip()
        if not turnstile_ok(request.form, ip):
            flash("Vérification anti-robot échouée : coche la case puis réessaie.", "warning")
        elif not _rate_ok("account_mail", ip, MAILS_PER_HOUR, 3600):
            flash("Trop de demandes. Réessaie dans une heure.", "warning")
        else:
            rec = accounts.find_by_email(request.form.get("email") or "")
            if rec and rec.get("confirmed_at"):
                accounts.send_reset(rec)
            return _page("account_message.html", title="Vérifie ta boîte mail", heading="Vérifie ta boîte mail",
                         text="Si un compte existe avec cette adresse, un lien pour choisir un nouveau mot de passe "
                              "vient de partir. Il est valable 1 heure.")
    return _page("account_email_form.html", title="Mot de passe oublié", heading="Mot de passe oublié",
                 button="Recevoir un lien", action=url_for("account.forgot"))


@account_bp.route("/mot-de-passe/<token>", methods=["GET", "POST"], endpoint="reset")
def reset(token):
    rec, error = accounts.read_token("reset", token)
    if not rec:
        return _page("account_message.html", title="Lien invalide", heading="Lien invalide", text=error), 400
    if request.method == "POST":
        validate_csrf()
        password = request.form.get("password") or ""
        if password != (request.form.get("password2") or ""):
            flash("Les deux mots de passe ne sont pas identiques.", "warning")
        else:
            try:
                rec = accounts.set_password(rec["id"], password)
            except accounts.AccountError as exc:
                flash(str(exc), "warning")
            else:
                if rec.get("status") == "active":
                    accounts.login(rec)
                    flash("Nouveau mot de passe enregistré ✅ Les autres appareils sont déconnectés.", "success")
                    return redirect(url_for("account.page"))
                flash("Nouveau mot de passe enregistré.", "success")
                return redirect(url_for("account.login"))
    return _page("account_reset.html", title="Nouveau mot de passe", password_min=accounts.PASSWORD_MIN)


# ------------------------------------------------------------------ mon compte

def _account_page(rec: dict, new_key: str = ""):
    files = [m for m in load_db().values()
             if isinstance(m, dict) and m.get("account_id") == rec["id"]
             and (m.get("status") or "active").lower() in ("active", "pending")]
    return _page("account_page.html", title="Mon compte", rec=rec, file_count=len(files),
                 pending_count=sum(1 for m in files if (m.get("status") or "").lower() == "pending"),
                 limits=limits_table(), password_min=accounts.PASSWORD_MIN, new_key=new_key)


@account_bp.route("/compte", methods=["GET"], endpoint="page")
def page():
    rec = accounts.current_account()
    if not rec:
        return redirect(url_for("account.login", next="/compte"))
    return _account_page(rec)


@account_bp.route("/compte/extension/cle", methods=["POST"], endpoint="extension_key")
def extension_key():
    """Crée (ou remplace) la clé de l'extension et l'affiche une seule fois, sans passer par un cookie."""
    validate_csrf()
    rec = accounts.current_account()
    if not rec:
        return redirect(url_for("account.login"))
    key = accounts.create_extension_key(rec["id"])
    return _account_page(accounts.get_account(rec["id"]), new_key=key)


@account_bp.route("/compte/extension/supprimer", methods=["POST"], endpoint="extension_revoke")
def extension_revoke():
    validate_csrf()
    rec = accounts.current_account()
    if not rec:
        return redirect(url_for("account.login"))
    accounts.revoke_extension_key(rec["id"])
    flash("Clé de l'extension supprimée : l'extension ne peut plus rien envoyer.", "success")
    return redirect(url_for("account.page") + "#extension")


@account_bp.route("/compte/mot-de-passe", methods=["POST"], endpoint="change_password")
def change_password():
    validate_csrf()
    rec = accounts.current_account()
    if not rec:
        return redirect(url_for("account.login"))
    if not accounts.authenticate(rec["email"], request.form.get("current_password") or ""):
        flash("Mot de passe actuel incorrect.", "danger")
    elif (request.form.get("password") or "") != (request.form.get("password2") or ""):
        flash("Les deux nouveaux mots de passe ne sont pas identiques.", "warning")
    else:
        try:
            rec = accounts.set_password(rec["id"], request.form.get("password") or "")
        except accounts.AccountError as exc:
            flash(str(exc), "warning")
        else:
            accounts.login(rec)
            flash("Mot de passe changé ✅ Les autres appareils sont déconnectés.", "success")
    return redirect(url_for("account.page"))


@account_bp.route("/compte/supprimer", methods=["POST"], endpoint="delete")
def delete():
    validate_csrf()
    rec = accounts.current_account()
    if not rec:
        return redirect(url_for("account.login"))
    if request.form.get("confirm") != "1" or not accounts.authenticate(rec["email"], request.form.get("password") or ""):
        flash("Coche la case et donne ton mot de passe pour supprimer le compte.", "danger")
        return redirect(url_for("account.page"))
    removed = accounts.delete_account(rec["id"])
    flash(f"Compte supprimé, avec ses {removed} fichier(s). Ton adresse e-mail a été effacée.", "success")
    return redirect(url_for("public.index"))


# ------------------------------------------------------------------ fichiers du membre

@account_bp.route("/mes-images/<file_id>/apercu", endpoint="owner_preview")
def owner_preview(file_id):
    """Aperçu d'une image pour celui qui l'a envoyée (même en attente de modération), sur tous ses appareils."""
    meta = load_db().get(file_id)
    if not isinstance(meta, dict) or (meta.get("status") or "active").lower() not in ("active", "pending"):
        abort(404)
    if not (is_owner(meta) or is_admin()):
        abort(404)
    folder = current_app.config["UPLOAD_FOLDER"]
    name = os.path.basename(str(meta.get("server_name") or ""))
    if os.path.isfile(medium_path(file_id)):
        name = os.path.basename(medium_path(file_id))
    if not name or not os.path.isfile(os.path.join(folder, name)):
        abort(404)
    response = make_response(send_from_directory(folder, name, as_attachment=False))
    response.headers["Cache-Control"] = "private, max-age=300"
    response.headers["X-Robots-Tag"] = "noindex, noimageindex"
    return response


@account_bp.route("/remplacer/<file_id>", methods=["POST"], endpoint="replace")
def replace(file_id):
    validate_csrf()
    rec = accounts.current_account()
    if not rec:
        flash("Remplacer une image en gardant son lien est réservé aux comptes.", "warning")
        return redirect(url_for("account.login"))
    back = redirect(url_for("public.index") + f"#file-{file_id}")
    meta = load_db().get(file_id)
    if not isinstance(meta, dict) or meta.get("account_id") != rec["id"]:
        abort(404)
    if (meta.get("status") or "active").lower() not in ("active", "pending"):
        abort(404)
    if _blocked():
        abort(403)
    if not upload_service_enabled():
        flash("Le service d'envoi est suspendu pour le moment.", "warning")
        return back
    f = request.files.get("file")
    if not f or not f.filename:
        flash("Choisis le nouveau fichier.", "warning")
        return back
    safe_name = secure_filename(f.filename)
    if not safe_name or not allowed_file(safe_name):
        flash("Ce format de fichier n'est pas accepté.", "danger")
        return back
    ip = get_client_ip()
    rate = check_upload_rate(f"acct:{rec['id']}", exempt=is_admin(), limit=get_uploads_per_hour(True))
    if not rate.allowed:
        flash(limit_message(rate, member=True), "warning")
        return back
    if not has_room_for(request.content_length):
        flash("Le stockage est plein pour le moment. Réessaie un peu plus tard.", "warning")
        return back
    max_bytes = get_max_upload_size_bytes()
    if (request.content_length or 0) > max_bytes:
        flash(f"Fichier trop volumineux. Taille maximale : {get_max_upload_size_mb()} Mo.", "danger")
        return back
    try:
        replace_file(file_id, f, f.filename, ip, max_bytes)
    except FileTooLargeError:
        flash(f"Fichier trop volumineux. Taille maximale : {get_max_upload_size_mb()} Mo.", "danger")
        return back
    except BannedImageError:
        flash("Cette image a déjà été refusée par la modération : elle ne peut pas être publiée.", "danger")
        return back
    except FileNotFoundError:
        abort(404)
    if requires_image_moderation(safe_name):
        flash("Image remplacée ✅ Le lien reste le même. Elle redevient visible après la vérification automatique "
              "(les anciennes copies en cache peuvent mettre quelques minutes à disparaître).", "success")
    else:
        flash("Fichier remplacé ✅ Le lien reste le même.", "success")
    return back
