"""Comptes PixShare : inscription par e-mail + mot de passe.

- Les comptes sont rangés dans accounts.json (disque persistant). Le mot de passe n'est jamais
  gardé : seulement son empreinte (werkzeug, scrypt/pbkdf2).
- L'adresse doit être confirmée par un lien reçu par mail (signé, valable 48 h) avant la connexion.
- « Mot de passe oublié » : lien signé valable 1 heure, utilisable une seule fois
  (il contient la version du mot de passe, qui change dès qu'on le modifie).
- Changer de mot de passe déconnecte les autres appareils.
- Les comptes jamais confirmés sont effacés au bout de 7 jours.
- Après ACCOUNT_STRIKES images refusées par la modération, le compte est suspendu (réactivable dans l'admin).
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone

from flask import current_app, g, session, url_for
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

from pixshare.services.json_services import _json_lock, load_json, save_json
from pixshare.services.time_service import parse_dt, utcnow

ACCOUNTS_FILE = "accounts.json"
SESSION_KEY = "account"
PASSWORD_MIN = 8
PASSWORD_MAX = 128
EMAIL_MAX = 254
CONFIRM_MAX_AGE = 48 * 3600
RESET_MAX_AGE = 3600
UNCONFIRMED_DAYS = 7
ACCOUNT_STRIKES = 3
_SALT = "pixshare-account-v1"
_EMAIL_RE = re.compile(r"^[^@\s<>\"',;]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
# Empreinte factice : on fait le même calcul quand l'adresse est inconnue (pas de différence de durée).
_DUMMY_HASH = generate_password_hash("pixshare-dummy-password")


class AccountError(ValueError):
    """Erreur affichable telle quelle à l'utilisateur."""


# ------------------------------------------------------------------ stockage

def _now_iso() -> str:
    return utcnow().isoformat(timespec="seconds")


def _load() -> dict:
    data = load_json(ACCOUNTS_FILE, {"accounts": {}})
    if not isinstance(data, dict) or not isinstance(data.get("accounts"), dict):
        data = {"accounts": {}}
    return data


def _prune(data: dict) -> bool:
    """Efface les comptes jamais confirmés depuis plus de 7 jours."""
    limit = utcnow() - timedelta(days=UNCONFIRMED_DAYS)
    stale = []
    for account_id, rec in data["accounts"].items():
        if rec.get("confirmed_at"):
            continue
        try:
            created = parse_dt(rec.get("created_at") or "")
        except Exception:
            created = None
        if created is None or created < limit:
            stale.append(account_id)
    for account_id in stale:
        data["accounts"].pop(account_id, None)
    return bool(stale)


def all_accounts() -> dict:
    with _json_lock:
        data = _load()
        if _prune(data):
            save_json(ACCOUNTS_FILE, data)
        return data["accounts"]


def get_account(account_id: str) -> dict | None:
    if not account_id:
        return None
    rec = _load()["accounts"].get(account_id)
    return dict(rec, id=account_id) if isinstance(rec, dict) else None


def _update(account_id: str, **changes) -> dict | None:
    with _json_lock:
        data = _load()
        rec = data["accounts"].get(account_id)
        if not isinstance(rec, dict):
            return None
        rec.update(changes)
        save_json(ACCOUNTS_FILE, data)
        return dict(rec, id=account_id)


# ------------------------------------------------------------------ validation

def normalize_email(email: str) -> str:
    email = (email or "").strip()
    if len(email) > EMAIL_MAX or not _EMAIL_RE.match(email):
        raise AccountError("Adresse e-mail invalide.")
    local, _at, domain = email.rpartition("@")
    return f"{local}@{domain.lower()}"


def email_key(email: str) -> str:
    return email.strip().lower()


def check_password_rules(password: str, email: str = "") -> None:
    password = password or ""
    if len(password) < PASSWORD_MIN:
        raise AccountError(f"Le mot de passe doit faire au moins {PASSWORD_MIN} caractères.")
    if len(password) > PASSWORD_MAX:
        raise AccountError(f"Le mot de passe doit faire au plus {PASSWORD_MAX} caractères.")
    if email and password.strip().lower() == email.strip().lower():
        raise AccountError("Le mot de passe ne doit pas être votre adresse e-mail.")


def find_by_email(email: str) -> dict | None:
    key = email_key(email or "")
    for account_id, rec in all_accounts().items():
        if isinstance(rec, dict) and rec.get("email_key") == key:
            return dict(rec, id=account_id)
    return None


# ------------------------------------------------------------------ création, connexion

def create_account(email: str, password: str) -> tuple[dict, bool]:
    """(compte, nouveau). Adresse déjà confirmée : (compte existant, False), rien n'est modifié.
    Adresse en attente de confirmation : le mot de passe est remplacé (nouvelle inscription)."""
    email = normalize_email(email)
    check_password_rules(password, email)
    with _json_lock:
        data = _load()
        _prune(data)
        key = email_key(email)
        for account_id, rec in data["accounts"].items():
            if rec.get("email_key") == key:
                if rec.get("confirmed_at"):
                    return dict(rec, id=account_id), False
                rec.update(password_hash=generate_password_hash(password), pw_ver=int(rec.get("pw_ver") or 0) + 1,
                           created_at=_now_iso())
                save_json(ACCOUNTS_FILE, data)
                return dict(rec, id=account_id), True
        account_id = secrets.token_urlsafe(9).replace("-", "").replace("_", "")
        rec = {
            "email": email,
            "email_key": key,
            "password_hash": generate_password_hash(password),
            "pw_ver": 1,
            "created_at": _now_iso(),
            "confirmed_at": "",
            "last_login_at": "",
            "status": "active",
            "strikes": 0,
        }
        data["accounts"][account_id] = rec
        save_json(ACCOUNTS_FILE, data)
        return dict(rec, id=account_id), True


def authenticate(email: str, password: str) -> dict | None:
    """Compte si l'adresse et le mot de passe sont bons (confirmé ou non), sinon None."""
    try:
        rec = find_by_email(normalize_email(email))
    except AccountError:
        rec = None
    stored = (rec or {}).get("password_hash") or _DUMMY_HASH
    try:
        ok = check_password_hash(stored, password or "")
    except Exception:
        ok = False
    return rec if (rec and ok) else None


def confirm_account(account_id: str) -> dict | None:
    rec = get_account(account_id)
    if not rec:
        return None
    if rec.get("confirmed_at"):
        return rec
    return _update(account_id, confirmed_at=_now_iso())


def set_password(account_id: str, password: str) -> dict | None:
    rec = get_account(account_id)
    if not rec:
        return None
    check_password_rules(password, rec.get("email", ""))
    # Nouveau mot de passe : la clé de l'extension est désactivée aussi (à recréer dans « Mon compte »).
    return _update(account_id, password_hash=generate_password_hash(password), pw_ver=int(rec.get("pw_ver") or 0) + 1,
                   ext_key_hash="", ext_key_created="", ext_key_last_used="")


def set_status(account_id: str, status: str) -> dict | None:
    if status not in ("active", "suspended"):
        return None
    changes = {"status": status}
    if status == "active":
        changes["strikes"] = 0
    return _update(account_id, **changes)


def strikes_max() -> int:
    """Refus avant suspension (réglage admin, 0 = jamais de suspension automatique)."""
    from pixshare.services.settings_service import load_settings
    value = load_settings().get("member_strikes_max")
    return ACCOUNT_STRIKES if value is None else int(value)


def add_strike(account_id: str) -> dict | None:
    """Une image du compte a été refusée par la modération. Trop de refus : compte suspendu."""
    rec = get_account(account_id)
    if not rec:
        return None
    strikes = int(rec.get("strikes") or 0) + 1
    changes = {"strikes": strikes}
    limit = strikes_max()
    if limit and strikes >= limit:
        changes["status"] = "suspended"
    return _update(account_id, **changes)


# ------------------------------------------------------------------ formule personnalisée d'un compte

PLAN_NAME_MAX = 40
PLAN_MAX_MB = 1000          # limite des requêtes du serveur (MAX_CONTENT_LENGTH)
PLAN_MAX_PER_HOUR = 10000


def clean_plan(raw) -> dict:
    """Formule d'un compte. Champ absent = réglage général des membres."""
    from pixshare.services.settings_service import MAX_LIFETIME_CHOICES
    raw = raw if isinstance(raw, dict) else {}
    plan: dict = {}
    name = " ".join(str(raw.get("name") or "").split())[:PLAN_NAME_MAX]
    name = "".join(c for c in name if c not in "<>\"{}")
    if name:
        plan["name"] = name

    def _int(key, low, high):
        value = raw.get(key)
        if value in (None, ""):
            return None
        try:
            value = int(value)
        except (TypeError, ValueError):
            return None
        return value if low <= value <= high else None

    life = _int("life", 1, 10 ** 7)
    if life in MAX_LIFETIME_CHOICES:
        plan["life"] = life
    mb = _int("mb", 1, PLAN_MAX_MB)
    if mb:
        plan["mb"] = mb
    per_hour = _int("per_hour", 0, PLAN_MAX_PER_HOUR)
    if per_hour is not None:
        plan["per_hour"] = per_hour
    albums = _int("albums", 0, 200)
    if albums is not None:
        plan["albums"] = albums
    album_mb = _int("album_mb", 10, 100000)
    if album_mb:
        plan["album_mb"] = album_mb
    if raw.get("no_ads") in (True, "1", 1):
        plan["no_ads"] = True
    until = str(raw.get("until") or "").strip()
    try:
        plan["until"] = datetime.strptime(until, "%Y-%m-%d").strftime("%Y-%m-%d") if until else ""
    except ValueError:
        plan["until"] = ""
    if not plan.get("until"):
        plan.pop("until", None)
    return plan


def plan_expired(plan: dict) -> bool:
    until = (plan or {}).get("until")
    return bool(until) and until < datetime.now(timezone.utc).strftime("%Y-%m-%d")


def active_plan(rec: dict | None) -> dict:
    """Formule en vigueur du compte ({} = réglages généraux des membres)."""
    plan = clean_plan((rec or {}).get("plan"))
    if not plan or plan_expired(plan):
        return {}
    return plan


def set_plan(account_id: str, raw) -> dict | None:
    plan = clean_plan(raw)
    return _update(account_id, plan=plan)


def delete_account(account_id: str) -> int:
    """Efface le compte et tous ses fichiers. Renvoie le nombre de fichiers supprimés."""
    from pixshare.services.file_service import delete_by_id
    from pixshare.services.json_services import load_db, save_db

    removed = 0
    try:  # ses albums, avec les photos que les invités y ont ajoutées
        from pixshare.services.album_service import delete_all_for
        removed += delete_all_for(account_id)
    except Exception:
        pass
    for file_id, meta in list(load_db().items()):
        if isinstance(meta, dict) and meta.get("account_id") == account_id:
            if (meta.get("status") or "active").lower() in ("active", "pending"):
                if delete_by_id(file_id, reason="account_deleted"):
                    removed += 1
    # On retire aussi le lien entre les anciennes fiches et le compte effacé.
    db = load_db()
    changed = False
    for meta in db.values():
        if isinstance(meta, dict) and meta.get("account_id") == account_id:
            meta.pop("account_id", None)
            changed = True
    if changed:
        save_db(db)
    with _json_lock:
        data = _load()
        data["accounts"].pop(account_id, None)
        save_json(ACCOUNTS_FILE, data)
    if current_account_id() == account_id:
        logout()
    return removed


# ------------------------------------------------------------------ session

def login(rec: dict) -> None:
    session[SESSION_KEY] = {"id": rec["id"], "v": int(rec.get("pw_ver") or 0)}
    session.permanent = True
    g.pop("pixshare_account", None)
    _update(rec["id"], last_login_at=_now_iso())


def logout() -> None:
    session.pop(SESSION_KEY, None)
    g.pop("pixshare_account", None)


def current_account() -> dict | None:
    """Membre connecté (compte confirmé, actif, mot de passe inchangé depuis la connexion)."""
    if "pixshare_account" in g:
        return g.pixshare_account
    rec = None
    info = session.get(SESSION_KEY)
    if isinstance(info, dict) and info.get("id"):
        found = get_account(str(info["id"]))
        if (found and found.get("confirmed_at") and found.get("status") == "active"
                and int(found.get("pw_ver") or 0) == int(info.get("v") or -1)):
            rec = found
        else:
            session.pop(SESSION_KEY, None)
    g.pixshare_account = rec
    return rec


def current_account_id() -> str:
    rec = current_account()
    return rec["id"] if rec else ""


def is_member() -> bool:
    from pixshare.services.auth_service import is_admin
    return bool(is_admin() or current_account())


# ------------------------------------------------------------------ clé de l'extension de navigateur

EXT_KEY_PREFIX = "pxs_"


def _key_hash(key: str) -> str:
    return hashlib.sha256((key or "").encode("utf-8")).hexdigest()


def create_extension_key(account_id: str) -> str:
    """Nouvelle clé pour l'extension (l'ancienne ne marche plus). Affichée une seule fois :
    seule son empreinte est gardée."""
    key = EXT_KEY_PREFIX + secrets.token_urlsafe(32)
    _update(account_id, ext_key_hash=_key_hash(key), ext_key_created=_now_iso(), ext_key_last_used="")
    return key


def revoke_extension_key(account_id: str) -> None:
    _update(account_id, ext_key_hash="", ext_key_created="", ext_key_last_used="")


def account_for_extension_key(key: str) -> dict | None:
    """Compte actif et confirmé correspondant à la clé, sinon None."""
    key = (key or "").strip()
    if not key.startswith(EXT_KEY_PREFIX) or len(key) > 100:
        return None
    wanted = _key_hash(key)
    for account_id, rec in all_accounts().items():
        stored = (rec or {}).get("ext_key_hash") or ""
        if stored and hmac.compare_digest(stored, wanted):
            if rec.get("confirmed_at") and rec.get("status") == "active":
                return dict(rec, id=account_id)
            return None
    return None


def act_as(rec: dict) -> None:
    """Pour cette requête seulement (extension) : le membre de la clé est le membre courant."""
    g.pixshare_account = rec
    now = _now_iso()
    if rec.get("id") and (rec.get("ext_key_last_used") or "")[:15] != now[:15]:  # au plus une écriture toutes les 10 min
        _update(rec["id"], ext_key_last_used=now)


# ------------------------------------------------------------------ liens signés

def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(str(current_app.config.get("SECRET_KEY") or current_app.secret_key), salt=_SALT)


def make_token(kind: str, rec: dict) -> str:
    return _serializer().dumps({"k": kind, "a": rec["id"], "v": int(rec.get("pw_ver") or 0)})


def read_token(kind: str, token: str) -> tuple[dict | None, str]:
    """(compte, "") si le lien est bon, sinon (None, message)."""
    max_age = CONFIRM_MAX_AGE if kind == "confirm" else RESET_MAX_AGE
    try:
        data = _serializer().loads(token, max_age=max_age)
    except SignatureExpired:
        return None, "Ce lien a expiré. Recommencez la demande."
    except BadSignature:
        return None, "Lien invalide."
    if not isinstance(data, dict) or data.get("k") != kind:
        return None, "Lien invalide."
    rec = get_account(str(data.get("a") or ""))
    if not rec:
        return None, "Ce compte n'existe plus."
    if int(rec.get("pw_ver") or 0) != int(data.get("v") or -1):
        return None, "Ce lien a déjà servi ou n'est plus valable."
    return rec, ""


# ------------------------------------------------------------------ mails

def mail_ready() -> bool:
    from pixshare.services.mail_service import account_mail_configured
    return account_mail_configured()


def _send(rec: dict, subject: str, text: str, button: str = "", link: str = "") -> bool:
    from html import escape

    from pixshare.services.mail_service import send_account_mail

    html = ('<div style="font-family:system-ui,Arial,sans-serif;max-width:520px;margin:auto">'
            + "".join(f"<p>{escape(par)}</p>" for par in text.split("\n\n")))
    if link:
        html += (f'<p><a href="{escape(link)}" style="display:inline-block;background:#0d6efd;color:#fff;'
                 f'padding:10px 16px;border-radius:6px;text-decoration:none">{escape(button)}</a></p>'
                 f'<p style="font-size:12px;color:#666">Si le bouton ne marche pas, copie ce lien : {escape(link)}</p>')
    html += '<p style="font-size:12px;color:#666">PixShare · pixshare.fr</p></div>'
    body = text + (f"\n\n{button} : {link}" if link else "") + "\n\nPixShare · pixshare.fr\n"
    ok, _error = send_account_mail(rec["email"], subject, body, html)
    return ok


def send_confirmation(rec: dict) -> bool:
    link = url_for("account.confirm", token=make_token("confirm", rec), _external=True)
    return _send(rec, "PixShare : confirmez votre adresse e-mail",
                 "Bienvenue sur PixShare !\n\nCliquez sur le bouton pour confirmer votre adresse et activer votre compte. "
                 "Le lien est valable 48 heures.\n\nSi vous n'avez pas créé de compte, ignorez simplement ce message : "
                 "le compte sera effacé automatiquement.",
                 "Confirmer mon adresse", link)


def send_already_registered(rec: dict) -> bool:
    link = url_for("account.forgot", _external=True)
    return _send(rec, "PixShare : vous avez déjà un compte",
                 "Quelqu'un (sans doute vous) a voulu créer un compte PixShare avec cette adresse, "
                 "mais vous en avez déjà un.\n\nSi vous avez oublié votre mot de passe, vous pouvez en choisir un nouveau. "
                 "Sinon, ignorez ce message.",
                 "Choisir un nouveau mot de passe", link)


def send_reset(rec: dict) -> bool:
    link = url_for("account.reset", token=make_token("reset", rec), _external=True)
    return _send(rec, "PixShare : nouveau mot de passe",
                 "Vous avez demandé à changer le mot de passe de votre compte PixShare. Le lien est valable 1 heure "
                 "et ne sert qu'une fois.\n\nSi ce n'est pas vous, ignorez ce message : votre mot de passe ne change pas.",
                 "Choisir un nouveau mot de passe", link)
