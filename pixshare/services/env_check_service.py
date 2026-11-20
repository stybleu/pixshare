"""Variables d'environnement (Render) : lesquelles sont définies, lesquelles manquent, et les problèmes.

Les valeurs secrètes (mots de passe, clés) ne sont JAMAIS affichées : seulement « définie » et leur longueur.
"""
from __future__ import annotations

import os

# (nom, rôle, secret ?)
GROUPS = [
    ("Indispensables", [
        ("SECRET_KEY", "Clé de sécurité des sessions et des liens signés", True),
        ("ADMIN_USER", "Identifiant de l'admin", True),
        ("ADMIN_PASS", "Mot de passe de l'admin", True),
        ("PIXSHARE_DATA_DIR", "Dossier du disque persistant (ex. /var/data)", False),
    ]),
    ("Alertes mail pour toi (images à vérifier)", [
        ("MAIL_SMTP_HOST", "Serveur d'envoi (ex. smtp.orange.fr)", False),
        ("MAIL_SMTP_PORT", "Port (465 ou 587)", False),
        ("MAIL_SMTP_USER", "Identifiant de la boîte d'envoi", False),
        ("MAIL_SMTP_PASS", "Mot de passe de la boîte d'envoi", True),
        ("MAIL_TO", "Adresse qui reçoit les alertes", False),
        ("MAIL_FROM", "Expéditeur affiché", False),
        ("MAIL_SITE_URL", "Adresse du site dans les mails", False),
        ("MAIL_REVIEW_IMAGE", "Aperçu dans le mail : net, flou ou aucune", False),
    ]),
    ("Mails aux membres (confirmation, mot de passe oublié)", [
        ("ACCOUNT_MAIL_SMTP_HOST", "Serveur d'envoi de la boîte dédiée (ex. smtp.gmail.com)", False),
        ("ACCOUNT_MAIL_SMTP_PORT", "Port (465 conseillé)", False),
        ("ACCOUNT_MAIL_SMTP_USER", "Adresse de la boîte dédiée", False),
        ("ACCOUNT_MAIL_SMTP_PASS", "Mot de passe d'application de la boîte dédiée", True),
        ("ACCOUNT_MAIL_FROM", "Expéditeur affiché aux membres", False),
    ]),
    ("Anti-robot Cloudflare Turnstile", [
        ("TURNSTILE_SITE_KEY", "Clé publique du widget", False),
        ("TURNSTILE_SECRET_KEY", "Clé secrète", True),
    ]),
    ("Réglages et apparence", [
        ("PIXSHARE_SETTINGS", "Sauvegarde des réglages de l'admin (copiée depuis Paramètres)", False),
        ("SUPPORT_URL", "Lien « Soutenir PixShare »", False),
        ("SEASON_THEME", "Thème de saison", False),
        ("SKY_THEME", "Ciel animé", False),
    ]),
    ("Sauvegarde de secours (Cloudflare R2)", [
        ("R2_ACCOUNT_ID", "Identifiant du compte Cloudflare", False),
        ("R2_ACCESS_KEY_ID", "Identifiant de la clé d'accès R2", True),
        ("R2_SECRET_ACCESS_KEY", "Clé secrète R2", True),
        ("R2_BUCKET", "Nom de l'espace de stockage (bucket)", False),
    ]),
    ("Limites et stockage", [
        ("MAX_LIFETIME_MIN", "Durée maximale des membres en minutes (sinon 1 an)", False),
        ("UPLOAD_RATE_LIMIT", "Envois par fenêtre (0 = aucune limite)", False),
        ("UPLOAD_RATE_WINDOW_SEC", "Fenêtre de la limite d'envois, en secondes", False),
        ("DISK_RESERVE_MB", "Espace gardé libre sur le disque", False),
        ("RAM_LIMIT_MB", "Mémoire de l'offre Render", False),
    ]),
    ("Modération", [
        ("NSFW_AUTO_MODERATION", "NudeNet activé par défaut", False),
        ("NSFW_REVIEW_THRESHOLD", "Seuil de revue par défaut", False),
        ("NSFW_BLOCK_THRESHOLD", "Seuil de suppression par défaut", False),
        ("NSFW_CLASSES", "Parties du corps surveillées par défaut", False),
        ("MODERATION_PENDING_IMAGES", "Images privées jusqu'à l'analyse", False),
        ("BANNED_SIMILARITY", "Ressemblance avec une image déjà refusée", False),
        ("REPORT_HIDE_THRESHOLD", "Signalements avant masquage", False),
        ("STRIP_IMAGE_METADATA", "Retrait des métadonnées des photos", False),
    ]),
    ("Technique", [
        ("TRUSTED_PROXY_COUNT", "Nombre de relais devant le site (lecture de l'IP)", False),
        ("PIXSHARE_STORAGE", "Stockage : base SQLite (par défaut) ou « json » en secours", False),
        ("SESSION_COOKIE_SECURE", "Cookie de session en HTTPS seulement", False),
        ("UPLOAD_FOLDER", "Dossier des fichiers (sinon sur le disque)", False),
        ("THUMBNAIL_FOLDER", "Dossier des miniatures (sinon sur le disque)", False),
        ("ALLOW_DEFAULT_ADMIN", "Admin sans mot de passe (développement seulement)", False),
        ("FLASK_DEBUG", "Mode débogage (développement seulement)", False),
    ]),
]

OBSOLETE = {
    "GEOIP": "localisation retirée du site",
    "PERMANENT_UPLOADS": "fichiers permanents retirés",
    "PERMANENT_UPLOADS_ADMIN_ONLY": "fichiers permanents retirés",
}
# Préfixes qui ressemblent à des variables de PixShare : un nom inconnu est sans doute une faute de frappe.
_PREFIXES = ("MAIL_", "ACCOUNT_MAIL", "NSFW_", "TURNSTILE_", "PIXSHARE_", "ADMIN_", "UPLOAD_", "MAX_LIFETIME", "GEOIP",
             "SUPPORT_URL", "SEASON_", "R2_", "SKY_THEME", "REPORT_HIDE", "BANNED_", "DISK_RESERVE", "RAM_LIMIT", "MODERATION_")


def _shown(name: str, value: str, secret: bool) -> str:
    if secret:
        return f"définie (masquée, {len(value)} caractères)"
    if name == "PIXSHARE_SETTINGS":
        return f"définie ({len(value)} caractères)"
    if name == "TURNSTILE_SITE_KEY" and len(value) > 10:
        return value[:6] + "…" + value[-4:]
    return value if len(value) <= 80 else value[:77] + "…"


def check() -> dict:
    env = os.environ
    known = {name for _title, items in GROUPS for name, _role, _secret in items}
    groups = []
    for title, items in GROUPS:
        rows = []
        for name, role, secret in items:
            value = (env.get(name) or "").strip()
            rows.append({"name": name, "role": role, "set": bool(value), "shown": _shown(name, value, secret) if value else ""})
        groups.append({"title": title, "rows": rows, "set_count": sum(1 for r in rows if r["set"])})

    problems: list[tuple[str, str]] = []  # (niveau Bootstrap, message)

    def has(name: str) -> bool:
        return bool((env.get(name) or "").strip())

    if not has("SECRET_KEY"):
        problems.append(("danger", "SECRET_KEY manque : les connexions sont perdues à chaque redémarrage et les liens signés ne sont pas sûrs."))
    if not (has("ADMIN_USER") and has("ADMIN_PASS")):
        problems.append(("danger", "ADMIN_USER ou ADMIN_PASS manque : l'admin est inaccessible."))
    if not has("PIXSHARE_DATA_DIR"):
        problems.append(("warning", "PIXSHARE_DATA_DIR manque : rien n'est sur le disque persistant, tout est effacé à chaque déploiement."))
    if has("ALLOW_DEFAULT_ADMIN"):
        problems.append(("danger", "ALLOW_DEFAULT_ADMIN est définie : à supprimer sur le site en ligne (admin sans vrai mot de passe)."))
    if (env.get("FLASK_DEBUG") or "").strip() not in ("", "0", "false", "False"):
        problems.append(("danger", "FLASK_DEBUG est activé : à supprimer sur le site en ligne (affiche des détails techniques)."))
    r2 = [has(n) for n in ("R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET")]
    if any(r2) and not all(r2):
        problems.append(("warning", "Sauvegarde R2 : il manque une des 4 variables R2_*, la sauvegarde ne se fait pas."))
    if has("TURNSTILE_SITE_KEY") != has("TURNSTILE_SECRET_KEY"):
        problems.append(("warning", "Turnstile : une seule des deux clés est définie, l'anti-robot ne marche pas."))

    mail_vars = ("MAIL_SMTP_HOST", "MAIL_TO")
    if any(has(n) for n in mail_vars) and not all(has(n) for n in mail_vars):
        problems.append(("warning", "Alertes mail : MAIL_SMTP_HOST et MAIL_TO doivent être définies toutes les deux."))
    if has("MAIL_SMTP_HOST") and has("MAIL_SMTP_USER") and not has("MAIL_SMTP_PASS"):
        problems.append(("warning", "Alertes mail : MAIL_SMTP_PASS manque (la connexion au serveur d'envoi va échouer)."))

    if has("ACCOUNT_MAIL_SMTP_HOST"):
        missing = [n for n in ("ACCOUNT_MAIL_SMTP_USER", "ACCOUNT_MAIL_SMTP_PASS") if not has(n)]
        if missing:
            problems.append(("warning", "Mails aux membres : il manque " + ", ".join(missing) + "."))
        sender = (env.get("ACCOUNT_MAIL_FROM") or env.get("ACCOUNT_MAIL_SMTP_USER") or "").lower()
        user = (env.get("ACCOUNT_MAIL_SMTP_USER") or "").lower()
        if "gmail" in (env.get("ACCOUNT_MAIL_SMTP_HOST") or "") and user and user not in sender:
            problems.append(("warning", "Gmail refuse un expéditeur différent de la boîte : ACCOUNT_MAIL_FROM doit contenir ACCOUNT_MAIL_SMTP_USER."))
    elif has("MAIL_SMTP_HOST"):
        sender = env.get("MAIL_FROM") or env.get("MAIL_SMTP_USER") or env.get("MAIL_TO") or ""
        problems.append(("warning", "Pas de boîte dédiée aux membres (ACCOUNT_MAIL_…) : les mails de confirmation partent de "
                                    f"« {sender.strip()} », adresse visible par les inscrits."))
    else:
        problems.append(("info", "Aucun envoi de mail configuré : les inscriptions aux comptes sont fermées."))

    if has("MAX_LIFETIME_MIN"):
        problems.append(("info", f"MAX_LIFETIME_MIN = {env.get('MAX_LIFETIME_MIN')} : les membres ne peuvent pas dépasser cette durée "
                                 "(sans elle : 1 an, ou le maximum choisi dans Paramètres)."))

    for name, why in OBSOLETE.items():
        if has(name) or name in env:
            problems.append(("info", f"{name} ne sert plus ({why}) : tu peux la supprimer sur Render."))
    unknown = sorted(n for n in env if n.startswith(_PREFIXES) and n not in known and n not in OBSOLETE)
    for name in unknown:
        problems.append(("warning", f"{name} : variable inconnue de PixShare (faute de frappe ? ancienne variable ?)."))

    return {"groups": groups, "problems": problems, "on_render": bool(env.get("RENDER") or env.get("RENDER_GIT_COMMIT"))}
