"""« Télécharger mes données » (droit d'accès et portabilité, articles 15 et 20 du RGPD).

Le membre connecté reçoit un .zip avec :
  - mes-donnees.json : tout, dans un format lisible par une machine (portabilité) ;
  - mes-donnees.txt  : le même contenu, en clair, en français.

Jamais : l'empreinte du mot de passe, celle de la clé d'extension, les jetons des appareils,
ni les données d'un autre membre.
"""
from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone

from flask import url_for


def _fmt(value) -> str:
    return str(value or "—")


def _files(account_id: str) -> list[dict]:
    from .json_services import load_db
    items = []
    for file_id, meta in (load_db() or {}).items():
        if not isinstance(meta, dict) or meta.get("account_id") != account_id:
            continue
        active = (meta.get("status") or "") == "active"
        items.append({
            "id": file_id,
            "nom": meta.get("original_name") or "",
            "envoye_le": meta.get("uploaded_at") or "",
            "expire_le": meta.get("expires_at") or ("sans expiration" if meta.get("permanent") else ""),
            "etat": meta.get("status") or "",
            "motif_suppression": meta.get("delete_reason") or "",
            "vues": int(meta.get("views") or 0),
            "limite_de_vues": int(meta.get("max_views") or 0) if meta.get("view_limit_enabled") else None,
            "protege_par_mot_de_passe": bool(meta.get("password_hash")),
            "filtre": meta.get("photo_filter") or "",
            "album": meta.get("album_id") or "",
            "adresse_ip_de_l_envoi": meta.get("ip") or "",
            "lien": url_for("public.public_file", file_id=file_id, _external=True) if active else "",
        })
    return sorted(items, key=lambda f: f["envoye_le"], reverse=True)


def _albums(account_id: str) -> list[dict]:
    from . import album_service as albums
    out = []
    for album in albums.list_for(account_id):
        aid = album.get("id")
        out.append({
            "id": aid,
            "nom": album.get("name") or "",
            "petit_mot": album.get("description") or "",
            "cree_le": album.get("created_at") or "",
            "theme": album.get("theme") or "",
            "protege_par_mot_de_passe": bool(album.get("password_hash")),
            "les_invites_peuvent_ajouter": bool(album.get("guests_can_add", True)),
            "lien": url_for("album.view", album_id=aid, _external=True),
            "photos": [{"id": p.get("id", ""), "nom": p.get("original_name", ""),
                        "ajoutee_par": "vous" if not p.get("album_guest") else (p.get("album_contributor") or "un invité")}
                       for p in albums.photos(aid)],
            "livre_d_or": [{"prenom": m.get("name", ""), "message": m.get("text", ""), "le": m.get("at", "")}
                           for m in albums.guestbook(aid)],
        })
    return out


def _legal_rows(rec: dict) -> list[dict]:
    """Lignes du registre légal qui concernent CE membre (comparaison exacte, jamais approchée)."""
    from . import legal_log_service as legal
    email = (rec.get("email") or "").lower()
    seen, rows = set(), []
    for query in (email, rec.get("id") or ""):
        if not query:
            continue
        for r in legal.search(query, 100000):
            mine = (str(r.get("author") or "").lower() == email and email) or r.get("content") == rec.get("id")
            key = (r.get("at"), r.get("op"), r.get("content"), r.get("ip"))
            if mine and key not in seen:
                seen.add(key)
                rows.append({"le": r.get("at", ""), "operation": r.get("op", ""), "contenu": r.get("content", ""),
                             "adresse_ip": r.get("ip", ""), "protocole": r.get("proto", "")})
    return sorted(rows, key=lambda r: r["le"], reverse=True)


def collect(rec: dict) -> dict:
    from . import device_service
    account = {
        "adresse_e_mail": rec.get("email") or "",
        "inscrit_le": rec.get("created_at") or "",
        "confirme_le": rec.get("confirmed_at") or "",
        "derniere_connexion": rec.get("last_login_at") or "",
        "etat": rec.get("status") or "",
        "images_refusees": int(rec.get("strikes") or 0),
        "formule": rec.get("plan") or "standard",
        "cle_d_extension": ({"creee_le": rec.get("ext_key_created") or "",
                             "derniere_utilisation": rec.get("ext_key_last_used") or ""}
                            if rec.get("ext_key_hash") else None),
        "appareils_reconnus": [{"appareil": d.get("label", ""), "ajoute_le": d.get("added", ""), "vu_le": d.get("seen", "")}
                               for d in device_service.devices(rec)],
    }
    return {
        "genere_le": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "site": "PixShare",
        "compte": account,
        "fichiers": _files(rec["id"]),
        "albums": _albums(rec["id"]),
        "registre_legal": _legal_rows(rec),
        "a_savoir": ("Les dates sont en temps universel (UTC). Le registre légal est gardé un an pour la justice "
                     "(obligation des hébergeurs) puis effacé automatiquement. Les mots de passe ne sont jamais "
                     "conservés en clair : ils ne figurent donc pas ici."),
    }


def to_text(data: dict) -> str:
    c = data["compte"]
    lines = [
        "VOS DONNÉES SUR PIXSHARE",
        f"Fichier créé le {data['genere_le']} (heure UTC)",
        "",
        "== Votre compte ==",
        f"Adresse e-mail : {_fmt(c['adresse_e_mail'])}",
        f"Inscrit le : {_fmt(c['inscrit_le'])} · confirmé le : {_fmt(c['confirme_le'])}",
        f"Dernière connexion : {_fmt(c['derniere_connexion'])}",
        f"Images refusées par la modération : {c['images_refusees']}",
        f"Clé d'extension : {'oui' if c['cle_d_extension'] else 'aucune'}",
        f"Appareils reconnus : {len(c['appareils_reconnus'])}",
    ]
    lines += [f"  - {d['appareil']} (ajouté le {d['ajoute_le']}, vu le {d['vu_le']})" for d in c["appareils_reconnus"]]
    lines += ["", f"== Vos photos, vidéos et sons ({len(data['fichiers'])}) =="]
    for f in data["fichiers"]:
        extra = []
        if f["protege_par_mot_de_passe"]:
            extra.append("mot de passe")
        if f["limite_de_vues"]:
            extra.append(f"limite {f['limite_de_vues']} vues")
        if f["filtre"]:
            extra.append(f"filtre {f['filtre']}")
        lines.append(f"- {f['nom']} · envoyé le {f['envoye_le']} · {f['etat']} · {f['vues']} vue(s)"
                     + (f" · {', '.join(extra)}" if extra else "") + (f"\n    {f['lien']}" if f["lien"] else ""))
    lines += ["", f"== Vos albums ({len(data['albums'])}) =="]
    for a in data["albums"]:
        lines.append(f"- {a['nom']} · créé le {a['cree_le']} · {len(a['photos'])} photo(s) · "
                     f"{len(a['livre_d_or'])} message(s) dans le livre d'or\n    {a['lien']}")
    lines += ["", f"== Registre légal ({len(data['registre_legal'])} ligne(s), gardées un an pour la justice) =="]
    lines += [f"- {r['le']} · {r['operation']} · {r['contenu']} · IP {r['adresse_ip'] or '—'}" for r in data["registre_legal"]]
    lines += ["", data["a_savoir"], ""]
    return "\n".join(lines)


def build_zip(rec: dict) -> bytes:
    data = collect(rec)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("mes-donnees.json", json.dumps(data, ensure_ascii=False, indent=2))
        z.writestr("mes-donnees.txt", to_text(data))
    return buf.getvalue()
