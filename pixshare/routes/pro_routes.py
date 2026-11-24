"""Espace entreprise (essai) : /pro. Privé, sans expiration, chiffré. Voir services/pro_service.py."""
from __future__ import annotations

from flask import Blueprint, abort, current_app, flash, make_response, redirect, render_template, request, url_for

from pixshare.services import pro_service as pro
from pixshare.security.csrf import validate_csrf

pro_bp = Blueprint("pro", __name__)


def _brand() -> str:
    return str(current_app.config.get("BRAND_NAME") or "PixShare Pro")


def _guard():
    if not pro.allowed():
        from pixshare.services.account_service import current_account
        from pixshare.services.auth_service import is_admin
        if not (current_account() or is_admin()):
            return redirect(url_for("account.login", next=request.path))
        abort(404)                       # pas de « 403 » : on ne confirme même pas que la page existe
    pro.note_support_visit(request.path)
    return None


def _private(response):
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _page(template, **ctx):
    return _private(make_response(render_template(template, brand=_brand(), enterprise=pro.enterprise_mode(),
                                                  manager=pro.is_manager(), support=pro.support_open(), **ctx)))


@pro_bp.route("/pro", methods=["GET"], endpoint="home")
def home():
    if (r := _guard()):
        return r
    return _page("pro_home.html", machines=pro.machines(), recent=pro.recent(),
                 dedicated_key=pro.pro_crypto.uses_dedicated_key())


@pro_bp.route("/pro/machines", methods=["POST"], endpoint="machine_create")
def machine_create():
    if (r := _guard()):
        return r
    validate_csrf()
    try:
        m = pro.create_machine(request.form.get("name"), request.form.get("location"))
    except ValueError as exc:
        flash(str(exc), "warning")
        return redirect(url_for("pro.home"))
    flash(f"Machine « {m['name']} » ajoutée. Imprimez son QR code et collez-le dessus.", "success")
    return redirect(url_for("pro.machine", machine_id=m["id"]))


@pro_bp.route("/pro/machine/<machine_id>", methods=["GET"], endpoint="machine")
def machine(machine_id):
    if (r := _guard()):
        return r
    m = pro.machine(machine_id) or abort(404)
    return _page("pro_machine.html", m=m, items=pro.history(machine_id))


@pro_bp.route("/pro/machine/<machine_id>/qr.<fmt>", methods=["GET"], endpoint="machine_qr")
def machine_qr(machine_id, fmt):
    if (r := _guard()):
        return r
    from pixshare.services import qr_service
    m = pro.machine(machine_id) or abort(404)
    url = url_for("pro.machine", machine_id=machine_id, _external=True)
    if fmt == "svg":
        resp = make_response(qr_service.svg(url))
        resp.headers["Content-Type"] = "image/svg+xml"
    elif fmt == "png":
        resp = make_response(qr_service.png(url, scale=16))
        resp.headers["Content-Type"] = "image/png"
        resp.headers["Content-Disposition"] = f'attachment; filename="QR-{"".join(c for c in m["name"] if c.isalnum() or c in "-_ ")[:40] or "machine"}.png"'
    else:
        abort(404)
    return _private(resp)


@pro_bp.route("/pro/machine/<machine_id>/intervention", methods=["POST"], endpoint="intervention_create")
def intervention_create(machine_id):
    if (r := _guard()):
        return r
    validate_csrf()
    files = {kind: request.files.getlist(f"photos_{kind}") for kind in pro.KINDS}
    try:
        item = pro.create_intervention(machine_id, request.form.get("ref"), request.form.get("comment"), files)
    except ValueError as exc:
        flash(str(exc), "warning")
        return redirect(url_for("pro.machine", machine_id=machine_id) + "#nouvelle")
    flash("Intervention enregistrée ✅", "success")
    return redirect(url_for("pro.intervention", intervention_id=item["id"]))


@pro_bp.route("/pro/intervention/<intervention_id>", methods=["GET"], endpoint="intervention")
def intervention(intervention_id):
    if (r := _guard()):
        return r
    item = pro.intervention(intervention_id) or abort(404)
    return _page("pro_intervention.html", item=item)


@pro_bp.route("/pro/intervention/<intervention_id>.pdf", methods=["GET"], endpoint="intervention_pdf")
def intervention_pdf(intervention_id):
    if (r := _guard()):
        return r
    from pixshare.services import pro_report
    item = pro.intervention(intervention_id) or abort(404)
    resp = make_response(pro_report.build(item, pro.photo_bytes, brand=_brand()))
    resp.headers["Content-Type"] = "application/pdf"
    name = "".join(c for c in (item.get("machine", {}).get("name") or "machine") if c.isalnum() or c in "-_ ")[:40]
    resp.headers["Content-Disposition"] = f'attachment; filename="Rapport-{name}-{item["created_at"][:10]}.pdf"'
    return _private(resp)


@pro_bp.route("/pro/photo/<photo_id>", methods=["GET"], endpoint="photo")
def photo(photo_id):
    if (r := _guard()):
        return r
    if not pro.photo_owner(photo_id):
        abort(404)
    size = 480 if request.args.get("s") == "mini" else None
    try:
        data = pro.photo_bytes(photo_id, size)
    except (FileNotFoundError, pro.pro_crypto.DecryptError):
        abort(404)
    resp = make_response(data)
    resp.headers["Content-Type"] = "image/jpeg"
    return _private(resp)


@pro_bp.route("/pro/acces-depannage", methods=["GET", "POST"], endpoint="support")
def support():
    """Le responsable de l'entreprise ouvre ou ferme l'accès de dépannage de l'hébergeur."""
    if (r := _guard()):
        return r
    if not pro.enterprise_mode() or not pro.is_manager():
        abort(404)
    if request.method == "POST":
        validate_csrf()
        hours = int(request.form.get("hours") or 0)
        pro.set_support(hours)
        flash("Accès de dépannage ouvert." if hours else "Accès de dépannage fermé.", "success")
        return redirect(url_for("pro.support"))
    return _page("pro_support.html", journal=pro.journal()[:200])
