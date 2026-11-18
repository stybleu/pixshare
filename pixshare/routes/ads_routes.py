"""Publicité : bannières directes (image + clic compté sans pistage), ads.txt et page d'admin."""
from flask import Blueprint, abort, flash, redirect, render_template, request, send_file, url_for

from pixshare.security.csrf import validate_csrf
from pixshare.services import ads_service
from pixshare.services.auth_service import admin_required

ads_bp = Blueprint("ads", __name__)


@ads_bp.route("/pub/<name>", methods=["GET"], endpoint="banner")
def banner(name):
    cfg = ads_service.load()
    if name not in ads_service.SLOTS or not cfg["enabled"] or not ads_service.slot_ready(cfg, name) \
            or cfg["slots"][name]["mode"] != "direct":
        abort(404)
    image = cfg["slots"][name]["image"]
    ext = image.rsplit(".", 1)[-1]
    response = send_file(ads_service.banner_path(image), mimetype=ads_service.BANNER_TYPES[ext], max_age=3600)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Robots-Tag"] = "noindex"
    return response


@ads_bp.route("/pub/<name>/clic", methods=["GET"], endpoint="click")
def click(name):
    cfg = ads_service.load()
    if name not in ads_service.SLOTS or not cfg["enabled"] or cfg["slots"][name]["mode"] != "direct" \
            or not cfg["slots"][name]["link"]:
        abort(404)
    ads_service.count_click(name)
    response = redirect(cfg["slots"][name]["link"], code=302)
    response.headers["X-Robots-Tag"] = "noindex"
    response.headers["Cache-Control"] = "no-store"
    return response


@ads_bp.route("/ads.txt", methods=["GET"], endpoint="ads_txt")
def ads_txt():
    content = ads_service.ads_txt()
    if not content:
        abort(404)
    return content, 200, {"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=3600"}


@ads_bp.route("/admin/publicite", methods=["GET", "POST"], endpoint="admin_ads")
@admin_required
def admin_ads():
    if request.method == "POST":
        validate_csrf()
        cfg = ads_service.load()
        form = request.form
        client = (form.get("adsense_client") or "").strip()
        if client and not ads_service.CLIENT_RE.match(client):
            flash("Identifiant d'éditeur invalide : il ressemble à ca-pub-1234567890123456.", "danger")
            return redirect(url_for("ads.admin_ads"))
        cfg.update(enabled=form.get("enabled") == "1", adsense_client=client,
                   auto_ads=form.get("auto_ads") == "1", hide_for_members=form.get("hide_for_members") == "1")
        errors = []
        for name, label in ads_service.SLOTS.items():
            slot = cfg["slots"][name]
            slot["mode"] = form.get(f"{name}_mode") if form.get(f"{name}_mode") in ads_service.MODES else "off"
            ad_slot = (form.get(f"{name}_ad_slot") or "").strip()
            if ad_slot and not ads_service.AD_SLOT_RE.match(ad_slot):
                errors.append(f"{label} : numéro de bloc d'annonces invalide (chiffres uniquement).")
            slot["ad_slot"] = ad_slot
            link = (form.get(f"{name}_link") or "").strip()
            if link and not ads_service.clean_link(link):
                errors.append(f"{label} : le lien doit commencer par https://")
            slot["link"] = link
            slot["alt"] = form.get(f"{name}_alt") or ""
        cfg = ads_service.save(cfg)
        for name, label in ads_service.SLOTS.items():
            if form.get(f"{name}_remove") == "1":
                ads_service.remove_banner(name)
            upload = request.files.get(f"{name}_image")
            if upload and upload.filename:
                error = ads_service.save_banner(name, upload.read(ads_service.BANNER_MAX_BYTES + 1))
                if error:
                    errors.append(f"{label} : {error}")
        cfg = ads_service.load()
        for error in errors:
            flash(error, "warning")
        if cfg["enabled"] and cfg["slots"] and any(
                cfg["slots"][n]["mode"] != "off" and not ads_service.slot_ready(cfg, n) for n in ads_service.SLOTS):
            flash("Certains emplacements ne s'affichent pas encore : il leur manque l'identifiant Google, le numéro "
                  "de bloc, l'image ou le lien.", "warning")
        flash("Publicité enregistrée ✅" if cfg["enabled"] else "Publicité coupée : aucune annonce n'est affichée.", "success")
        return redirect(url_for("ads.admin_ads"))
    cfg = ads_service.load()
    ready = {n: ads_service.slot_ready(cfg, n) for n in ads_service.SLOTS}
    return render_template("admin_ads.html", cfg=cfg, slots=ads_service.SLOTS, ready=ready,
                           google_on=ads_service.google_on(cfg), ads_txt=ads_service.ads_txt(),
                           title="Publicité – Admin")
