"""Modération automatique des images par NudeNet, dans le processus du site (sans bot externe).

Principe : une image envoyée reste « en attente » (privée). Juste après la réponse HTTP, on analyse
les images en attente puis on applique la décision :

* score >= seuil de blocage  -> image supprimée + avertissement à l'auteur
* score >= seuil de revue    -> reste privée, envoyée en revue manuelle (admin)
* sinon                      -> image publiée

Les seuils, l'activation et le découpage se règlent dans Admin > Paramètres (sinon : variables
d'environnement NSFW_AUTO_MODERATION, NSFW_REVIEW_THRESHOLD, NSFW_BLOCK_THRESHOLD).

Échec fermé : si NudeNet n'est pas installé ou si l'image est illisible, rien n'est publié.
Une image qui échoue plusieurs fois part en revue manuelle au lieu d'être réessayée sans fin.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import logging
import os
import tempfile
import threading
import time
from typing import Any

from flask import current_app

from pixshare.services.file_service import IMAGE_EXTENSIONS, delete_by_id
from pixshare.services.json_services import _get_data_dir, load_db, save_db
from pixshare.services.moderation_service import (
    _utc_now_iso,
    approve_image,
    create_moderation_notice,
    mark_image_for_review,
)
from pixshare.services.settings_service import get_valid_nsfw_classes, load_settings
from pixshare.services.nsfw_stats_service import bump as bump_stat

try:  # Pillow décode GIF, TIFF, APNG, MPO... que OpenCV (donc NudeNet) lit mal.
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None

try:  # HEIC/HEIF seulement si pillow-heif est installé.
    import pillow_heif

    pillow_heif.register_heif_opener()
except Exception:  # pragma: no cover
    pass

try:
    import fcntl
except ImportError:  # pragma: no cover (Windows)
    fcntl = None

_log = logging.getLogger(__name__)

DETECTOR_NAME = "nudenet-3.4.2"
EXPLICIT_CLASSES = {
    "FEMALE_GENITALIA_EXPOSED",
    "MALE_GENITALIA_EXPOSED",
    "ANUS_EXPOSED",
    "FEMALE_BREAST_EXPOSED",
    "BUTTOCKS_EXPOSED",
}
ANALYSIS_SIDE = 1024          # vue d'ensemble : NudeNet réduit à 320 px, inutile de garder plus grand
SOURCE_SIDE = 2048            # résolution conservée pour découper en morceaux
TILE_MIN_SIDE = 800           # en dessous, découper n'apporte rien (NudeNet travaille à 320 px)
TILE_GRID = 2                 # grille 2x2 ...
TILE_OVERLAP = 0.2            # ... avec 20 % de recouvrement, pour ne pas couper un sujet en deux
MAX_PIXELS = 50_000_000       # au-delà, l'image part en revue manuelle (mémoire)
MAX_FRAMES = 6                # images analysées dans un GIF/APNG/WebP animé
MAX_ATTEMPTS = 3              # échecs d'analyse avant revue manuelle
UNSUPPORTED_MODES = {"I", "F", "I;16", "I;16L", "I;16B", "I;16N"}

_detector = None
_detector_failed = False
_detector_lock = threading.Lock()
_scan_lock = threading.Lock()


# --------------------------------------------------------------------------- détecteur

def _get_detector():
    """Charge NudeNet au premier besoin (économise la mémoire tant qu'aucune image n'attend)."""
    global _detector, _detector_failed
    with _detector_lock:
        if _detector is None and not _detector_failed:
            try:
                from nudenet import NudeDetector

                _detector = NudeDetector()
                _log.info("NudeNet chargé")
            except Exception as exc:
                _detector_failed = True
                _log.warning("NudeNet indisponible, les images restent en attente: %s: %s", type(exc).__name__, exc)
        return _detector


def effective_settings() -> dict:
    """Réglages en vigueur : ce que l'admin a enregistré, sinon les variables d'environnement."""
    cfg = current_app.config
    stored = load_settings()

    enabled = stored.get("nsfw_auto_moderation")
    if enabled is None:
        enabled = bool(cfg.get("NSFW_AUTO_MODERATION", True))

    block = stored.get("nsfw_block_threshold")
    if block is None:
        block = float(cfg.get("NSFW_BLOCK_THRESHOLD", 0.85))
    block = max(0.0, min(float(block), 1.0))

    review = stored.get("nsfw_review_threshold")
    if review is None:
        review = float(cfg.get("NSFW_REVIEW_THRESHOLD", 0.60))
    review = max(0.0, min(float(review), block))

    # Parties surveillées : choix de l'admin, sinon variable NSFW_CLASSES, sinon les 5 zones intimes exposées.
    classes = get_valid_nsfw_classes(stored.get("nsfw_classes"))
    if classes is None:
        classes = get_valid_nsfw_classes(cfg.get("NSFW_CLASSES"))
    if classes is None:
        classes = sorted(EXPLICIT_CLASSES)

    # Membres : moins de restrictions par défaut, mais réglables dans l'admin.
    m_block = stored.get("nsfw_member_block_threshold")
    m_block = block if m_block is None else max(0.0, min(float(m_block), 1.0))
    m_review = stored.get("nsfw_member_review_threshold")
    m_review = review if m_review is None else float(m_review)
    m_review = max(0.0, min(m_review, m_block))
    m_classes = get_valid_nsfw_classes(stored.get("nsfw_member_classes"))
    member = {
        "review_threshold": m_review,
        "block_threshold": m_block,
        "classes": m_classes if m_classes is not None else member_classes(classes),
        "reject_direct": bool(stored.get("nsfw_member_reject_direct", False)),
        "customized": any(stored.get(k) is not None for k in (
            "nsfw_member_review_threshold", "nsfw_member_block_threshold", "nsfw_member_classes")) or bool(
            stored.get("nsfw_member_reject_direct")),
    }

    return {
        "enabled": bool(enabled),
        "review_threshold": review,
        "block_threshold": block,
        "tiling": bool(stored.get("nsfw_tiling", True)),
        "classes": classes,
        "pending_images": bool(cfg.get("MODERATION_PENDING_IMAGES", True)),
        "member": member,
    }


def auto_moderation_enabled() -> bool:
    values = effective_settings()
    return values["enabled"] and values["pending_images"]


def nudenet_installed() -> bool:
    """NudeNet est-il installé ? (sans le charger : pas de mémoire consommée)"""
    if _detector is not None:
        return True
    try:
        return importlib.util.find_spec("nudenet") is not None
    except (ImportError, ValueError):
        return False


def queue_status(db: dict | None = None) -> dict:
    """Compteurs pour l'admin : images qui attendent l'analyse / images en revue manuelle."""
    db = load_db() if db is None else db
    waiting = review = 0
    for meta in db.values():
        if _is_waiting_image(meta):
            waiting += 1
        elif is_manual_review(meta):
            review += 1
    return {"waiting": waiting, "review": review}


# --------------------------------------------------------------------------- décodage

def _to_rgb(frame):
    """Image RGB sur fond blanc (la transparence ne doit pas cacher de contenu), réduite à SOURCE_SIDE."""
    if frame.mode in UNSUPPORTED_MODES:
        raise RuntimeError(f"mode d'image non géré: {frame.mode}")
    if "A" in frame.getbands() or frame.info.get("transparency") is not None:
        rgba = frame.convert("RGBA")
        rgb = Image.new("RGB", rgba.size, (255, 255, 255))
        rgb.paste(rgba, mask=rgba.getchannel("A"))
    else:
        rgb = frame.convert("RGB")
    rgb.thumbnail((SOURCE_SIDE, SOURCE_SIDE))
    return rgb


def _png(img) -> bytes:
    out = io.BytesIO()
    img.save(out, "PNG", compress_level=1)
    return out.getvalue()


def tile_boxes(size: tuple[int, int]) -> list[tuple[int, int, int, int]]:
    """Grille TILE_GRID x TILE_GRID de morceaux qui se recouvrent de TILE_OVERLAP."""
    width, height = size
    span = TILE_GRID - TILE_OVERLAP * (TILE_GRID - 1)
    tile_w, tile_h = round(width / span), round(height / span)
    xs = [round(i * (width - tile_w) / (TILE_GRID - 1)) for i in range(TILE_GRID)]
    ys = [round(i * (height - tile_h) / (TILE_GRID - 1)) for i in range(TILE_GRID)]
    return [(x, y, x + tile_w, y + tile_h) for y in ys for x in xs]


def extract_views(data: bytes, tiling: bool = True) -> list[bytes]:
    """Images PNG à faire analyser par NudeNet.

    * NudeNet réduit tout à 320 px : sur une grande photo, un détail devient minuscule. Pour une image
      fixe assez grande, on analyse donc la vue d'ensemble PUIS 4 morceaux qui se recouvrent.
    * Une animation peut cacher du contenu après sa première image : on en échantillonne plusieurs
      (vue d'ensemble seulement, pour limiter le temps de calcul).
    """
    if Image is None:
        raise RuntimeError("Pillow est requis")
    with Image.open(io.BytesIO(data)) as img:
        width, height = img.size
        if width * height > MAX_PIXELS:
            raise RuntimeError("image trop grande en pixels")
        img.draft("RGB", (SOURCE_SIDE, SOURCE_SIDE))
        total = max(1, int(getattr(img, "n_frames", 1)))
        if total <= MAX_FRAMES:
            indexes = list(range(total))
        else:
            indexes = sorted({round(i * (total - 1) / (MAX_FRAMES - 1)) for i in range(MAX_FRAMES)})
        views: list[bytes] = []
        for index in indexes:
            if index:
                img.seek(index)
            rgb = _to_rgb(img)
            overview = rgb.copy()
            overview.thumbnail((ANALYSIS_SIDE, ANALYSIS_SIDE))
            views.append(_png(overview))
            if tiling and total == 1 and min(rgb.size) >= TILE_MIN_SIDE:
                views.extend(_png(rgb.crop(box)) for box in tile_boxes(rgb.size))
        return views


def analyze_bytes(data: bytes, tiling: bool = True, classes=None) -> tuple[str | None, float]:
    """Renvoie (classe explicite la plus forte, son score). Lève une exception si l'analyse est impossible."""
    detector = _get_detector()
    if detector is None:
        raise RuntimeError("NudeNet indisponible")

    wanted = EXPLICIT_CLASSES if classes is None else set(classes)
    best_label: str | None = None
    best_score = 0.0
    for frame in extract_views(data, tiling):
        temp_path = ""
        try:
            with tempfile.NamedTemporaryFile(prefix="pixshare_nsfw_", suffix=".png", delete=False) as tmp:
                tmp.write(frame)
                temp_path = tmp.name
            detections = detector.detect(temp_path)
        finally:
            if temp_path:
                with contextlib.suppress(OSError):
                    os.remove(temp_path)
        for detection in detections:
            label = str(detection.get("class") or "")
            score = float(detection.get("score") or 0.0)
            if label in wanted and score > best_score:
                best_label, best_score = label, score
    return best_label, best_score


def test_image(data: bytes) -> dict:
    """Testeur de l'admin : tout ce que NudeNet voit dans l'image et ce que le filtre déciderait,
    pour un visiteur et pour un membre, avec les réglages actuels. Rien n'est enregistré."""
    cfg = effective_settings()
    detector = _get_detector()
    if detector is None:
        raise RuntimeError("NudeNet n'est pas disponible sur ce serveur.")
    if not _scan_lock.acquire(timeout=60):
        raise RuntimeError("Une analyse est déjà en cours, réessaie dans un instant.")
    try:
        found: dict[str, float] = {}
        views = extract_views(data, cfg["tiling"])
        for frame in views:
            temp_path = ""
            try:
                with tempfile.NamedTemporaryFile(prefix="pixshare_test_", suffix=".png", delete=False) as tmp:
                    tmp.write(frame)
                    temp_path = tmp.name
                detections = detector.detect(temp_path)
            finally:
                if temp_path:
                    with contextlib.suppress(OSError):
                        os.remove(temp_path)
            for detection in detections:
                label = str(detection.get("class") or "")
                score = float(detection.get("score") or 0.0)
                if label and score > found.get(label, 0.0):
                    found[label] = score
    finally:
        _scan_lock.release()

    def verdict(classes, member):
        rules = cfg["member"] if member else cfg
        best = max(((s, l) for l, s in found.items() if l in set(classes)), default=(0.0, None))
        decision = decide(best[1], best[0], rules["review_threshold"], rules["block_threshold"])
        if member and decision == "reject" and not cfg["member"]["reject_direct"]:
            decision = "review"
        return {"decision": decision, "label": best[1], "score": best[0]}

    watched = set(cfg["classes"])
    return {
        "views": len(views),
        "detections": sorted(({"label": l, "score": s, "watched": l in watched} for l, s in found.items()),
                             key=lambda d: -d["score"]),
        "guest": verdict(cfg["classes"], False),
        "member": verdict(cfg["member"]["classes"], True),
        "settings": cfg,
    }


def decide(label: str | None, score: float, review_threshold: float, block_threshold: float) -> str:
    if label is not None and score >= block_threshold:
        return "reject"
    if label is not None and score >= review_threshold:
        return "review"
    return "approve"


# --------------------------------------------------------------------------- file d'attente

@contextlib.contextmanager
def _cross_process_lock():
    """Un seul processus (worker gunicorn) analyse à la fois. Donne True si le verrou est obtenu."""
    if fcntl is None:
        yield True
        return
    handle = None
    try:
        handle = open(os.path.join(_get_data_dir(), ".nsfw_scan.lock"), "a+")
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        yield True
    finally:
        if handle is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(handle, fcntl.LOCK_UN)
            handle.close()


def is_manual_review(meta: Any) -> bool:
    return (
        isinstance(meta, dict)
        and (meta.get("status") or "active").lower() == "pending"
        and str(meta.get("moderation_decision") or "").lower() == "manual_review"
    )


def _is_waiting_image(meta: Any) -> bool:
    if not isinstance(meta, dict):
        return False
    if (meta.get("status") or "active").lower() != "pending":
        return False
    if str(meta.get("moderation_decision") or "pending").lower() != "pending":
        return False  # déjà en revue manuelle
    name = os.path.basename(str(meta.get("server_name") or ""))
    return os.path.splitext(name)[1].lower() in IMAGE_EXTENSIONS


def waiting_image_ids(db: dict, limit: int) -> list[str]:
    ids = [file_id for file_id, meta in db.items() if _is_waiting_image(meta)]
    return ids[: max(0, limit)]


def _record_failure(file_id: str, error: str) -> str:
    """Compte l'échec ; après MAX_ATTEMPTS, l'image part en revue manuelle."""
    db = load_db()
    meta = db.get(file_id)
    if not _is_waiting_image(meta):
        return "gone"
    attempts = int(meta.get("moderation_attempts") or 0) + 1
    meta["moderation_attempts"] = attempts
    meta["moderation_error"] = error[:120]
    db[file_id] = meta
    if attempts >= MAX_ATTEMPTS:
        mark_image_for_review(db, file_id, meta, DETECTOR_NAME, None, "analyse_impossible")
        return "review"
    save_db(db)
    return "retry"


def _record_rejection(file_id: str, label: str | None, score: float) -> None:
    """Garde la preuve de la détection (partie du corps, score) sur la fiche de l'image supprimée."""
    db = load_db()
    meta = db.get(file_id)
    if not isinstance(meta, dict):
        return
    meta["moderated_at"] = _utc_now_iso()
    meta["moderation_decision"] = "rejected"
    meta["moderation_detector"] = DETECTOR_NAME
    meta["moderation_score"] = float(score)
    meta["moderation_label"] = (label or "")[:80]
    db[file_id] = meta
    save_db(db)


def member_classes(classes) -> list[str]:
    """Images des membres : seule la nudité explicite compte (maillot, sous-vêtements, torse nu… tolérés)."""
    wanted = EXPLICIT_CLASSES if classes is None else set(classes)
    kept = sorted(set(wanted) & EXPLICIT_CLASSES)
    return kept or sorted(EXPLICIT_CLASSES)


def _process_one(file_id: str, review_threshold: float, block_threshold: float, stats: dict, tiling: bool = True, classes=None) -> None:
    db = load_db()
    meta = db.get(file_id)
    if not _is_waiting_image(meta):
        return
    member = bool(meta.get("account_id"))
    member_rules = None
    if member:
        member_rules = effective_settings()["member"]
        classes = member_rules["classes"]
        review_threshold, block_threshold = member_rules["review_threshold"], member_rules["block_threshold"]
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], os.path.basename(str(meta.get("server_name") or "")))
    from pixshare.services import approved_hash_service as approved
    fp = approved.fingerprint(DETECTOR_NAME, review_threshold, block_threshold, tiling, classes)
    try:
        with open(path, "rb") as handle:
            data = handle.read()
        sha = hashlib.sha256(data).hexdigest()
        already = approved.known(sha, member, fp)
        if already:
            # Exactement le même fichier, déjà accepté avec ces réglages : publié sans nouvelle analyse.
            db = load_db()
            meta = db.get(file_id)
            if _is_waiting_image(meta):
                meta["content_sha256"] = sha
                meta["moderation_cached"] = True
                approve_image(db, file_id, meta, DETECTOR_NAME, already.get("score"))
                stats["approved"] += 1
                bump_stat("auto_approved")
                bump_stat("hash_approved")
            return
        label, score = analyze_bytes(data, tiling, classes)
    except Exception as exc:
        outcome = _record_failure(file_id, f"{type(exc).__name__}: {exc}")
        stats["errors"] += 1
        if outcome == "review":
            stats["review"] += 1
        _log.warning("Analyse impossible file_id=%s (%s: %s)", file_id, type(exc).__name__, exc)
        return

    # L'image a pu être supprimée par son auteur pendant l'analyse : on relit avant d'agir.
    db = load_db()
    meta = db.get(file_id)
    if not _is_waiting_image(meta):
        return

    decision = decide(label, score, review_threshold, block_threshold)
    if member and decision == "reject" and not member_rules["reject_direct"]:
        decision = "review"  # membre : par défaut jamais de suppression automatique, l'admin décide
    if decision == "review" and _filter_decides(member):
        bump_stat("auto_review")
        if _delete_while_absent(file_id, meta, label, score):
            stats["rejected"] += 1
        return
    if decision == "approve":
        meta["content_sha256"] = sha
        approve_image(db, file_id, meta, DETECTOR_NAME, score)
        stats["approved"] += 1
        bump_stat("auto_approved")
        try:
            approved.remember(sha, member, fp, score)
        except Exception:
            _log.exception("Empreinte d'image acceptée non enregistrée")
    elif decision == "review":
        mark_image_for_review(db, file_id, meta, DETECTOR_NAME, score, label or "")
        stats["review"] += 1
        bump_stat("auto_review")
        _log.warning("Image envoyée en revue manuelle: file_id=%s label=%s score=%.3f", file_id, label, score)
    else:
        if delete_by_id(file_id, reason="auto:non_respect_cgu"):
            _record_rejection(file_id, label, score)
            create_moderation_notice(meta, file_id, reason="non_respect_cgu")
            try:  # récidive : IP bloquée un moment (jamais bloquant pour la modération)
                from pixshare.services.abuse_service import record_rejection
                if not meta.get("by_admin"):  # l'admin qui teste NudeNet ne se bloque pas lui-même
                    record_rejection(meta.get("ip") or "")
            except Exception:
                _log.exception("Blocage automatique impossible")
            stats["rejected"] += 1
            bump_stat("auto_rejected")
            _log.warning("Image supprimée: file_id=%s label=%s score=%.3f", file_id, label, score)
        else:
            stats["errors"] += 1


# ------------------------------------------------------------------ admin absent : le filtre décide seul

ABSENT_REASON = "auto:admin_absent"


def _filter_decides(member: bool) -> bool:
    try:
        from pixshare.services.admin_presence_service import filter_decides
        return filter_decides(member)
    except Exception:
        _log.exception("Présence admin inconnue : l'image attend l'admin")
        return False


def _delete_while_absent(file_id: str, meta: dict, label, score) -> bool:
    """Image douteuse et admin absent : supprimée par le filtre. Pas de blocage d'IP, pas
    d'avertissement de compte, pas d'empreinte bannie (ce n'est qu'un doute, pas une certitude)."""
    if not delete_by_id(file_id, reason=ABSENT_REASON):
        return False
    db = load_db()
    rec = db.get(file_id)
    if isinstance(rec, dict):
        rec["moderated_at"] = _utc_now_iso()
        rec["moderation_decision"] = "rejected_absent"
        rec["moderation_detector"] = DETECTOR_NAME
        rec["moderation_score"] = float(score) if isinstance(score, (int, float)) else None
        rec["moderation_label"] = (label or "")[:80]
        db[file_id] = rec
        save_db(db)
    create_moderation_notice(meta, file_id, reason="filtre_absent")
    bump_stat("absent_deleted")
    try:
        from pixshare.services.admin_presence_service import count_deletion
        count_deletion()
    except Exception:
        pass
    _log.warning("Admin absent, image douteuse supprimée par le filtre: file_id=%s label=%s score=%s", file_id, label, score)
    return True


def apply_absent_decisions(limit: int = 50) -> int:
    """Admin parti sans trancher : le filtre supprime les images qu'il avait mises de côté.
    Les signalements et les analyses impossibles attendent toujours l'admin (le filtre n'a rien vu)."""
    if not nudenet_ready():
        return 0
    done = 0
    for file_id, meta in list(load_db().items()):
        if done >= limit:
            break
        if not is_manual_review(meta):
            continue
        similar_to_banned = meta.get("moderation_label") == "deja_refusee"  # ressemble à une image interdite
        if meta.get("moderation_detector") != DETECTOR_NAME and not similar_to_banned:
            continue
        if meta.get("moderation_label") in ("", None, "analyse_impossible", "signalement"):
            continue
        if not _filter_decides(bool(meta.get("account_id"))):
            continue
        if _delete_while_absent(file_id, meta, meta.get("moderation_label"), meta.get("moderation_score")):
            done += 1
    return done


def release_waiting_images() -> int:
    """Publie les images qui attendaient l'analyse alors que NudeNet est coupé
    (ou absent) : sinon elles resteraient privées pour toujours. Les images déjà
    envoyées en revue manuelle restent dans la file de revue de l'admin."""
    db = load_db()
    released = 0
    for file_id, meta in list(db.items()):
        if _is_waiting_image(meta):
            from pixshare.services.moderation_service import start_lifetime_now
            start_lifetime_now(meta)
            meta["status"] = "active"
            meta["moderated_at"] = _utc_now_iso()
            meta["moderation_decision"] = "not_required"
            meta["moderation_detector"] = "nudenet_off"
            db[file_id] = meta
            released += 1
    if released:
        save_db(db)
    return released


# ------------------------------------------------------------------ analyse après suppression

def late_check_dir() -> str:
    import tempfile
    folder = os.path.join(tempfile.gettempdir(), "pixshare_late_check")
    os.makedirs(folder, exist_ok=True)
    return folder


def late_check_path(file_id: str, server_name: str) -> str:
    return os.path.join(late_check_dir(), file_id + os.path.splitext(server_name)[1].lower())


def nudenet_ready() -> bool:
    return auto_moderation_enabled() and nudenet_installed()


def run_late_checks(limit: int = 10) -> int:
    """Images supprimées par leur auteur avant l'analyse : NudeNet les analyse quand même (pour l'admin),
    note le verdict, refuse leur renvoi si elles auraient été supprimées, puis efface la copie."""
    from pixshare.services.json_services import save_db

    done = 0
    db = load_db()
    queued = [fid for fid, meta in db.items() if isinstance(meta, dict) and meta.get("late_check") == "queued"][:limit]
    if not queued:
        return 0
    values = effective_settings()
    for file_id in queued:
        meta = db[file_id]
        path = late_check_path(file_id, str(meta.get("server_name") or ""))
        verdict, label, score = "", None, None
        try:
            if os.path.isfile(path) and _get_detector() is not None:
                with open(path, "rb") as handle:
                    label, score = analyze_bytes(handle.read(), values["tiling"], values["classes"])
                decision = decide(label, score, values["review_threshold"], values["block_threshold"])
                verdict = {"approve": "ok", "review": "review", "reject": "reject"}.get(decision, decision)
                if verdict == "reject":
                    from pixshare.services.image_ban_service import ban_file
                    ban_file(path, "auto:non_respect_cgu", str(label or ""), file_id)
        except Exception:
            _log.exception("Analyse après suppression impossible pour %s", file_id)
            verdict = "error"
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
        db = load_db()
        meta = db.get(file_id)
        if isinstance(meta, dict):
            meta["late_check"] = verdict or "missing"
            meta["late_check_label"] = label or ""
            meta["late_check_score"] = round(float(score), 4) if isinstance(score, (int, float)) else None
            save_db(db)
        done += 1
    return done


def run_auto_moderation(limit: int = 10) -> dict[str, int]:
    """Analyse jusqu'à `limit` images en attente. À appeler dans un contexte d'application Flask."""
    stats = {"approved": 0, "review": 0, "rejected": 0, "errors": 0}
    if not auto_moderation_enabled() or not nudenet_installed():
        stats["approved"] = release_waiting_images()
        return stats
    if not _scan_lock.acquire(blocking=False):
        return stats
    try:
        if not waiting_image_ids(load_db(), 1):
            return stats  # rien à faire : on ne charge même pas NudeNet
        if _get_detector() is None:
            return stats
        values = effective_settings()
        with _cross_process_lock() as got:
            if not got:
                return stats
            for file_id in waiting_image_ids(load_db(), limit):
                _process_one(file_id, values["review_threshold"], values["block_threshold"], stats, values["tiling"], values["classes"])
        return stats
    except Exception:
        _log.exception("Erreur inattendue pendant la modération automatique")
        return stats
    finally:
        _scan_lock.release()


_last_approved_purge = 0.0


def _purge_approved_hourly() -> None:
    global _last_approved_purge
    if time.monotonic() - _last_approved_purge < 3600:
        return
    _last_approved_purge = time.monotonic()
    try:
        from pixshare.services.approved_hash_service import purge_old
        purge_old()
    except Exception:
        _log.exception("Ménage des images déjà acceptées impossible")


def run_after_response(app) -> None:
    """Point d'entrée appelé après l'envoi de la réponse HTTP (ne ralentit pas l'utilisateur)."""
    try:
        with app.app_context():
            run_auto_moderation()
            if nudenet_ready():
                run_late_checks()
                apply_absent_decisions()
            _purge_approved_hourly()
    except Exception:  # pragma: no cover
        _log.exception("Modération automatique interrompue")

