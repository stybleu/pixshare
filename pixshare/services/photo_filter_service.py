"""Filtres photo des membres (noir et blanc, rétro, vintage…) et mode Document.

Les filtres utilisent exactement les mêmes formules que l'aperçu du navigateur (fichier static/js/filtres.js) :
ce que la personne voit avant l'envoi est ce que le lien montrera.

Chaque filtre est une suite d'opérations simples, dosée par une intensité de 0 à 100 % :
- matrices de couleur (niveaux de gris, sépia, saturation, rotation de teinte), luminosité, contraste ;
- un voile de couleur en « produit » (teinte chaude ou froide) ;
- un vignettage (coins assombris).
"""
from __future__ import annotations

import math

import numpy as np
from PIL import Image

FILTERS: dict[str, dict] = {
    "noir_blanc": {"label": "Noir et blanc", "ops": [("grayscale", 1.0), ("contrast", 1.05)]},
    "dramatique": {"label": "Dramatique", "ops": [("grayscale", 1.0), ("contrast", 1.6), ("brightness", 0.95)]},
    "retro": {"label": "Rétro", "ops": [("sepia", 0.85), ("contrast", 1.05), ("brightness", 1.02)]},
    "vintage": {"label": "Vintage", "ops": [("sepia", 0.4), ("saturate", 0.8), ("contrast", 0.9), ("brightness", 1.06)],
                "vignette": 0.45},
    "intense": {"label": "Intense", "ops": [("contrast", 1.25), ("saturate", 1.7)]},
    "chaud": {"label": "Chaud", "ops": [("saturate", 1.15), ("brightness", 1.04)], "tint": ((255, 214, 170), 0.35)},
    "froid": {"label": "Froid", "ops": [("saturate", 0.95), ("brightness", 1.06)], "tint": ((170, 205, 255), 0.35)},
    "doux": {"label": "Doux", "ops": [("brightness", 1.08), ("contrast", 0.88), ("saturate", 0.9)]},
}

DOCUMENT = "document"
DOCUMENT_MODES = ("couleur", "gris", "scan")


def parse_filter(name: str | None) -> str:
    name = (name or "").strip().lower()
    return name if name in FILTERS or name == DOCUMENT else ""


def parse_strength(value, default: int = 100) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return default


# ------------------------------------------------------------------ matrices (spécification des filtres CSS)

def _matrix(op: str, amount: float) -> np.ndarray | None:
    if op == "grayscale":
        a = 1 - amount
        return np.array([
            [0.2126 + 0.7874 * a, 0.7152 - 0.7152 * a, 0.0722 - 0.0722 * a],
            [0.2126 - 0.2126 * a, 0.7152 + 0.2848 * a, 0.0722 - 0.0722 * a],
            [0.2126 - 0.2126 * a, 0.7152 - 0.7152 * a, 0.0722 + 0.9278 * a]])
    if op == "sepia":
        a = 1 - amount
        return np.array([
            [0.393 + 0.607 * a, 0.769 - 0.769 * a, 0.189 - 0.189 * a],
            [0.349 - 0.349 * a, 0.686 + 0.314 * a, 0.168 - 0.168 * a],
            [0.272 - 0.272 * a, 0.534 - 0.534 * a, 0.131 + 0.869 * a]])
    if op == "saturate":
        s = amount
        return np.array([
            [0.213 + 0.787 * s, 0.715 - 0.715 * s, 0.072 - 0.072 * s],
            [0.213 - 0.213 * s, 0.715 + 0.285 * s, 0.072 - 0.072 * s],
            [0.213 - 0.213 * s, 0.715 - 0.715 * s, 0.072 + 0.928 * s]])
    if op == "hue":
        c, s = math.cos(math.radians(amount)), math.sin(math.radians(amount))
        return np.array([
            [0.213 + c * 0.787 - s * 0.213, 0.715 - c * 0.715 - s * 0.715, 0.072 - c * 0.072 + s * 0.928],
            [0.213 - c * 0.213 + s * 0.143, 0.715 + c * 0.285 + s * 0.140, 0.072 - c * 0.072 - s * 0.283],
            [0.213 - c * 0.213 - s * 0.787, 0.715 - c * 0.715 + s * 0.715, 0.072 + c * 0.928 + s * 0.072]])
    return None


def _scaled(op: str, value: float, t: float) -> float:
    """Intensité t (0..1) : on part de « aucun effet » vers la valeur du filtre."""
    if op in ("grayscale", "sepia", "hue"):
        return value * t
    return 1 + (value - 1) * t


def apply_filter_array(rgb: np.ndarray, name: str, strength: int = 100) -> np.ndarray:
    """``rgb`` : tableau float32 (h, w, 3) entre 0 et 1. Renvoie un nouveau tableau, mêmes bornes."""
    spec = FILTERS.get(name)
    t = max(0, min(100, int(strength))) / 100
    if not spec or t <= 0:
        return rgb
    out = rgb.astype(np.float32, copy=True)
    for op, value in spec["ops"]:
        amount = _scaled(op, value, t)
        if op in ("grayscale", "sepia", "saturate", "hue"):
            out = out @ _matrix(op, amount).T.astype(np.float32)
        elif op == "brightness":
            out = out * amount
        elif op == "contrast":
            out = (out - 0.5) * amount + 0.5
        np.clip(out, 0, 1, out=out)
    if "tint" in spec:
        color, k = spec["tint"]
        k *= t
        tint = np.array(color, dtype=np.float32) / 255
        out = out * (1 - k + k * tint)
    if "vignette" in spec:
        v = spec["vignette"] * t
        h, w = out.shape[:2]
        yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
        d = np.sqrt(((xx + 0.5 - w / 2) / (w / 2)) ** 2 + ((yy + 0.5 - h / 2) / (h / 2)) ** 2) / math.sqrt(2)
        alpha = v * np.clip((d - 0.55) / 0.45, 0, 1)
        out = out * (1 - alpha[..., None])
    return np.clip(out, 0, 1)


def apply_filter(img: Image.Image, name: str, strength: int = 100) -> Image.Image:
    if name not in FILTERS:
        return img
    arr = np.asarray(img.convert("RGB"), dtype=np.float32) / 255
    out = apply_filter_array(arr, name, strength)
    return Image.fromarray((out * 255 + 0.5).astype(np.uint8), "RGB")


# ------------------------------------------------------------------ mode Document

def _cv2():
    import cv2  # fourni avec NudeNet
    return cv2


def _order(pts: np.ndarray) -> np.ndarray:
    """Haut-gauche, haut-droit, bas-droit, bas-gauche."""
    pts = np.asarray(pts, dtype=np.float32).reshape(4, 2)
    s = pts.sum(axis=1)
    d = np.diff(pts, axis=1).ravel()
    return np.array([pts[np.argmin(s)], pts[np.argmin(d)], pts[np.argmax(s)], pts[np.argmax(d)]], dtype=np.float32)


def default_corners() -> list[list[float]]:
    return [[0.05, 0.05], [0.95, 0.05], [0.95, 0.95], [0.05, 0.95]]


def detect_corners(img: Image.Image) -> tuple[list[list[float]], bool]:
    """Coins de la feuille, en proportions (0..1) de l'image. (coins, trouvés ?)"""
    cv2 = _cv2()
    rgb = np.asarray(img.convert("RGB"))
    h, w = rgb.shape[:2]
    scale = 800 / max(h, w) if max(h, w) > 800 else 1.0
    small = cv2.resize(rgb, (max(1, int(w * scale)), max(1, int(h * scale))), interpolation=cv2.INTER_AREA)
    sh, sw = small.shape[:2]
    gray = cv2.cvtColor(small, cv2.COLOR_RGB2GRAY)
    gray = cv2.GaussianBlur(gray, (5, 5), 0)
    best, best_area = None, 0.0
    for lo, hi in ((30, 90), (50, 150), (75, 200)):
        edges = cv2.Canny(gray, lo, hi)
        edges = cv2.dilate(edges, np.ones((3, 3), np.uint8), iterations=2)
        contours, _ = cv2.findContours(edges, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
        for c in sorted(contours, key=cv2.contourArea, reverse=True)[:8]:
            area = cv2.contourArea(c)
            if area < 0.15 * sw * sh:
                break
            peri = cv2.arcLength(c, True)
            for eps in (0.02, 0.03, 0.05):
                approx = cv2.approxPolyDP(c, eps * peri, True)
                if len(approx) == 4 and cv2.isContourConvex(approx) and area > best_area:
                    best, best_area = approx, area
                    break
    if best is None:
        return default_corners(), False
    pts = _order(best.reshape(4, 2))
    return [[round(float(x) / sw, 4), round(float(y) / sh, 4)] for x, y in pts], True


def parse_corners(value) -> list[list[float]] | None:
    """« x1,y1,x2,y2,x3,y3,x4,y4 » en proportions -> 4 coins, ou None si invalide."""
    try:
        nums = [float(v) for v in str(value or "").replace(";", ",").split(",") if v.strip() != ""]
    except ValueError:
        return None
    if len(nums) != 8 or any(math.isnan(n) or n < -0.05 or n > 1.05 for n in nums):
        return None
    pts = [[min(max(nums[i], 0.0), 1.0), min(max(nums[i + 1], 0.0), 1.0)] for i in range(0, 8, 2)]
    ordered = _order(np.array(pts))
    cv2 = _cv2()
    if cv2.contourArea(ordered.reshape(4, 1, 2)) < 0.01:   # coins presque alignés : rien d'exploitable
        return None
    return [[float(x), float(y)] for x, y in ordered]


def straighten(img: Image.Image, corners: list[list[float]], mode: str = "scan", max_side: int = 3000) -> Image.Image:
    """Redresse la page délimitée par ``corners`` (proportions) et la rend lisible selon ``mode``."""
    cv2 = _cv2()
    rgb = np.asarray(img.convert("RGB"))
    h, w = rgb.shape[:2]
    src = _order(np.array([[x * w, y * h] for x, y in corners], dtype=np.float32))
    # on rentre très légèrement vers l'intérieur : pas de liseré de table sur les bords
    src = src + (src.mean(axis=0) - src) * 0.008
    tl, tr, br, bl = src
    out_w = int(max(np.linalg.norm(tr - tl), np.linalg.norm(br - bl)))
    out_h = int(max(np.linalg.norm(bl - tl), np.linalg.norm(br - tr)))
    ratio = min(1.0, max_side / max(out_w, out_h, 1))
    out_w, out_h = max(16, int(out_w * ratio)), max(16, int(out_h * ratio))
    dst = np.array([[0, 0], [out_w - 1, 0], [out_w - 1, out_h - 1], [0, out_h - 1]], dtype=np.float32)
    page = cv2.warpPerspective(rgb, cv2.getPerspectiveTransform(src, dst), (out_w, out_h),
                               flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
    mode = mode if mode in DOCUMENT_MODES else "scan"
    if mode == "couleur":
        page = _even_light(page, color=True)
        return Image.fromarray(page, "RGB")
    gray = cv2.cvtColor(page, cv2.COLOR_RGB2GRAY)
    gray = _even_light(gray, color=False)
    if mode == "scan":
        # fond blanc, texte noir et net (comme une photocopie), sans perdre les traits fins
        gray = cv2.addWeighted(gray, 1.5, cv2.GaussianBlur(gray, (0, 0), 1.2), -0.5, 0)
        lut = np.clip((np.arange(256, dtype=np.float32) - 60) * (255 / (215 - 60)), 0, 255).astype(np.uint8)
        gray = cv2.LUT(gray, lut)
    return Image.fromarray(gray, "L").convert("RGB")


def _even_light(arr: np.ndarray, color: bool) -> np.ndarray:
    """Retire les ombres et les différences d'éclairage : le papier devient uniformément clair."""
    cv2 = _cv2()
    channels = cv2.split(arr) if color else [arr]
    out = []
    for ch in channels:
        k = max(15, (min(ch.shape[:2]) // 12) | 1)
        background = cv2.medianBlur(cv2.dilate(ch, np.ones((7, 7), np.uint8)), k)
        norm = cv2.divide(ch, background, scale=255)
        out.append(cv2.normalize(norm, None, 0, 255, cv2.NORM_MINMAX))
    return cv2.merge(out) if color else out[0]


def to_pdf_bytes(img: Image.Image, dpi: int = 150) -> bytes:
    """La page en PDF au format A4 (portrait ou paysage selon la page), centrée avec une petite marge."""
    import io
    landscape = img.width > img.height
    a4_w, a4_h = (297, 210) if landscape else (210, 297)
    page_w, page_h = int(a4_w / 25.4 * dpi), int(a4_h / 25.4 * dpi)
    margin = int(8 / 25.4 * dpi)
    fit = min((page_w - 2 * margin) / img.width, (page_h - 2 * margin) / img.height)
    content = img.convert("RGB").resize((max(1, int(img.width * fit)), max(1, int(img.height * fit))), Image.LANCZOS)
    sheet = Image.new("RGB", (page_w, page_h), (255, 255, 255))
    sheet.paste(content, ((page_w - content.width) // 2, (page_h - content.height) // 2))
    buf = io.BytesIO()
    sheet.save(buf, "PDF", resolution=dpi)
    return buf.getvalue()


def parse_crop(value):
    """« x,y,l,h » en proportions de la photo (0 à 1) → tuple, ou None si absent, invalide ou inutile."""
    try:
        parts = [float(v) for v in str(value or "").split(",")]
    except ValueError:
        return None
    if len(parts) != 4 or any(v != v for v in parts):   # NaN
        return None
    x, y, w, h = parts
    if not (0 <= x < 1 and 0 <= y < 1 and 0.01 <= w <= 1 and 0.01 <= h <= 1):
        return None
    if x + w > 1.001 or y + h > 1.001:
        return None
    if x < 0.002 and y < 0.002 and w > 0.996 and h > 0.996:
        return None                                     # toute la photo : rien à recadrer
    return (x, y, min(w, 1 - x), min(h, 1 - y))
