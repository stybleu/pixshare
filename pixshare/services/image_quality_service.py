from __future__ import annotations

import io

from PIL import Image, ImageEnhance, ImageFilter, ImageOps

# Protection contre les images gigantesques / decompression bombs
Image.MAX_IMAGE_PIXELS = 60_000_000

# Support HEIC / HEIF via pillow-heif
try:
    import pillow_heif
    pillow_heif.register_heif_opener()
    HEIF_AVAILABLE = True
except Exception:
    HEIF_AVAILABLE = False


SUPPORTED_ENHANCE_EXTENSIONS = {
    ".jpg", ".jpeg",
    ".png",
    ".webp",
    ".tif", ".tiff",
    ".avif",
    ".heic", ".heif",
}

# Curseur du formulaire : 0 = rien, 10 = léger, 20 = moyen, 30 = fort.
MIN_STRENGTH = 0
MAX_STRENGTH = 30
DEFAULT_STRENGTH = 10


def can_enhance_extension(ext: str) -> bool:
    ext = (ext or "").lower()

    if ext in {".heic", ".heif"} and not HEIF_AVAILABLE:
        return False

    return ext in SUPPORTED_ENHANCE_EXTENSIONS


def get_output_extension(ext: str) -> str:
    """
    Retourne l'extension finale après amélioration.
    HEIC / HEIF sont convertis en JPG pour compatibilité navigateur.
    """
    ext = (ext or "").lower()

    if ext in {".heic", ".heif"}:
        return ".jpg"

    return ext


def parse_strength(value, default: int = DEFAULT_STRENGTH) -> int:
    """Valeur du curseur, ramenée entre 0 et 30 (valeur absurde -> défaut)."""
    try:
        strength = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default
    return max(MIN_STRENGTH, min(MAX_STRENGTH, strength))


def _auto_levels(rgb: Image.Image) -> Image.Image:
    """Étire la luminosité (noirs plus noirs, blancs plus blancs) sans changer les teintes."""
    try:
        return ImageOps.autocontrast(rgb, cutoff=(0.5, 0.5), preserve_tone=True)
    except TypeError:  # vieux Pillow sans preserve_tone
        return ImageOps.autocontrast(rgb, cutoff=0.5)


def _enhance_rgb(rgb: Image.Image, strength: int) -> Image.Image:
    t = strength / MAX_STRENGTH  # 0 -> 1

    # 1) Niveaux automatiques, dosés par le curseur.
    leveled = _auto_levels(rgb)
    rgb = Image.blend(rgb, leveled, 0.7 * t)

    # 2) Couleurs un peu plus vives (jusqu'à +15 %).
    rgb = ImageEnhance.Color(rgb).enhance(1.0 + 0.15 * t)

    # 3) Netteté « masque flou » : rayon adapté à la taille de la photo,
    #    seuil pour ne pas renforcer le grain des zones unies.
    radius = max(0.8, min(rgb.size) / 1200.0)
    percent = int(30 + 120 * t)
    rgb = rgb.filter(ImageFilter.UnsharpMask(radius=radius, percent=percent, threshold=3))
    return rgb


def enhance_image_bytes(file_bytes: bytes, ext: str, strength: int = DEFAULT_STRENGTH) -> bytes:
    """
    Améliore légèrement une photo. En cas de doute (format illisible, image
    animée, force 0...), renvoie l'objet d'origine tel quel.
    """
    ext = (ext or "").lower()
    strength = parse_strength(strength)

    if strength <= 0 or not can_enhance_extension(ext):
        return file_bytes

    try:
        with Image.open(io.BytesIO(file_bytes)) as src:
            if getattr(src, "is_animated", False) and getattr(src, "n_frames", 1) > 1:
                return file_bytes  # on ne casse pas les animations

            icc = src.info.get("icc_profile")
            # Remet la photo dans le bon sens (téléphones) avant de la réenregistrer.
            img = ImageOps.exif_transpose(src)
            if img is None:
                img = src.copy()

            has_alpha = img.mode in ("RGBA", "LA", "PA") or (
                img.mode == "P" and "transparency" in img.info
            )
            if has_alpha:
                img = img.convert("RGBA")
                alpha = img.getchannel("A")
                rgb = img.convert("RGB")
            else:
                alpha = None
                rgb = img.convert("RGB")

            if rgb.mode != "RGB" or rgb.width < 2 or rgb.height < 2:
                return file_bytes

            rgb = _enhance_rgb(rgb, strength)

            if alpha is not None:
                rgb.putalpha(alpha)
            out_img = rgb

            extra = {"icc_profile": icc} if icc else {}
            output = io.BytesIO()

            if ext in {".jpg", ".jpeg", ".heic", ".heif"}:
                if out_img.mode != "RGB":
                    background = Image.new("RGB", out_img.size, (255, 255, 255))
                    background.paste(out_img, mask=out_img.getchannel("A"))
                    out_img = background
                out_img.save(output, format="JPEG", quality=92, optimize=True, progressive=True, **extra)

            elif ext == ".png":
                out_img.save(output, format="PNG", optimize=True, compress_level=6, **extra)

            elif ext == ".webp":
                out_img.save(output, format="WEBP", quality=92, method=4, **extra)

            elif ext in {".tif", ".tiff"}:
                out_img.save(output, format="TIFF", compression="tiff_deflate", **extra)

            elif ext == ".avif":
                out_img.save(output, format="AVIF", quality=85, **extra)

            else:
                return file_bytes

            data = output.getvalue()
            return data if data else file_bytes

    except Exception:
        return file_bytes
