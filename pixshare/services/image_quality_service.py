from __future__ import annotations

import io
from PIL import Image, ImageEnhance, ImageFilter

# Protection contre les images gigantesques / decompression bombs
Image.MAX_IMAGE_PIXELS = 60_000_000


SUPPORTED_ENHANCE_EXTENSIONS = {
    ".jpg", ".jpeg",
    ".png",
    ".webp",
    ".tif", ".tiff",
    ".avif",
}


def can_enhance_extension(ext: str) -> bool:
    return (ext or "").lower() in SUPPORTED_ENHANCE_EXTENSIONS


def enhance_image_bytes(file_bytes: bytes, ext: str) -> bytes:
    ext = (ext or "").lower()

    try:
        with Image.open(io.BytesIO(file_bytes)) as img:

            if ext in {".jpg", ".jpeg"}:
                if img.mode != "RGB":
                    img = img.convert("RGB")

            elif ext == ".png":
                if img.mode not in ("RGB", "RGBA"):
                    img = img.convert("RGBA")

            elif ext == ".webp":
                if img.mode not in ("RGB", "RGBA"):
                    img = img.convert("RGB")

            elif ext in {".tif", ".tiff"}:
                if img.mode not in ("RGB", "RGBA"):
                    img = img.convert("RGB")

            elif ext == ".avif":
                if img.mode not in ("RGB", "RGBA"):
                    img = img.convert("RGB")

            else:
                return file_bytes

            # Amélioration légère
            img = img.filter(ImageFilter.SHARPEN)

            contrast = ImageEnhance.Contrast(img)
            img = contrast.enhance(1.04)

            sharpness = ImageEnhance.Sharpness(img)
            img = sharpness.enhance(1.10)

            output = io.BytesIO()

            if ext in {".jpg", ".jpeg"}:
                img.save(
                    output,
                    format="JPEG",
                    quality=100,
                    subsampling=0,
                    optimize=True,
                )

            elif ext == ".png":
                img.save(
                    output,
                    format="PNG",
                    optimize=True,
                    compress_level=9,
                )

            elif ext == ".webp":
                img.save(
                    output,
                    format="WEBP",
                    quality=95,
                    method=6,
                )

            elif ext in {".tif", ".tiff"}:
                img.save(
                    output,
                    format="TIFF",
                    compression="tiff_deflate",
                )

            elif ext == ".avif":
                try:
                    img.save(
                        output,
                        format="AVIF",
                        quality=85,
                    )
                except Exception:
                    # Si AVIF n'est pas supporté par Pillow/libavif
                    return file_bytes

            else:
                return file_bytes

            return output.getvalue()

    except Exception:
        return file_bytes