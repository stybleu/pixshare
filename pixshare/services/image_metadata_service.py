"""Suppression des métadonnées (EXIF, GPS, XMP, commentaires…) des images envoyées.

Un smartphone enregistre dans chaque photo la position GPS, le modèle de
l'appareil, la date, parfois le nom du propriétaire. Sans nettoyage, quiconque
télécharge l'image publique peut tout lire.

Principe : on réécrit le *conteneur* du fichier (JPEG, PNG, WebP) en ne gardant
que les blocs nécessaires à l'affichage. Les pixels ne sont JAMAIS décodés ni
ré-encodés : aucune perte de qualité, aucun changement de taille notable.

Choix de conception :
- L'orientation de la photo (rotation du téléphone) est conservée, sous la
  forme d'un bloc EXIF minimal de 26 octets qui ne contient QUE l'orientation.
  Sans ça, une photo prise en portrait s'afficherait couchée.
- Le profil de couleurs (ICC) est conservé : il change l'aspect des couleurs
  mais ne contient aucune donnée personnelle.
- Les données ajoutées après la fin de l'image (vidéo d'une « photo animée »,
  fichier caché…) sont supprimées.
- Au moindre doute (fichier abîmé, résultat illisible, taille différente), le
  fichier d'origine est laissé tel quel : on ne casse jamais un envoi.

Formats traités : JPEG (jpg, jpeg, jfif, jpe), PNG (png, apng), WebP.
Non traités : GIF, BMP, TIFF, HEIC/HEIF, vidéos.
"""

from __future__ import annotations

import io
import logging
import os
import struct
import zlib

from PIL import Image

_log = logging.getLogger(__name__)

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# Blocs PNG utiles à l'affichage (tout le reste est supprimé : tEXt, zTXt, iTXt,
# tIME, blocs privés inconnus…). acTL/fcTL/fdAT sont indispensables aux APNG.
_PNG_KEEP = {
    b"IHDR", b"PLTE", b"IDAT", b"IEND",
    b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT", b"bKGD", b"hIST", b"pHYs",
    b"cICP", b"mDCV", b"cLLI",
    b"acTL", b"fcTL", b"fdAT",
}

# Blocs WebP utiles à l'affichage (EXIF et XMP sont retirés, ainsi que les inconnus).
_WEBP_KEEP = {b"VP8X", b"VP8 ", b"VP8L", b"ALPH", b"ANIM", b"ANMF", b"ICCP"}


class _Unsupported(Exception):
    """Fichier non reconnu ou abîmé : on ne le touche pas."""


# ------------------------------------------------------------------ EXIF minimal

def _exif_orientation(exif: bytes):
    """Lit l'orientation (2 à 8) dans un bloc EXIF ; None si absente ou normale (1)."""
    if exif[:6] == b"Exif\x00\x00":
        exif = exif[6:]
    if len(exif) < 8:
        return None

    if exif[:2] == b"II":
        endian = "<"
    elif exif[:2] == b"MM":
        endian = ">"
    else:
        return None

    try:
        if struct.unpack(endian + "H", exif[2:4])[0] != 42:
            return None
        ifd = struct.unpack(endian + "I", exif[4:8])[0]
        if ifd + 2 > len(exif):
            return None
        count = struct.unpack(endian + "H", exif[ifd:ifd + 2])[0]
        for k in range(min(count, 512)):
            pos = ifd + 2 + 12 * k
            if pos + 12 > len(exif):
                return None
            tag, typ, cnt = struct.unpack(endian + "HHI", exif[pos:pos + 8])
            if tag == 0x0112 and typ == 3 and cnt == 1:
                value = struct.unpack(endian + "H", exif[pos + 8:pos + 10])[0]
                return value if 2 <= value <= 8 else None
    except struct.error:
        return None
    return None


def _minimal_exif(orientation: int) -> bytes:
    """Bloc EXIF (format TIFF) ne contenant que l'orientation : 26 octets."""
    return (
        b"MM\x00\x2a\x00\x00\x00\x08"          # en-tête TIFF, premier IFD à l'octet 8
        + b"\x00\x01"                          # une seule entrée
        + b"\x01\x12\x00\x03\x00\x00\x00\x01"  # tag 0x0112 (Orientation), SHORT, 1 valeur
        + struct.pack(">H", orientation) + b"\x00\x00"
        + b"\x00\x00\x00\x00"                  # pas d'autre IFD
    )


# ------------------------------------------------------------------ JPEG

def _strip_jpeg(data: bytes) -> bytes:
    n = len(data)
    if n < 4 or data[:2] != b"\xff\xd8":
        raise _Unsupported("jpeg")

    orientation = None
    segments = []          # (marqueur, octets du segment complet)
    i = 2
    ended = False

    while i < n:
        if data[i] != 0xFF:
            raise _Unsupported("jpeg: marqueur attendu")
        while i + 1 < n and data[i + 1] == 0xFF:      # octets de remplissage
            i += 1
        if i + 1 >= n:
            raise _Unsupported("jpeg: fin inattendue")
        marker = data[i + 1]

        if marker == 0xD9:                            # EOI : fin de l'image
            segments.append((marker, b"\xff\xd9"))
            ended = True
            break

        if marker == 0x01 or 0xD0 <= marker <= 0xD8:  # marqueurs sans longueur
            segments.append((marker, data[i:i + 2]))
            i += 2
            continue

        if i + 4 > n:
            raise _Unsupported("jpeg: segment tronqué")
        length = struct.unpack(">H", data[i + 2:i + 4])[0]
        if length < 2 or i + 2 + length > n:
            raise _Unsupported("jpeg: longueur invalide")
        payload = data[i + 4:i + 2 + length]
        end = i + 2 + length

        if marker == 0xE1 and payload[:6] == b"Exif\x00\x00" and orientation is None:
            orientation = _exif_orientation(payload)

        if marker == 0xDA:                            # SOS : données image jusqu'au marqueur suivant
            j = end
            while True:
                k = data.find(b"\xff", j)
                if k == -1 or k + 1 >= n:
                    j = n
                    break
                nxt = data[k + 1]
                if nxt == 0x00 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF:
                    j = k + 1 if nxt == 0xFF else k + 2
                    continue
                j = k
                break
            segments.append((marker, data[i:j]))
            i = j
            continue

        segments.append((marker, data[i:end]))
        i = end

    if not ended:
        raise _Unsupported("jpeg: pas de marqueur de fin")

    out = [b"\xff\xd8"]
    exif_done = orientation is None

    def put_exif():
        tiff = _minimal_exif(orientation)
        body = b"Exif\x00\x00" + tiff
        out.append(b"\xff\xe1" + struct.pack(">H", len(body) + 2) + body)

    for marker, raw in segments:
        payload = raw[4:]
        if marker == 0xE0:                            # APP0 : on garde JFIF, pas les miniatures JFXX
            if payload[:5] != b"JFIF\x00":
                continue
        elif marker == 0xE2:                          # APP2 : on garde le profil de couleurs ICC
            if payload[:12] != b"ICC_PROFILE\x00":
                continue
        elif marker == 0xEE:                          # APP14 : on garde Adobe (mode de couleur)
            if payload[:5] != b"Adobe":
                continue
        elif marker in range(0xE1, 0xF0) or marker == 0xFE:   # EXIF, XMP, IPTC, commentaires…
            continue

        if not exif_done and not (marker == 0xE0):
            put_exif()
            exif_done = True
        out.append(raw)

    return b"".join(out)


# ------------------------------------------------------------------ PNG

def _png_chunk(ctype: bytes, body: bytes) -> bytes:
    crc = zlib.crc32(ctype + body) & 0xFFFFFFFF
    return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", crc)


def _strip_png(data: bytes) -> bytes:
    n = len(data)
    if data[:8] != _PNG_SIGNATURE:
        raise _Unsupported("png")

    chunks = []
    orientation = None
    i = 8
    ended = False

    while i + 12 <= n:
        length = struct.unpack(">I", data[i:i + 4])[0]
        ctype = data[i + 4:i + 8]
        end = i + 12 + length
        if end > n:
            raise _Unsupported("png: bloc tronqué")
        if ctype == b"eXIf" and orientation is None:
            orientation = _exif_orientation(data[i + 8:i + 8 + length])
        if ctype in _PNG_KEEP:
            chunks.append((ctype, data[i:end]))
        i = end
        if ctype == b"IEND":
            ended = True
            break

    if not ended or not chunks or chunks[0][0] != b"IHDR":
        raise _Unsupported("png: structure invalide")

    out = [_PNG_SIGNATURE]
    exif_done = orientation is None
    for ctype, raw in chunks:
        if not exif_done and ctype in (b"IDAT", b"fdAT", b"IEND"):
            out.append(_png_chunk(b"eXIf", _minimal_exif(orientation)))
            exif_done = True
        out.append(raw)
    return b"".join(out)


# ------------------------------------------------------------------ WebP

def _strip_webp(data: bytes) -> bytes:
    n = len(data)
    if n < 20 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise _Unsupported("webp")

    riff_end = min(8 + struct.unpack("<I", data[4:8])[0], n)
    chunks = []
    orientation = None
    i = 12

    while i + 8 <= riff_end:
        cid = data[i:i + 4]
        size = struct.unpack("<I", data[i + 4:i + 8])[0]
        body_end = i + 8 + size
        if body_end > riff_end:
            raise _Unsupported("webp: bloc tronqué")
        body = data[i + 8:body_end]
        if cid == b"EXIF" and orientation is None:
            orientation = _exif_orientation(body)
        if cid in _WEBP_KEEP:
            chunks.append([cid, body])
        i = body_end + (size & 1)

    if not chunks:
        raise _Unsupported("webp: aucun bloc image")

    has_vp8x = chunks[0][0] == b"VP8X"
    if has_vp8x and len(chunks[0][1]) >= 10:
        flags = chunks[0][1][0] & ~(0x08 | 0x04)          # on retire les drapeaux EXIF et XMP
        if orientation is not None:
            chunks.append([b"EXIF", _minimal_exif(orientation)])
            flags |= 0x08
        chunks[0][1] = bytes([flags]) + chunks[0][1][1:]

    payload = b"WEBP"
    for cid, body in chunks:
        payload += cid + struct.pack("<I", len(body)) + body + (b"\x00" if len(body) & 1 else b"")
    return b"RIFF" + struct.pack("<I", len(payload)) + payload


# ------------------------------------------------------------------ API publique

def strip_image_metadata_bytes(data: bytes) -> bytes:
    """Retourne l'image sans métadonnées. Lève _Unsupported si le format n'est pas pris en charge."""
    if data[:3] == b"\xff\xd8\xff":
        return _strip_jpeg(data)
    if data[:8] == _PNG_SIGNATURE:
        return _strip_png(data)
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return _strip_webp(data)
    raise _Unsupported("format")


def _same_picture(before: bytes, after: bytes) -> bool:
    """Contrôle léger : même format et mêmes dimensions (lecture de l'en-tête seulement)."""
    try:
        with Image.open(io.BytesIO(before)) as a, Image.open(io.BytesIO(after)) as b:
            return a.format == b.format and a.size == b.size
    except Exception:
        return False


def strip_image_metadata_file(path) -> bool:
    """Nettoie l'image `path` sur place. Retourne True si le fichier a été modifié.

    Ne lève jamais d'exception : en cas de problème, le fichier d'origine reste intact.
    """
    path = os.fspath(path)
    tmp_path = path + ".strip-tmp"
    try:
        with open(path, "rb") as f:
            head = f.read(12)
        is_jpeg = head[:3] == b"\xff\xd8\xff"
        is_png = head[:8] == _PNG_SIGNATURE
        is_webp = head[:4] == b"RIFF" and head[8:12] == b"WEBP"
        if not (is_jpeg or is_png or is_webp):
            return False

        with open(path, "rb") as f:
            original = f.read()

        try:
            cleaned = strip_image_metadata_bytes(original)
        except _Unsupported as exc:
            _log.info("Métadonnées conservées (fichier non traité : %s).", exc)
            return False

        if cleaned == original:
            return False
        if not cleaned or not _same_picture(original, cleaned):
            _log.warning("Nettoyage des métadonnées abandonné : contrôle de l'image échoué.")
            return False

        with open(tmp_path, "wb") as f:
            f.write(cleaned)
        os.replace(tmp_path, path)
        return True
    except Exception:
        _log.exception("Nettoyage des métadonnées impossible.")
        return False
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def strip_uploaded_image(path) -> bool:
    """Nettoie une image qui vient d'être enregistrée, si l'option est active (par défaut : oui)."""
    try:
        from flask import current_app

        if not current_app.config.get("STRIP_IMAGE_METADATA", True):
            return False
    except RuntimeError:
        pass  # hors contexte Flask : on nettoie quand même
    return strip_image_metadata_file(path)
