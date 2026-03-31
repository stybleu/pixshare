from __future__ import annotations

import ipaddress
import os
import socket
import tempfile
from typing import Final
from urllib.parse import urljoin, urlparse, unquote

import requests
from PIL import Image, UnidentifiedImageError
from werkzeug.utils import secure_filename

from pixshare.services.file_service import HEIF_ENABLED

ALLOWED_IMPORT_MIME_TO_EXT: Final[dict[str, str]] = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/tiff": ".tiff",
}

if HEIF_ENABLED:
    ALLOWED_IMPORT_MIME_TO_EXT.update({
        "image/heic": ".heic",
        "image/heif": ".heif",
    })

PIL_FORMAT_TO_EXT: Final[dict[str, str]] = {
    "PNG": ".png",
    "JPEG": ".jpg",
    "GIF": ".gif",
    "WEBP": ".webp",
    "TIFF": ".tiff",
    "HEIC": ".heic",
    "HEIF": ".heif",
}

DEFAULT_IMPORT_TIMEOUT = (5, 20)
MAX_REDIRECTS = 4
ALLOWED_PORTS = {80, 443, None}


class UrlImportError(ValueError):
    """Raised when a remote image cannot be imported safely."""


def _is_public_ip(ip_text: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return False

    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def _resolve_public_addresses(hostname: str, port: int | None) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UrlImportError("Impossible de résoudre l'adresse distante.") from exc

    addresses: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_text = sockaddr[0]
        if ip_text not in addresses:
            addresses.append(ip_text)

    if not addresses:
        raise UrlImportError("Adresse distante introuvable.")

    if not all(_is_public_ip(ip) for ip in addresses):
        raise UrlImportError("Adresse refusée pour des raisons de sécurité.")

    return addresses


def validate_remote_image_url(url: str) -> str:
    clean_url = (url or "").strip()
    if not clean_url:
        raise UrlImportError("URL manquante.")

    parsed = urlparse(clean_url)
    if parsed.scheme not in {"http", "https"}:
        raise UrlImportError("Seules les URL HTTP et HTTPS sont autorisées.")

    if not parsed.hostname:
        raise UrlImportError("URL invalide.")

    if parsed.username or parsed.password:
        raise UrlImportError("Les URL avec authentification ne sont pas autorisées.")

    hostname = parsed.hostname.strip().lower()
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith('.local'):
        raise UrlImportError("Adresse locale refusée.")

    if parsed.port not in ALLOWED_PORTS:
        raise UrlImportError("Port distant non autorisé.")

    _resolve_public_addresses(hostname, parsed.port)
    return clean_url


def _build_original_name(source_url: str, real_ext: str) -> str:
    parsed = urlparse(source_url)
    raw_name = os.path.basename(unquote(parsed.path or "")).strip()
    safe_name = secure_filename(raw_name) or "image-importee"
    stem, _ = os.path.splitext(safe_name)
    stem = stem or "image-importee"
    return f"{stem}{real_ext}"


def _download_with_checked_redirects(source_url: str):
    session = requests.Session()
    session.trust_env = False

    current_url = validate_remote_image_url(source_url)

    for _ in range(MAX_REDIRECTS + 1):
        response = session.get(
            current_url,
            stream=True,
            timeout=DEFAULT_IMPORT_TIMEOUT,
            allow_redirects=False,
            headers={
                "User-Agent": "PixShare/1.0 (+url-import)",
                "Accept": "image/*,*/*;q=0.8",
            },
        )

        if response.is_redirect or response.is_permanent_redirect:
            next_url = response.headers.get("Location", "").strip()
            response.close()
            if not next_url:
                raise UrlImportError("Redirection invalide.")
            current_url = validate_remote_image_url(urljoin(current_url, next_url))
            continue

        return session, response, current_url

    raise UrlImportError("Trop de redirections.")


def download_remote_image_to_temp(source_url: str, upload_folder: str, max_size_bytes: int) -> tuple[str, str, int, str]:
    session = None
    response = None
    tmp_path = ""

    try:
        session, response, final_url = _download_with_checked_redirects(source_url)

        if response.status_code != 200:
            raise UrlImportError("Téléchargement impossible depuis cette URL.")

        content_type = (response.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if content_type not in ALLOWED_IMPORT_MIME_TO_EXT:
            raise UrlImportError("Le lien doit pointer vers une image directe autorisée.")

        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > int(max_size_bytes):
                    raise UrlImportError("Image trop volumineuse pour l'import par URL.")
            except ValueError:
                pass

        fd, tmp_path = tempfile.mkstemp(prefix="url_import_", suffix=".bin", dir=upload_folder)
        total_size = 0

        with os.fdopen(fd, "wb") as tmp_file:
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                total_size += len(chunk)
                if total_size > int(max_size_bytes):
                    raise UrlImportError("Image trop volumineuse pour l'import par URL.")
                tmp_file.write(chunk)

        try:
            with Image.open(tmp_path) as img:
                img.verify()
            with Image.open(tmp_path) as img:
                image_format = (img.format or "").upper()
        except (UnidentifiedImageError, OSError, SyntaxError) as exc:
            raise UrlImportError("Le fichier distant n'est pas une image valide.") from exc

        real_ext = PIL_FORMAT_TO_EXT.get(image_format)
        if not real_ext:
            raise UrlImportError("Format d'image non pris en charge.")

        if real_ext in {".heic", ".heif"} and not HEIF_ENABLED:
            raise UrlImportError("Le format HEIC/HEIF n'est pas disponible sur ce serveur.")

        original_name = _build_original_name(final_url, real_ext)
        return tmp_path, original_name, total_size, content_type
    except Exception:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        raise
    finally:
        if response is not None:
            response.close()
        if session is not None:
            session.close()
