from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests


class PixShareError(RuntimeError):
    """Erreur retournée par l'API PixShare ou par le réseau."""

    def __init__(self, message: str, status_code: int | None = None, code: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code


@dataclass(slots=True)
class PixShareFile:
    id: str
    url: str
    viewer_url: str = ""
    expires_at: str | None = None
    status: str = ""
    filename: str = ""
    size: int = 0

    @classmethod
    def from_api(cls, payload: dict[str, Any]) -> "PixShareFile":
        return cls(
            id=str(payload.get("id", "")),
            url=str(payload.get("url", "")),
            viewer_url=str(payload.get("url_viewer") or payload.get("viewer_url") or ""),
            expires_at=payload.get("expiration") or payload.get("expires_at"),
            status=str(payload.get("status", "")),
            filename=str(payload.get("original_filename") or payload.get("filename") or ""),
            size=int(payload.get("size") or 0),
        )


class PixShare:
    """Client Python minimal pour l'API PixShare."""

    def __init__(self, api_key: str, base_url: str = "https://pixshare.fr", timeout: int = 30):
        if not api_key:
            raise ValueError("api_key ne peut pas être vide")

        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"X-API-Key": api_key})

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = self.session.request(
                method,
                f"{self.base_url}{path}",
                timeout=self.timeout,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise PixShareError(f"Impossible de contacter PixShare : {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise PixShareError(
                "PixShare a retourné une réponse invalide.",
                status_code=response.status_code,
            ) from exc

        if not response.ok or payload.get("success") is False:
            error = payload.get("error") or {}
            raise PixShareError(
                str(error.get("message") or f"Erreur HTTP {response.status_code}"),
                status_code=response.status_code,
                code=error.get("code"),
            )

        data = payload.get("data", payload)
        if not isinstance(data, dict):
            raise PixShareError("Format de réponse PixShare inattendu.")

        return data

    def upload(self, file_path: str | Path, expiration: int | str | None = None) -> PixShareFile:
        """Envoie un fichier et retourne un objet PixShareFile."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(path)

        form: dict[str, str] = {}
        if expiration is not None:
            form["expiration"] = str(expiration)

        with path.open("rb") as file_obj:
            data = self._request(
                "POST",
                "/api/upload",
                files={"file": (path.name, file_obj)},
                data=form,
            )

        return PixShareFile.from_api(data)

    def info(self, file_id: str) -> PixShareFile:
        """Récupère les informations d'un fichier envoyé avec cette clé API."""
        data = self._request("GET", f"/api/file/{file_id}")
        return PixShareFile.from_api(data)

    def delete(self, file_id: str) -> bool:
        """Supprime un fichier envoyé avec cette clé API."""
        data = self._request("DELETE", f"/api/file/{file_id}")
        return bool(data.get("deleted"))

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "PixShare":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
