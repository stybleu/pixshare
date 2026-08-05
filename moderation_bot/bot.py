from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import requests
from nudenet import NudeDetector


EXPLICIT_CLASSES = {
    "FEMALE_GENITALIA_EXPOSED",
    "MALE_GENITALIA_EXPOSED",
    "ANUS_EXPOSED",
    "FEMALE_BREAST_EXPOSED",
    "BUTTOCKS_EXPOSED",
}


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except ValueError:
        return default


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    base_url: str
    api_key: str
    block_threshold: float
    dry_run: bool
    run_once: bool
    poll_interval: int
    request_timeout: int
    max_image_bytes: int
    batch_limit: int

    @classmethod
    def from_env(cls) -> "Settings":
        base_url = os.environ.get("PIXSHARE_BASE_URL", "https://directfile.onrender.com").rstrip("/")
        api_key = os.environ.get("MODERATION_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("MODERATION_API_KEY est absente.")
        return cls(
            base_url=base_url,
            api_key=api_key,
            block_threshold=max(0.0, min(env_float("BLOCK_THRESHOLD", 0.85), 1.0)),
            dry_run=env_bool("DRY_RUN", True),
            run_once=env_bool("RUN_ONCE", True),
            poll_interval=max(10, env_int("POLL_INTERVAL_SECONDS", 30)),
            request_timeout=max(5, env_int("REQUEST_TIMEOUT_SECONDS", 45)),
            max_image_bytes=max(1, env_int("MAX_IMAGE_MB", 20)) * 1024 * 1024,
            batch_limit=max(1, min(env_int("BATCH_LIMIT", 50), 500)),
        )


class PixShareModerationBot:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.session = requests.Session()
        self.session.headers.update({
            "X-Moderation-Key": settings.api_key,
            "User-Agent": "PixShare-NudeNet-Bot/1.0",
            "Accept": "application/json",
        })
        self.detector = NudeDetector()

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        response = self.session.request(
            method,
            url,
            timeout=self.settings.request_timeout,
            **kwargs,
        )
        response.raise_for_status()
        return response

    def list_pending(self) -> list[dict[str, Any]]:
        url = urljoin(self.settings.base_url + "/", "api/admin/moderation/images")
        response = self._request("GET", url, params={"limit": self.settings.batch_limit})
        payload = response.json()
        return payload.get("data", {}).get("images", [])

    def download_private_bytes(self, item: dict[str, Any]) -> bytes:
        url = str(item.get("content_url") or "")
        if not url:
            raise RuntimeError("content_url absente")

        response = self._request("GET", url, stream=True)
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > self.settings.max_image_bytes:
            response.close()
            raise RuntimeError("image trop volumineuse pour le bot")

        chunks: list[bytes] = []
        total = 0
        try:
            for chunk in response.iter_content(chunk_size=128 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > self.settings.max_image_bytes:
                    raise RuntimeError("image trop volumineuse pour le bot")
                chunks.append(chunk)
        finally:
            response.close()

        return b"".join(chunks)

    def analyze(self, image_bytes: bytes) -> tuple[str | None, float, list[dict[str, Any]]]:
        detections = self.detector.detect(image_bytes)
        strongest_class: str | None = None
        strongest_score = 0.0

        for detection in detections:
            label = str(detection.get("class") or "")
            score = float(detection.get("score") or 0.0)
            if label in EXPLICIT_CLASSES and score > strongest_score:
                strongest_class = label
                strongest_score = score

        return strongest_class, strongest_score, detections

    def approve(self, item: dict[str, Any], score: float) -> None:
        self._request(
            "POST",
            str(item["approve_url"]),
            json={"detector": "nudenet-3.4.2", "score": round(score, 6)},
        )

    def delete(self, item: dict[str, Any], score: float, label: str) -> None:
        self._request(
            "DELETE",
            str(item["delete_url"]),
            json={
                "reason": "contenu_illicite",
                "detector": "nudenet-3.4.2",
                "score": round(score, 6),
                "label": label,
            },
        )

    def process_once(self) -> int:
        items = self.list_pending()
        print(f"[bot] {len(items)} image(s) en attente")
        processed = 0

        for item in items:
            file_id = str(item.get("id") or "?")
            try:
                image_bytes = self.download_private_bytes(item)
                label, score, _detections = self.analyze(image_bytes)
                blocked = label is not None and score >= self.settings.block_threshold
                decision = "DELETE" if blocked else "APPROVE"

                print(
                    f"[bot] id={file_id} decision={decision} "
                    f"label={label or '-'} score={score:.3f}"
                )

                if self.settings.dry_run:
                    print(f"[bot] id={file_id} DRY_RUN: aucune action envoyée")
                elif blocked:
                    self.delete(item, score, label or "explicit")
                else:
                    self.approve(item, score)

                processed += 1
            except requests.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else "?"
                print(f"[bot] id={file_id} erreur HTTP={status}", file=sys.stderr)
            except Exception as exc:
                print(f"[bot] id={file_id} erreur={type(exc).__name__}: {exc}", file=sys.stderr)

        return processed

    def run(self) -> None:
        while True:
            self.process_once()
            if self.settings.run_once:
                return
            time.sleep(self.settings.poll_interval)


def main() -> int:
    try:
        settings = Settings.from_env()
        print(
            "[bot] démarrage "
            f"dry_run={settings.dry_run} run_once={settings.run_once} "
            f"threshold={settings.block_threshold:.2f}"
        )
        PixShareModerationBot(settings).run()
        return 0
    except Exception as exc:
        print(f"[bot] démarrage impossible: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
