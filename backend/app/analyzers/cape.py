from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from app.config import settings


class CapeUnavailable(RuntimeError):
    pass


@dataclass
class CapeResult:
    task_id: int
    score: float
    signatures: list[dict]
    network: dict
    behavior: dict
    target: dict


def _headers() -> dict[str, str]:
    return {"Authorization": f"Token {settings.cape_api_token}"} if settings.cape_api_token else {}


def _extract_task_id(payload: dict) -> int:
    candidates = [
        payload.get("task_id"),
        (payload.get("data") or {}).get("task_id"),
        ((payload.get("data") or {}).get("task_ids") or [None])[0],
    ]
    for candidate in candidates:
        if candidate is not None:
            return int(candidate)
    raise CapeUnavailable(f"Réponse CAPE sans identifiant de tâche: {payload}")


def analyze_in_cape(path: Path, custom: str) -> CapeResult:
    if not settings.cape_base_url:
        raise CapeUnavailable("CAPE_BASE_URL n'est pas configurée")
    base = settings.cape_base_url
    timeout = httpx.Timeout(120.0, read=180.0)
    with httpx.Client(headers=_headers(), verify=settings.cape_verify_tls, timeout=timeout) as client:
        with path.open("rb") as stream:
            response = client.post(
                f"{base}/apiv2/tasks/create/file/",
                files={"file": (path.name, stream, "application/octet-stream")},
                data={"priority": "2", "timeout": "120", "custom": custom},
            )
        response.raise_for_status()
        task_id = _extract_task_id(response.json())

        deadline = time.monotonic() + settings.cape_timeout_seconds
        status = ""
        while time.monotonic() < deadline:
            view = client.get(f"{base}/apiv2/tasks/view/{task_id}/")
            view.raise_for_status()
            payload = view.json()
            task = payload.get("data") or payload.get("task") or payload
            status = str(task.get("status", "")).lower()
            if status in {"reported", "completed"}:
                break
            if status in {"failed_analysis", "failed_processing", "failed_reporting"}:
                raise CapeUnavailable(f"CAPE a échoué avec le statut {status}")
            time.sleep(settings.cape_poll_seconds)
        else:
            raise CapeUnavailable(f"Délai CAPE dépassé après {settings.cape_timeout_seconds} secondes")

        report_response = client.get(f"{base}/apiv2/tasks/get/report/{task_id}/")
        if report_response.status_code == 404:
            report_response = client.get(f"{base}/tasks/report/{task_id}")
        report_response.raise_for_status()
        raw = report_response.json()
        report = raw.get("data") if isinstance(raw.get("data"), dict) else raw
        info = report.get("info") or {}
        signatures = report.get("signatures") or []
        return CapeResult(
            task_id=task_id,
            score=float(info.get("score") or report.get("malscore") or 0.0),
            signatures=[
                {
                    "name": item.get("name"),
                    "description": item.get("description"),
                    "severity": item.get("severity"),
                    "confidence": item.get("confidence"),
                    "categories": item.get("categories") or [],
                }
                for item in signatures[:200]
            ],
            network=report.get("network") or {},
            behavior=report.get("behavior") or {},
            target=report.get("target") or {},
        )

