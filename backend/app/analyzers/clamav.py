from __future__ import annotations

from pathlib import Path

import clamd

from app.analyzers.base import BaseAnalyzer
from app.analyzers.types import AnalyzerFinding
from app.config import settings


class ClamAVAnalyzer(BaseAnalyzer):
    """
    Static antivirus analyzer using ClamAV.

    Responsibilities:
    - Connect to clamd
    - Scan the submitted file
    - Update metadata
    - Update extracted features
    - Produce forensic findings
    """

    name = "clamav"

    def _scan(
        self,
        path: Path,
    ) -> tuple[str | None, str | None]:

        try:

            client = clamd.ClamdNetworkSocket(
                host=settings.clamav_host,
                port=settings.clamav_port,
                timeout=settings.clamav_timeout_seconds,
            )

            client.ping()

            with path.open("rb") as stream:
                result = client.instream(stream)

            if not result:
                return None, None

            _, (status, signature) = next(iter(result.items()))

            if status == "FOUND":
                return signature, None

            return None, None

        except Exception as exc:
            return None, f"{type(exc).__name__}: {exc}"

    def analyze(
        self,
        path: Path,
        features: dict,
        metadata: dict,
        findings: list[AnalyzerFinding],
    ) -> None:

        signature, error = self._scan(path)

        features["clamav_detected"] = float(signature is not None)

        metadata["clamav"] = {
            "signature": signature,
            "error": error,
        }

        if signature:

            findings.append(
                AnalyzerFinding(
                    agent="agent-static",
                    category="antivirus",
                    severity=100,
                    title=f"ClamAV : {signature}",
                    description=(
                        "Le moteur ClamAV a identifié une signature "
                        "connue de malware."
                    ),
                    confidence=0.99,
                    details={
                        "engine": "ClamAV",
                        "signature": signature,
                    },
                )
            )

        elif error:

            findings.append(
                AnalyzerFinding(
                    agent="agent-static",
                    category="availability",
                    severity=10,
                    title="ClamAV indisponible",
                    description=error,
                    confidence=1.0,
                )
            )