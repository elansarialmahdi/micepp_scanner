from __future__ import annotations

from pathlib import Path

from app.analyzers.base import BaseAnalyzer
from app.analyzers.types import AnalyzerFinding


class SuspiciousStringsAnalyzer(BaseAnalyzer):
    """
    Detect suspicious strings already extracted by base_features().

    base_features() computes suspicious_term_count.
    This analyzer only interprets the feature and generates findings.
    """

    name = "strings"

    def analyze(
        self,
        path: Path,
        features: dict,
        metadata: dict,
        findings: list[AnalyzerFinding],
    ) -> None:

        suspicious_strings = int(
            features.get(
                "suspicious_term_count",
                0,
            )
        )

        metadata["strings"] = {
            "suspicious_term_count": suspicious_strings,
        }

        if suspicious_strings == 0:
            return

        severity = min(
            65,
            20 + suspicious_strings * 5,
        )

        findings.append(
            AnalyzerFinding(
                agent="agent-static",
                category="suspicious_strings",
                severity=severity,
                title="Chaînes sensibles détectées",
                description=(
                    "Des chaînes fréquemment associées à des comportements "
                    "malveillants ont été détectées dans le fichier."
                ),
                confidence=0.55,
                details={
                    "count": suspicious_strings,
                },
            )
        )