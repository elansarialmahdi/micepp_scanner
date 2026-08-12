from __future__ import annotations

from pathlib import Path

from app.analyzers.features import base_features
from app.analyzers.registry import REGISTRY
from app.analyzers.types import StaticResult,AnalyzerFinding


def detect_mime(path: Path) -> str:
    try:
        import magic

        return str(magic.from_file(str(path), mime=True))
    except Exception:
        import mimetypes

        return mimetypes.guess_type(path.name)[0] or "application/octet-stream"


def analyze_static(path: Path) -> StaticResult:
    """
    Execute every registered static analyzer.

    Workflow:
        1. Detect MIME type.
        2. Extract generic features.
        3. Execute every analyzer.
        4. Compute global risk.
        5. Return the analysis result.
    """

    mime_type = detect_mime(path)

    features, metadata = base_features(
        path,
        mime_type,
    )

    findings = []

    for analyzer in REGISTRY.analyzers():
        analyzer.analyze(
            path,
            features,
            metadata,
            findings,
        )

    suspicious_strings = int(
        features.get(
            "suspicious_term_count",
            0,
        )
    )

    risk = max(
        (
            finding.severity
            for finding in findings
            if finding.category != "availability"
        ),
        default=0,
    )

    risk = max(
        risk,
        min(
            60,
            features.get("pe_high_entropy_sections", 0) * 12
            + suspicious_strings * 3,
        ),
    )

    metadata["features"] = features

    # If no actionable finding was produced, emit one informational finding
    # so the "Constats techniques" panel is never shown empty.
    actionable = [f for f in findings if f.category != "availability"]
    if not actionable:
        mime_short = mime_type.split("/")[-1].upper()
        findings.append(
            AnalyzerFinding(
                agent="agent-static",
                category="info",
                severity=0,
                title=f"Analyse statique terminée — aucune menace détectée",
                description=(
                    f"Les moteurs statiques (antivirus, YARA, entropie, chaînes) "
                    f"n'ont relevé aucun indicateur suspect dans ce fichier "
                    f"{mime_short} ({metadata.get('sampled_bytes', 0):,} octets analysés)."
                ),
                confidence=1.0,
                details={
                    "mime_type": mime_type,
                    "engines_run": ["ClamAV", "YARA", "PE", "Office", "PDF", "Strings"],
                    "static_risk_score": float(min(100, risk)),
                },
            )
        )

    return StaticResult(
        mime_type=mime_type,
        features=features,
        metadata=metadata,
        findings=findings,
        risk_score=float(min(100, risk)),
    )