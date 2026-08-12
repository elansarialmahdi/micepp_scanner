from __future__ import annotations

from pathlib import Path

from pypdf import PdfReader

from app.analyzers.base import BaseAnalyzer
from app.analyzers.types import AnalyzerFinding


class PDFAnalyzer(BaseAnalyzer):
    """
    Analyze PDF documents.

    Responsibilities:
    - Detect JavaScript
    - Detect OpenAction
    - Detect Launch actions
    - Detect embedded files
    - Collect metadata
    - Generate forensic findings
    """

    name = "pdf"

    PDF_TOKENS = (
        "/javascript",
        "/openaction",
        "/launch",
        "/embeddedfile",
    )

    @staticmethod
    def _contains_token(value, token: str, seen: set[int] | None = None) -> bool:
        """Search resolved PDF objects without relying on their string representation."""
        seen = seen if seen is not None else set()
        try:
            resolved = value.get_object()
        except AttributeError:
            resolved = value
        marker = id(resolved)
        if marker in seen:
            return False
        seen.add(marker)
        if isinstance(resolved, dict):
            for key, child in resolved.items():
                if str(key).lower() == token or PDFAnalyzer._contains_token(child, token, seen):
                    return True
            return False
        if isinstance(resolved, (list, tuple)):
            return any(PDFAnalyzer._contains_token(item, token, seen) for item in resolved)
        return str(resolved).lower() == token

    def analyze(
        self,
        path: Path,
        features: dict,
        metadata: dict,
        findings: list[AnalyzerFinding],
    ) -> None:

        if path.suffix.lower() != ".pdf":
            return

        try:
            reader = PdfReader(
                str(path),
                strict=False,
            )

            suspicious_tokens = [
                token
                for token in self.PDF_TOKENS
                if self._contains_token(reader.trailer, token)
            ]

            metadata["pdf"] = {
                "pages": len(reader.pages),
                "encrypted": reader.is_encrypted,
                "suspicious_tokens": suspicious_tokens,
                "token_count": len(suspicious_tokens),
            }

            features["pdf_page_count"] = float(len(reader.pages))
            features["pdf_active_content"] = float(
                bool(suspicious_tokens)
            )

            if suspicious_tokens:
                findings.append(
                    AnalyzerFinding(
                        agent="agent-static",
                        category="pdf_active_content",
                        severity=70,
                        title="Contenu PDF actif détecté",
                        description=(
                            "Le document contient des objets PDF actifs "
                            "ou embarqués pouvant nécessiter une "
                            "analyse approfondie."
                        ),
                        confidence=0.80,
                        details={
                            "tokens": suspicious_tokens,
                            "count": len(suspicious_tokens),
                            "mitre_ttp": "T1059",
                        },
                    )
                )

        except Exception as exc:
            metadata["pdf_error"] = f"{type(exc).__name__}: {exc}"
