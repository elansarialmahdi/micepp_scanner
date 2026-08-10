from __future__ import annotations

from pathlib import Path

from oletools.olevba import VBA_Parser

from app.analyzers.base import BaseAnalyzer
from app.analyzers.types import AnalyzerFinding


class OfficeAnalyzer(BaseAnalyzer):
    """
    Analyze Microsoft Office documents.

    Supported formats:
    - DOC
    - DOCM
    - DOCX
    - XLS
    - XLSM
    - XLSX
    - PPT
    - PPTM
    - PPTX

    Responsibilities:
    - Detect VBA macros
    - Extract suspicious VBA indicators
    - Update metadata
    - Update extracted features
    - Create forensic findings
    """

    name = "office"

    OFFICE_EXTENSIONS = {
        ".doc",
        ".docm",
        ".docx",
        ".xls",
        ".xlsm",
        ".xlsx",
        ".ppt",
        ".pptm",
        ".pptx",
    }

    def analyze(
        self,
        path: Path,
        features: dict,
        metadata: dict,
        findings: list[AnalyzerFinding],
    ) -> None:

        if path.suffix.lower() not in self.OFFICE_EXTENSIONS:
            return

        try:
            parser = VBA_Parser(str(path))

            has_macro = bool(parser.detect_vba_macros())

            features["has_macro"] = float(has_macro)

            macro_indicators = []

            if has_macro:

                for kind, keyword, description in parser.analyze_macros():
                    macro_indicators.append(
                        {
                            "type": kind,
                            "keyword": keyword,
                            "description": description,
                        }
                    )

                findings.append(
                    AnalyzerFinding(
                        agent="agent-static",
                        category="office_macro",
                        severity=65,
                        title="Macros Office détectées",
                        description=(
                            "Le document contient du code VBA. "
                            "Une validation humaine et une analyse dynamique "
                            "sont recommandées."
                        ),
                        confidence=0.90,
                        details={
                            "indicator_count": len(macro_indicators),
                            "indicators": macro_indicators[:100],
                        },
                    )
                )

            metadata["office"] = {
                "has_macro": has_macro,
                "indicator_count": len(macro_indicators),
                "indicators": macro_indicators[:100],
            }

            parser.close()

        except Exception as exc:

            metadata["office_error"] = (
                f"{type(exc).__name__}: {exc}"
            )