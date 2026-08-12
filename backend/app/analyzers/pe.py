from __future__ import annotations

from pathlib import Path

from app.analyzers.base import BaseAnalyzer
from app.analyzers.types import AnalyzerFinding


class PEAnalyzer(BaseAnalyzer):
    """
    Portable Executable (PE) analyzer.

    Inspects Windows executables (.exe, .dll, .sys...)
    and extracts structural information.
    """

    name = "pe"

    def analyze(
        self,
        path: Path,
        features: dict,
        metadata: dict,
        findings: list[AnalyzerFinding],
    ) -> None:

        if path.suffix.lower() not in {
            ".exe",
            ".dll",
            ".sys",
            ".scr",
            ".com",
        }:
            return

        try:
            import pefile

            pe = pefile.PE(str(path), fast_load=False)

            sections = []
            high_entropy = 0

            for section in pe.sections:
                name = section.Name.rstrip(b"\x00").decode(
                    "ascii",
                    "replace",
                )

                entropy = float(section.get_entropy())

                high_entropy += int(entropy >= 7.2)

                sections.append(
                    {
                        "name": name,
                        "entropy": round(entropy, 3),
                        "size": section.SizeOfRawData,
                    }
                )

            imports = []

            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):

                library = entry.dll.decode(
                    "ascii",
                    "replace",
                )

                for imported in entry.imports:

                    imports.append(
                        f"{library}!{(imported.name or b'ordinal').decode('ascii','replace')}"
                    )

            features["pe_section_count"] = float(len(sections))
            features["pe_import_count"] = float(len(imports))
            features["pe_high_entropy_sections"] = float(high_entropy)

            metadata["pe"] = {
                "machine": int(pe.FILE_HEADER.Machine),
                "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
                "sections": sections,
                "imports": imports[:500],
            }

            if high_entropy:

                findings.append(
                    AnalyzerFinding(
                        "agent-static",
                        "packing",
                        min(70, 35 + high_entropy * 10),
                        "Sections PE à forte entropie",
                        (
                            "Une ou plusieurs sections présentent "
                            "une entropie compatible avec du packing "
                            "ou du chiffrement."
                        ),
                        0.7,
                        {
                            "count": high_entropy,
                            "sections": sections,
                            "mitre_ttp": "T1027",
                        },
                    )
                )

        except Exception as exc:

            metadata["pe_error"] = (
                f"{type(exc).__name__}: {exc}"
            )