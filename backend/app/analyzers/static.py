from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from app.analyzers.features import base_features
from app.config import settings


@dataclass
class AnalyzerFinding:
    agent: str
    category: str
    severity: int
    title: str
    description: str
    confidence: float | None = None
    details: dict = field(default_factory=dict)


@dataclass
class StaticResult:
    mime_type: str
    features: dict[str, float]
    metadata: dict
    findings: list[AnalyzerFinding]
    risk_score: float


def detect_mime(path: Path) -> str:
    try:
        import magic

        return str(magic.from_file(str(path), mime=True))
    except Exception:
        import mimetypes

        return mimetypes.guess_type(path.name)[0] or "application/octet-stream"


def scan_clamav(path: Path) -> tuple[str | None, str | None]:
    try:
        import clamd

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
        _name, (status, signature) = next(iter(result.items()))
        return signature if status == "FOUND" else None, None
    except Exception as exc:
        return None, f"ClamAV indisponible: {type(exc).__name__}: {exc}"


def scan_yara(path: Path) -> tuple[list[dict], str | None]:
    try:
        import yara

        rule_files = sorted(settings.yara_rules_root.glob("*.yar")) + sorted(
            settings.yara_rules_root.glob("*.yara")
        )
        if not rule_files:
            return [], "Aucune règle YARA installée"
        rules = yara.compile(filepaths={p.stem: str(p) for p in rule_files}, error_on_warning=False)
        matches = rules.match(str(path), timeout=settings.yara_timeout_seconds)
        return [
            {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "meta": dict(match.meta),
            }
            for match in matches
        ], None
    except Exception as exc:
        return [], f"YARA indisponible: {type(exc).__name__}: {exc}"


def inspect_pe(path: Path, features: dict, metadata: dict, findings: list[AnalyzerFinding]) -> None:
    if path.suffix.lower() not in {".exe", ".dll", ".sys", ".scr", ".com"}:
        return
    try:
        import pefile

        pe = pefile.PE(str(path), fast_load=False)
        sections = []
        high_entropy = 0
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("ascii", "replace")
            ent = float(section.get_entropy())
            high_entropy += int(ent >= 7.2)
            sections.append({"name": name, "entropy": round(ent, 3), "size": section.SizeOfRawData})
        imports = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            library = entry.dll.decode("ascii", "replace")
            for imported in entry.imports:
                imports.append(f"{library}!{(imported.name or b'ordinal').decode('ascii', 'replace')}")
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
                    "Une ou plusieurs sections présentent une entropie compatible avec du packing ou du chiffrement.",
                    0.7,
                    {"count": high_entropy, "sections": sections},
                )
            )
    except Exception as exc:
        metadata["pe_error"] = f"{type(exc).__name__}: {exc}"


def inspect_office(path: Path, features: dict, metadata: dict, findings: list[AnalyzerFinding]) -> None:
    if path.suffix.lower() not in {".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptm", ".pptx"}:
        return
    try:
        from oletools.olevba import VBA_Parser

        parser = VBA_Parser(str(path))
        has_macro = bool(parser.detect_vba_macros())
        features["has_macro"] = float(has_macro)
        macro_indicators = []
        if has_macro:
            for kind, keyword, description in parser.analyze_macros():
                macro_indicators.append({"type": kind, "keyword": keyword, "description": description})
            findings.append(
                AnalyzerFinding(
                    "agent-static",
                    "office_macro",
                    65,
                    "Macros Office détectées",
                    "Le document contient du code VBA. Une validation et une analyse dynamique sont requises.",
                    0.9,
                    {"indicators": macro_indicators[:100]},
                )
            )
        metadata["office"] = {"has_macro": has_macro, "indicators": macro_indicators[:100]}
        parser.close()
    except Exception as exc:
        metadata["office_error"] = f"{type(exc).__name__}: {exc}"


def inspect_pdf(path: Path, metadata: dict, findings: list[AnalyzerFinding]) -> None:
    if path.suffix.lower() != ".pdf":
        return
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(path), strict=False)
        root_text = json.dumps(str(reader.trailer), ensure_ascii=False).lower()
        suspicious = [token for token in ("/javascript", "/openaction", "/launch", "/embeddedfile") if token in root_text]
        metadata["pdf"] = {"pages": len(reader.pages), "encrypted": reader.is_encrypted, "suspicious_tokens": suspicious}
        if suspicious:
            findings.append(
                AnalyzerFinding(
                    "agent-static",
                    "pdf_active_content",
                    70,
                    "Contenu PDF actif ou embarqué",
                    "Le PDF contient des objets actifs nécessitant une inspection approfondie.",
                    0.8,
                    {"tokens": suspicious},
                )
            )
    except Exception as exc:
        metadata["pdf_error"] = f"{type(exc).__name__}: {exc}"


def analyze_static(path: Path) -> StaticResult:
    mime_type = detect_mime(path)
    features, metadata = base_features(path, mime_type)
    findings: list[AnalyzerFinding] = []
    inspect_pe(path, features, metadata, findings)
    inspect_office(path, features, metadata, findings)
    inspect_pdf(path, metadata, findings)

    signature, clam_error = scan_clamav(path)
    features["clamav_detected"] = float(bool(signature))
    metadata["clamav"] = {"signature": signature, "error": clam_error}
    if signature:
        findings.append(
            AnalyzerFinding(
                "agent-static",
                "antivirus",
                100,
                f"ClamAV: {signature}",
                "Le moteur antivirus a identifié une signature malveillante.",
                0.99,
                {"signature": signature},
            )
        )
    elif clam_error:
        findings.append(AnalyzerFinding("agent-static", "availability", 10, "ClamAV indisponible", clam_error))

    matches, yara_error = scan_yara(path)
    features["yara_match_count"] = float(len(matches))
    metadata["yara"] = {"matches": matches, "error": yara_error}
    for match in matches:
        severity = int(match["meta"].get("severity", 70))
        findings.append(
            AnalyzerFinding(
                "agent-static",
                "yara",
                max(1, min(100, severity)),
                f"Règle YARA: {match['rule']}",
                str(match["meta"].get("description", "Correspondance avec une règle YARA locale.")),
                0.9,
                match,
            )
        )
    if yara_error:
        findings.append(AnalyzerFinding("agent-static", "availability", 10, "YARA incomplet", yara_error))

    suspicious_strings = int(features["suspicious_term_count"])
    if suspicious_strings:
        findings.append(
            AnalyzerFinding(
                "agent-static",
                "suspicious_strings",
                min(65, 20 + suspicious_strings * 5),
                "Chaînes sensibles détectées",
                "Des primitives fréquemment associées à l'exécution ou à l'injection ont été observées.",
                0.55,
                {"count": suspicious_strings},
            )
        )

    risk = max((finding.severity for finding in findings if finding.category != "availability"), default=0)
    risk = max(risk, min(60, features["pe_high_entropy_sections"] * 12 + suspicious_strings * 3))
    metadata["features"] = features
    return StaticResult(mime_type, features, metadata, findings, float(min(100, risk)))
