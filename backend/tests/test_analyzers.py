from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import clamd
import pefile
import pytest
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject

import app.analyzers.office as office_module
import app.analyzers.static as static_module
from app.analyzers.clamav import ClamAVAnalyzer
from app.analyzers.office import OfficeAnalyzer
from app.analyzers.pdf import PDFAnalyzer
from app.analyzers.pe import PEAnalyzer
from app.analyzers.types import AnalyzerFinding
from app.analyzers.yara import YaraAnalyzer


def test_pe_analyzer_collects_structure_and_packing_signal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    class FakePE:
        FILE_HEADER = SimpleNamespace(Machine=332, TimeDateStamp=123)
        sections = [
            SimpleNamespace(Name=b".packed\x00", SizeOfRawData=64, get_entropy=lambda: 7.5),
        ]
        DIRECTORY_ENTRY_IMPORT = [
            SimpleNamespace(
                dll=b"KERNEL32.dll",
                imports=[SimpleNamespace(name=b"VirtualAlloc")],
            )
        ]

    monkeypatch.setattr(pefile, "PE", lambda *_args, **_kwargs: FakePE())
    features: dict = {}
    metadata: dict = {}
    findings: list[AnalyzerFinding] = []

    PEAnalyzer().analyze(sample, features, metadata, findings)

    assert features["pe_section_count"] == 1.0
    assert features["pe_import_count"] == 1.0
    assert features["pe_high_entropy_sections"] == 1.0
    assert metadata["pe"]["imports"] == ["KERNEL32.dll!VirtualAlloc"]
    assert findings[0].category == "packing"


def test_office_analyzer_records_macros(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    sample = tmp_path / "sample.docm"
    sample.write_bytes(b"test")

    class FakeParser:
        closed = False

        def __init__(self, _: str):
            pass

        def detect_vba_macros(self) -> bool:
            return True

        def analyze_macros(self):
            return [("AutoExec", "AutoOpen", "Runs when the document opens")]

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(office_module, "VBA_Parser", FakeParser)
    features: dict = {}
    metadata: dict = {}
    findings: list[AnalyzerFinding] = []

    OfficeAnalyzer().analyze(sample, features, metadata, findings)

    assert features["has_macro"] == 1.0
    assert metadata["office"]["indicator_count"] == 1
    assert findings[0].category == "office_macro"


def test_pdf_analyzer_detects_active_content(tmp_path: Path):
    sample = tmp_path / "active.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer._root_object[NameObject("/OpenAction")] = DictionaryObject(
        {NameObject("/S"): NameObject("/JavaScript")}
    )
    with sample.open("wb") as stream:
        writer.write(stream)

    features: dict = {}
    metadata: dict = {}
    findings: list[AnalyzerFinding] = []
    PDFAnalyzer().analyze(sample, features, metadata, findings)

    assert features["pdf_active_content"] == 1.0
    assert "/openaction" in metadata["pdf"]["suspicious_tokens"]
    assert findings[0].category == "pdf_active_content"


def test_clamav_analyzer_records_signature(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")

    class FakeClient:
        def __init__(self, **_: object):
            pass

        def ping(self) -> None:
            pass

        def instream(self, _stream):
            return {"stream": ("FOUND", "Test.Malware")}

    monkeypatch.setattr(clamd, "ClamdNetworkSocket", FakeClient)
    features: dict = {}
    metadata: dict = {}
    findings: list[AnalyzerFinding] = []
    ClamAVAnalyzer().analyze(sample, features, metadata, findings)

    assert features["clamav_detected"] == 1.0
    assert metadata["clamav"]["signature"] == "Test.Malware"
    assert findings[0].severity == 100


def test_yara_analyzer_records_rule_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")

    class FakeRules:
        def match(self, *_: object, **__: object):
            return [
                SimpleNamespace(
                    rule="Suspicious_Test",
                    namespace="local",
                    tags=["test"],
                    meta={"severity": 85, "description": "Test detection"},
                )
            ]

    analyzer = YaraAnalyzer()
    monkeypatch.setattr(analyzer, "_load_rules", lambda: FakeRules())
    features: dict = {}
    metadata: dict = {}
    findings: list[AnalyzerFinding] = []
    analyzer.analyze(sample, features, metadata, findings)

    assert features["yara_match_count"] == 1.0
    assert metadata["yara"]["matches"][0]["rule"] == "Suspicious_Test"
    assert findings[0].severity == 85


def test_static_risk_excludes_availability_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"ordinary content")

    class AvailabilityOnlyAnalyzer:
        def analyze(self, _path, _features, _metadata, findings):
            findings.append(
                AnalyzerFinding("test", "availability", 100, "Unavailable", "Analyzer unavailable")
            )

    monkeypatch.setattr(static_module.REGISTRY, "analyzers", lambda: [AvailabilityOnlyAnalyzer()])
    result = static_module.analyze_static(sample)

    assert result.risk_score == 0.0
    assert result.findings[0].category == "availability"
