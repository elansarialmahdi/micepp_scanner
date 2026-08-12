from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

from app.analyzers.ember import extract_ember_features

BASE_FEATURE_NAMES = [
    "size_log2",
    "entropy",
    "printable_ratio",
    "string_count",
    "url_count",
    "ip_count",
    "suspicious_term_count",
    "pe_section_count",
    "pe_import_count",
    "pe_high_entropy_sections",
    "is_executable",
    "is_script",
    "is_office",
    "is_pdf",
    "has_macro",
    "yara_match_count",
    "clamav_detected",
    "sandbox_signature_count",
    "sandbox_score",
]

EMBER_HISTOGRAM_NAMES = [f"byte_hist_{i}" for i in range(256)]
EMBER_ENTROPY_NAMES = [f"entropy_bin_{i}" for i in range(16)]
EMBER_PE_NAMES = [
    "is_pe",
    "has_debug",
    "exports_count",
    "imports_count",
    "has_relocations",
    "has_resources",
    "has_signature",
    "has_tls",
    "pe_unmapped_sections",
]

FEATURE_NAMES = BASE_FEATURE_NAMES + EMBER_HISTOGRAM_NAMES + EMBER_ENTROPY_NAMES + EMBER_PE_NAMES

URL_RE = re.compile(rb"https?://[^\s\x00\"'<>]{4,}", re.I)
IP_RE = re.compile(rb"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
ASCII_RE = re.compile(rb"[ -~]{4,}")
SUSPICIOUS_TERMS = (
    b"powershell",
    b"cmd.exe",
    b"rundll32",
    b"regsvr32",
    b"virtualalloc",
    b"writeprocessmemory",
    b"createremotethread",
    b"wscript.shell",
    b"autoopen",
    b"document_open",
    b"frombase64string",
)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def base_features(path: Path, mime_type: str) -> tuple[dict[str, float], dict]:
    size = path.stat().st_size
    with path.open("rb") as stream:
        sample = stream.read(4 * 1024 * 1024)
    strings = ASCII_RE.findall(sample)
    lowered = sample.lower()
    executable = mime_type in {
        "application/x-dosexec",
        "application/x-executable",
        "application/x-pie-executable",
        "application/x-sharedlib",
    } or path.suffix.lower() in {".exe", ".dll", ".com", ".scr", ".elf", ".so"}
    script = path.suffix.lower() in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".sh", ".py"}
    office = path.suffix.lower() in {".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptm", ".pptx"}
    pdf = path.suffix.lower() == ".pdf" or mime_type == "application/pdf"
    
    values = {
        "size_log2": math.log2(size + 1),
        "entropy": entropy(sample),
        "printable_ratio": sum(32 <= byte < 127 for byte in sample) / max(1, len(sample)),
        "string_count": float(len(strings)),
        "url_count": float(len(URL_RE.findall(sample))),
        "ip_count": float(len(IP_RE.findall(sample))),
        "suspicious_term_count": float(sum(lowered.count(term) for term in SUSPICIOUS_TERMS)),
        "pe_section_count": 0.0,
        "pe_import_count": 0.0,
        "pe_high_entropy_sections": 0.0,
        "is_executable": float(executable),
        "is_script": float(script),
        "is_office": float(office),
        "is_pdf": float(pdf),
        "has_macro": 0.0,
        "yara_match_count": 0.0,
        "clamav_detected": 0.0,
        "sandbox_signature_count": 0.0,
        "sandbox_score": 0.0,
    }
    
    ember_vals, ember_meta = extract_ember_features(path, mime_type)
    values.update(ember_vals)

    metadata = {
        "sampled_bytes": len(sample),
        "urls": [item.decode("utf-8", "replace")[:500] for item in URL_RE.findall(sample)[:20]],
        "ip_addresses": [item.decode() for item in IP_RE.findall(sample)[:20]],
        "ember": ember_meta,
    }
    return values, metadata


def vectorize(features: dict[str, float]) -> list[float]:
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]


