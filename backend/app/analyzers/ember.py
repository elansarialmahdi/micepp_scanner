from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

# EMBER Feature Category Definitions for Explainability
EMBER_CATEGORIES = [
    "byte_histogram",
    "byte_entropy",
    "general_info",
    "header_info",
    "section_info",
    "imports_info",
    "exports_info",
    "string_stats",
]

SUSPICIOUS_APIS = {
    "virtualalloc",
    "virtualallocex",
    "writeprocessmemory",
    "createremotethread",
    "ntunmapviewofsection",
    "queueuserapc",
    "setwindowshookex",
    "internetopen",
    "urldownloadtofile",
    "winhttpopen",
    "regsetvalueex",
    "createservice",
    "cmd.exe",
    "powershell",
    "wscript.shell",
}

URL_RE = re.compile(rb"https?://[^\s\x00\"'<>]{4,}", re.I)
IP_RE = re.compile(rb"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
ASCII_RE = re.compile(rb"[ -~]{4,}")


def calculate_byte_histogram(data: bytes) -> list[float]:
    """Computes normalized 256-byte frequency distribution."""
    if not data:
        return [0.0] * 256
    counts = Counter(data)
    total = float(len(data))
    return [counts[i] / total for i in range(256)]


def calculate_byte_entropy_histogram(data: bytes, window_size: int = 2048, step: int = 1024) -> list[float]:
    """
    Computes a 16-bin entropy histogram across sliding byte windows.
    Returns 16 normalized bin ratios representing low to high entropy distribution.
    """
    bins = [0.0] * 16
    if not data:
        return bins

    total_windows = 0
    for i in range(0, max(1, len(data) - window_size + 1), step):
        window = data[i : i + window_size]
        if not window:
            continue
        counts = Counter(window)
        length = float(len(window))
        ent = -sum((c / length) * math.log2(c / length) for c in counts.values())
        bin_idx = min(15, int((ent / 8.0) * 16))
        bins[bin_idx] += 1.0
        total_windows += 1

    if total_windows > 0:
        bins = [b / total_windows for b in bins]
    return bins


def extract_ember_features(path: Path, mime_type: str) -> tuple[dict[str, float], dict[str, Any]]:
    """
    Extracts EMBER-compliant feature set for PE binaries & general files.
    Returns:
      (vector_dict, metadata_dict)
    """
    size = path.stat().st_size
    with path.open("rb") as stream:
        sample = stream.read(4 * 1024 * 1024)

    byte_hist = calculate_byte_histogram(sample)
    entropy_hist = calculate_byte_entropy_histogram(sample)

    strings = ASCII_RE.findall(sample)
    printable_len = sum(len(s) for s in strings)
    avg_string_len = (printable_len / float(len(strings))) if strings else 0.0
    lowered = sample.lower()

    suspicious_api_hits = sum(lowered.count(api.encode()) for api in SUSPICIOUS_APIS)
    url_hits = len(URL_RE.findall(sample))
    ip_hits = len(IP_RE.findall(sample))

    features: dict[str, float] = {
        "file_size": float(size),
        "file_size_log2": math.log2(size + 1),
        "printable_ratio": sum(32 <= b < 127 for b in sample) / max(1, len(sample)),
        "string_count": float(len(strings)),
        "avg_string_len": float(avg_string_len),
        "url_count": float(url_hits),
        "ip_count": float(ip_hits),
        "suspicious_api_count": float(suspicious_api_hits),
        # PE specific indicators (default 0 for non-PE)
        "is_pe": 0.0,
        "has_debug": 0.0,
        "exports_count": 0.0,
        "imports_count": 0.0,
        "has_relocations": 0.0,
        "has_resources": 0.0,
        "has_signature": 0.0,
        "has_tls": 0.0,
        "pe_section_count": 0.0,
        "pe_high_entropy_sections": 0.0,
        "pe_unmapped_sections": 0.0,
    }

    # Add 256 byte histogram values
    for i, val in enumerate(byte_hist):
        features[f"byte_hist_{i}"] = float(val)

    # Add 16 byte entropy histogram bins
    for i, val in enumerate(entropy_hist):
        features[f"entropy_bin_{i}"] = float(val)

    metadata: dict[str, Any] = {
        "ember_categories": EMBER_CATEGORIES,
        "sampled_bytes": len(sample),
        "urls": [u.decode("utf-8", "replace")[:300] for u in URL_RE.findall(sample)[:10]],
        "ips": [ip.decode("utf-8", "replace") for ip in IP_RE.findall(sample)[:10]],
    }

    # Inspect PE structure if executable
    is_exe_ext = path.suffix.lower() in {".exe", ".dll", ".sys", ".scr", ".com", ".cpl"}
    if is_exe_ext or mime_type in {"application/x-dosexec", "application/x-executable"}:
        try:
            import pefile

            pe = pefile.PE(str(path), fast_load=False)
            features["is_pe"] = 1.0
            features["has_debug"] = 1.0 if hasattr(pe, "DIRECTORY_ENTRY_DEBUG") else 0.0
            features["has_relocations"] = 1.0 if hasattr(pe, "DIRECTORY_ENTRY_BASERELOC") else 0.0
            features["has_resources"] = 1.0 if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE") else 0.0
            features["has_tls"] = 1.0 if hasattr(pe, "DIRECTORY_ENTRY_TLS") else 0.0
            features["has_signature"] = 1.0 if hasattr(pe, "DIRECTORY_ENTRY_SECURITY") else 0.0

            exports_count = 0
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            features["exports_count"] = float(exports_count)

            imports_list = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    lib = entry.dll.decode("ascii", "replace") if entry.dll else "unknown"
                    for imp in entry.imports:
                        imp_name = imp.name.decode("ascii", "replace") if imp.name else f"ord_{imp.ordinal}"
                        imports_list.append(f"{lib}!{imp_name}")
            features["imports_count"] = float(len(imports_list))

            high_ent_sections = 0
            unmapped_sections = 0
            sections_meta = []
            for sec in pe.sections:
                sec_name = sec.Name.rstrip(b"\x00").decode("ascii", "replace")
                sec_ent = float(sec.get_entropy())
                if sec_ent >= 7.0:
                    high_ent_sections += 1
                if sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 0:
                    unmapped_sections += 1
                sections_meta.append({"name": sec_name, "entropy": round(sec_ent, 3), "size": sec.SizeOfRawData})

            features["pe_section_count"] = float(len(pe.sections))
            features["pe_high_entropy_sections"] = float(high_ent_sections)
            features["pe_unmapped_sections"] = float(unmapped_sections)

            metadata["pe_details"] = {
                "machine": int(pe.FILE_HEADER.Machine),
                "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
                "subsystem": int(pe.OPTIONAL_HEADER.Subsystem) if hasattr(pe, "OPTIONAL_HEADER") else 0,
                "sections": sections_meta,
                "imported_functions_sample": imports_list[:100],
            }
        except Exception as exc:
            metadata["pe_parse_error"] = f"{type(exc).__name__}: {exc}"

    return features, metadata
