from pathlib import Path

import pytest

from app.analyzers.extractor import extract_evidence
from app.analyzers.features import FEATURE_NAMES, entropy, vectorize
from app.config import settings
from app.models import EvidenceKind
from app.storage import assert_within, hash_file, sanitize_filename


def test_filename_and_path_guards(tmp_path: Path):
    assert sanitize_filename("../../preuve très sensible.E01") == "preuve_tr_s_sensible.E01"
    assert assert_within(tmp_path / "case" / "file.bin", tmp_path).is_absolute()
    with pytest.raises(ValueError):
        assert_within(tmp_path / ".." / "outside.bin", tmp_path)


def test_hashes_and_feature_vector_are_deterministic(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"forensic-evidence\x00" * 100)
    first = hash_file(sample)
    second = hash_file(sample)
    assert first == second
    assert first[0] == 1800
    assert entropy(b"\x00" * 256) == 0
    vector = vectorize({"entropy": 7.5})
    assert len(vector) == len(FEATURE_NAMES)
    assert vector[FEATURE_NAMES.index("entropy")] == 7.5


def test_individual_file_is_analyzed_from_a_work_copy(tmp_path: Path):
    source = tmp_path / "original.bin"
    source.write_bytes(b"original forensic content")

    root, extracted = extract_evidence(source, EvidenceKind.FILE, "job-copy-check")

    assert root == settings.work_root / "job-copy-check" / "extracted"
    assert extracted[0] != source
    assert extracted[0].read_bytes() == source.read_bytes()
    assert hash_file(extracted[0]) == hash_file(source)
