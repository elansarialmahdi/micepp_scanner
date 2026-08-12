from __future__ import annotations

import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

from app.config import settings
from app.models import EvidenceKind
from app.storage import assert_within


class ExtractionError(RuntimeError):
    pass


def _safe_target(root: Path, member_name: str) -> Path:
    normalized = member_name.replace("\\", "/").lstrip("/")
    return assert_within(root / normalized, root)


def _enforce_limits(root: Path) -> list[Path]:
    files: list[Path] = []
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            path.unlink(missing_ok=True)
            continue
        if path.is_file():
            files.append(path)
            total += path.stat().st_size
            if len(files) > settings.max_extracted_files:
                raise ExtractionError(f"Extraction exceeds {settings.max_extracted_files} files")
            if total > settings.max_extracted_bytes:
                raise ExtractionError(f"Extraction exceeds {settings.max_extracted_bytes} bytes")
    return files


def _copy_limited(source, destination: Path, remaining: int) -> int:
    """Copy one archive member without exceeding the job byte budget."""
    copied = 0
    with destination.open("xb") as output:
        while chunk := source.read(1024 * 1024):
            copied += len(chunk)
            if copied > remaining:
                raise ExtractionError("Archive extraction exceeds the configured byte limit")
            output.write(chunk)
    return copied


def _extract_zip(source: Path, destination: Path) -> None:
    with zipfile.ZipFile(source) as archive:
        members = archive.infolist()
        declared_total = sum(item.file_size for item in members if not item.is_dir())
        if len(members) > settings.max_extracted_files or declared_total > settings.max_extracted_bytes:
            raise ExtractionError("Archive exceeds the configured extraction limits")
        extracted_bytes = 0
        extracted_files = 0
        for item in members:
            if item.is_dir():
                continue
            if stat.S_ISLNK(item.external_attr >> 16):
                raise ExtractionError("ZIP symbolic links are not allowed")
            extracted_files += 1
            if extracted_files > settings.max_extracted_files:
                raise ExtractionError("Archive exceeds the configured file limit")
            target = _safe_target(destination, item.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(item) as stream:
                extracted_bytes += _copy_limited(
                    stream, target, settings.max_extracted_bytes - extracted_bytes
                )


def _extract_tar(source: Path, destination: Path) -> None:
    with tarfile.open(source, mode="r:*") as archive:
        all_members = archive.getmembers()
        if any(member.issym() or member.islnk() for member in all_members):
            raise ExtractionError("TAR links are not allowed")
        if any(not (member.isfile() or member.isdir()) for member in all_members):
            raise ExtractionError("TAR contains a disallowed entry type")
        members = [member for member in all_members if member.isfile()]
        declared_total = sum(member.size for member in members)
        if len(members) > settings.max_extracted_files or declared_total > settings.max_extracted_bytes:
            raise ExtractionError("Archive exceeds the configured extraction limits")
        extracted_bytes = 0
        for member in members:
            target = _safe_target(destination, member.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            with extracted:
                extracted_bytes += _copy_limited(
                    extracted, target, settings.max_extracted_bytes - extracted_bytes
                )


def _recover_image(command: list[str], destination: Path) -> None:
    """Run tsk_recover while continuously enforcing extraction limits."""
    deadline = time.monotonic() + 6 * 60 * 60
    with tempfile.TemporaryFile(mode="w+") as error_output:
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=error_output,
            text=True,
        )
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise ExtractionError("tsk_recover exceeded the six-hour timeout")
                _enforce_limits(destination)
                time.sleep(0.25)
        except Exception:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            raise
        error_output.seek(0)
        error = error_output.read()
    if process.returncode != 0:
        raise ExtractionError(f"tsk_recover failed ({process.returncode}): {error[-2000:]}")
    _enforce_limits(destination)


def extract_evidence(source: Path, kind: EvidenceKind, job_id: str) -> tuple[Path, list[Path]]:
    work = assert_within(settings.work_root / job_id, settings.work_root)
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True, exist_ok=False)
    extracted = work / "extracted"
    extracted.mkdir()
    try:
        if kind == EvidenceKind.FILE:
            target = assert_within(extracted / source.name, extracted)
            shutil.copy2(source, target)
            target.chmod(0o640)
            return extracted, [target]
        if kind == EvidenceKind.ARCHIVE:
            if zipfile.is_zipfile(source):
                _extract_zip(source, extracted)
            elif tarfile.is_tarfile(source):
                _extract_tar(source, extracted)
            else:
                raise ExtractionError("Unsupported archive format")
        elif kind in {EvidenceKind.RAW_IMAGE, EvidenceKind.EWF_IMAGE}:
            command = ["tsk_recover", "-e"]
            if kind == EvidenceKind.EWF_IMAGE:
                command.extend(["-i", "ewf"])
            command.extend([str(source), str(extracted)])
            _recover_image(command, extracted)
        else:
            raise ExtractionError(f"Unsupported evidence type: {kind.value}")
        files = _enforce_limits(extracted)
        if not files:
            raise ExtractionError("No usable files were extracted")
        return extracted, files
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        raise
