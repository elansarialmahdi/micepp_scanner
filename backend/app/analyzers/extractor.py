from __future__ import annotations

import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

from app.config import settings
from app.models import EvidenceKind
from app.storage import assert_within


class ExtractionError(RuntimeError):
    pass


def _safe_target(root: Path, member_name: str) -> Path:
    normalized = member_name.replace("\\", "/").lstrip("/")
    target = assert_within(root / normalized, root)
    return target


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
                raise ExtractionError(f"Limite de {settings.max_extracted_files} fichiers extraits dépassée")
            if total > settings.max_extracted_bytes:
                raise ExtractionError(f"Limite de {settings.max_extracted_bytes} octets extraits dépassée")
    return files


def _extract_zip(source: Path, destination: Path) -> None:
    with zipfile.ZipFile(source) as archive:
        declared_total = sum(item.file_size for item in archive.infolist())
        if len(archive.infolist()) > settings.max_extracted_files or declared_total > settings.max_extracted_bytes:
            raise ExtractionError("L'archive dépasse les limites d'extraction")
        for item in archive.infolist():
            if item.is_dir():
                continue
            target = _safe_target(destination, item.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(item) as src, target.open("xb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)


def _extract_tar(source: Path, destination: Path) -> None:
    with tarfile.open(source, mode="r:*") as archive:
        members = [m for m in archive.getmembers() if m.isfile()]
        if len(members) > settings.max_extracted_files:
            raise ExtractionError("L'archive dépasse le nombre de fichiers autorisé")
        for member in members:
            target = _safe_target(destination, member.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            with extracted, target.open("xb") as dst:
                shutil.copyfileobj(extracted, dst, length=1024 * 1024)


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
                raise ExtractionError("Format d'archive non pris en charge")
        elif kind in {EvidenceKind.RAW_IMAGE, EvidenceKind.EWF_IMAGE}:
            command = ["tsk_recover", "-e"]
            if kind == EvidenceKind.EWF_IMAGE:
                command.extend(["-i", "ewf"])
            command.extend([str(source), str(extracted)])
            process = subprocess.run(command, capture_output=True, text=True, timeout=6 * 60 * 60, check=False)
            if process.returncode != 0:
                raise ExtractionError(
                    f"tsk_recover a échoué ({process.returncode}): {process.stderr[-2000:]}"
                )
        else:
            raise ExtractionError(f"Type de preuve non pris en charge: {kind.value}")
        files = _enforce_limits(extracted)
        if not files:
            raise ExtractionError("Aucun fichier exploitable n'a été extrait")
        return extracted, files
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        raise
