from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException, UploadFile

from app.config import settings


SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class StoredFile:
    path: Path
    size: int
    sha256: str
    sha1: str
    md5: str


def sanitize_filename(name: str) -> str:
    candidate = SAFE_NAME.sub("_", Path(name).name).strip("._")
    return candidate[:180] or "evidence.bin"


def assert_within(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    root_resolved = root.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise ValueError("Chemin hors de la zone autorisée")
    return resolved


async def persist_upload(upload: UploadFile, evidence_id: str) -> StoredFile:
    destination_dir = assert_within(settings.evidence_root / evidence_id, settings.evidence_root)
    destination_dir.mkdir(parents=True, exist_ok=False)
    final_path = destination_dir / sanitize_filename(upload.filename or "evidence.bin")
    partial_path = destination_dir / ".uploading"
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5(usedforsecurity=False)
    size = 0
    try:
        with partial_path.open("xb") as output:
            while chunk := await upload.read(1024 * 1024):
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise HTTPException(status_code=413, detail="La preuve dépasse la taille autorisée")
                output.write(chunk)
                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)
            output.flush()
            os.fsync(output.fileno())
        partial_path.replace(final_path)
        try:
            final_path.chmod(0o440)
        except OSError:
            pass
    except Exception:
        partial_path.unlink(missing_ok=True)
        try:
            destination_dir.rmdir()
        except OSError:
            pass
        raise
    finally:
        await upload.close()
    return StoredFile(final_path, size, sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest())


def hash_file(path: Path) -> tuple[int, str, str, str]:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5(usedforsecurity=False)
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return size, sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest()

