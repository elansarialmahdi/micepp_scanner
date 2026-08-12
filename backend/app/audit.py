from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import timezone
from pathlib import Path

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AuditEvent, utcnow


GENESIS_HASH = "0" * 64


class AuditAnchorError(RuntimeError):
    pass


def _anchor_path() -> Path:
    return settings.report_root / ".audit-anchor.json"


def _write_anchor(event: AuditEvent) -> None:
    """Atomically persist the latest committed audit event outside PostgreSQL."""
    path = _anchor_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    value = {"sequence": event.sequence, "event_hash": event.event_hash}
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_anchor() -> tuple[int, str] | None:
    try:
        value = json.loads(_anchor_path().read_text(encoding="utf-8"))
        sequence = value["sequence"]
        event_hash = value["event_hash"]
        if not isinstance(sequence, int) or not isinstance(event_hash, str):
            raise ValueError("invalid audit anchor")
        return sequence, event_hash
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return -1, ""


def _canonical(event: AuditEvent) -> bytes:
    timestamp = event.created_at
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    created = timestamp.astimezone(timezone.utc).isoformat()
    value = {
        "actor_id": event.actor_id,
        "action": event.action,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "payload": event.payload,
        "created_at": created,
        "previous_hash": event.previous_hash,
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(event: AuditEvent) -> str:
    return hmac.new(settings.audit_hmac_key.encode(), _canonical(event), hashlib.sha256).hexdigest()


def append_event(
    db: Session,
    *,
    actor_id: str | None,
    action: str,
    target_type: str,
    target_id: str,
    payload: dict | None = None,
) -> AuditEvent:
    # Prevent concurrent PostgreSQL writers from forking the audit chain after
    # observing the same previous event. SQLite remains portable for tests.
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(1296646992)"))

    previous = db.scalar(
        select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(1).with_for_update()
    )
    event = AuditEvent(
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        payload=payload or {},
        created_at=utcnow(),
        previous_hash=previous.event_hash if previous else GENESIS_HASH,
        event_hash="",
    )
    event.event_hash = _digest(event)
    db.add(event)
    db.flush()
    return event


def commit_with_audit_anchor(db: Session) -> None:
    """Commit a transaction, then checkpoint its latest audit hash externally."""
    db.commit()
    latest = db.scalar(select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(1))
    if latest:
        try:
            _write_anchor(latest)
        except OSError as exc:
            raise AuditAnchorError("Could not persist the external audit checkpoint") from exc


def verify_chain(db: Session) -> tuple[bool, int, str | None]:
    previous = GENESIS_HASH
    count = 0
    last_sequence: int | None = None
    for event in db.scalars(select(AuditEvent).order_by(AuditEvent.sequence.asc())):
        count += 1
        if event.previous_hash != previous or not hmac.compare_digest(event.event_hash, _digest(event)):
            return False, count, event.event_hash
        previous = event.event_hash
        last_sequence = event.sequence
    anchor = _read_anchor()
    if anchor is not None and anchor != (last_sequence, previous):
        return False, count, anchor[1] or None
    return True, count, None
