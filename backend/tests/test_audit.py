from app.audit import append_event, commit_with_audit_anchor, verify_chain
from app.models import AuditEvent


def test_audit_chain_detects_tampering(db):
    _valid, initial_count, _invalid = verify_chain(db)
    append_event(db, actor_id=None, action="case.created", target_type="case", target_id="A")
    append_event(db, actor_id=None, action="evidence.ingested", target_type="evidence", target_id="B")
    commit_with_audit_anchor(db)
    assert verify_chain(db) == (True, initial_count + 2, None)

    second = db.get(AuditEvent, initial_count + 2)
    second.payload = {"tampered": True}
    db.commit()
    valid, count, invalid_hash = verify_chain(db)
    assert valid is False
    assert count == initial_count + 2
    assert invalid_hash == second.event_hash


def test_audit_anchor_detects_tail_deletion(db):
    event = append_event(db, actor_id=None, action="case.created", target_type="case", target_id="A")
    commit_with_audit_anchor(db)

    db.delete(event)
    db.commit()

    valid, count, invalid_hash = verify_chain(db)
    assert valid is False
    assert count == 1
    assert invalid_hash == event.event_hash
