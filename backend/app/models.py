from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def uuid4_str() -> str:
    return str(uuid.uuid4())


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    REVIEWER = "reviewer"


class CaseStatus(str, enum.Enum):
    OPEN = "open"
    SEALED = "sealed"
    CLOSED = "closed"


class EvidenceStatus(str, enum.Enum):
    INGESTED = "ingested"
    VERIFIED = "verified"
    COMPROMISED = "compromised"
    ANALYZING = "analyzing"
    ANALYZED = "analyzed"


class EvidenceKind(str, enum.Enum):
    FILE = "file"
    RAW_IMAGE = "raw_image"
    EWF_IMAGE = "ewf_image"
    ARCHIVE = "archive"


class JobStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    AWAITING_REVIEW = "awaiting_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    FAILED = "failed"


class Verdict(str, enum.Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    INCONCLUSIVE = "inconclusive"


class ReviewDecision(str, enum.Enum):
    APPROVE = "approve"
    REJECT = "reject"
    NEEDS_MORE_ANALYSIS = "needs_more_analysis"


class GroundTruthLabel(str, enum.Enum):
    BENIGN = "benign"
    MALICIOUS = "malicious"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(160))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.ANALYST)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    reference: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text, default="")
    classification: Mapped[str] = mapped_column(String(80), default="Interne")
    status: Mapped[CaseStatus] = mapped_column(Enum(CaseStatus), default=CaseStatus.OPEN)
    created_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    created_by: Mapped[User] = relationship()
    evidence: Mapped[list[Evidence]] = relationship(back_populates="case", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="RESTRICT"), index=True)
    label: Mapped[str] = mapped_column(String(240))
    original_filename: Mapped[str] = mapped_column(String(512))
    kind: Mapped[EvidenceKind] = mapped_column(Enum(EvidenceKind))
    status: Mapped[EvidenceStatus] = mapped_column(Enum(EvidenceStatus), default=EvidenceStatus.INGESTED)
    storage_path: Mapped[str] = mapped_column(String(1024), unique=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    sha1: Mapped[str] = mapped_column(String(40))
    md5: Mapped[str] = mapped_column(String(32))
    acquisition_notes: Mapped[str] = mapped_column(Text, default="")
    source_identifier: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    case: Mapped[Case] = relationship(back_populates="evidence")
    created_by: Mapped[User] = relationship()
    jobs: Mapped[list[AnalysisJob]] = relationship(back_populates="evidence")
    artifacts: Mapped[list[Artifact]] = relationship(back_populates="evidence")


class Artifact(Base):
    __tablename__ = "artifacts"
    __table_args__ = (UniqueConstraint("evidence_id", "relative_path", name="uq_artifact_evidence_path"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"), index=True)
    relative_path: Mapped[str] = mapped_column(String(2048))
    storage_path: Mapped[str] = mapped_column(String(2048))
    size_bytes: Mapped[int] = mapped_column(Integer)
    mime_type: Mapped[str] = mapped_column(String(255), default="application/octet-stream")
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    sha1: Mapped[str] = mapped_column(String(40))
    md5: Mapped[str] = mapped_column(String(32))
    extracted_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    evidence: Mapped[Evidence] = relationship(back_populates="artifacts")
    findings: Mapped[list[Finding]] = relationship(back_populates="artifact")
    ground_truth: Mapped[GroundTruth | None] = relationship(
        back_populates="artifact", uselist=False, cascade="all, delete-orphan"
    )

    @property
    def ground_truth_label(self) -> GroundTruthLabel | None:
        return self.ground_truth.label if self.ground_truth else None


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id", ondelete="RESTRICT"), index=True)
    requested_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    status: Mapped[JobStatus] = mapped_column(Enum(JobStatus), default=JobStatus.QUEUED, index=True)
    pipeline_version: Mapped[str] = mapped_column(String(40), default="1.0.0")
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    verdict: Mapped[Verdict | None] = mapped_column(Enum(Verdict), nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    evidence: Mapped[Evidence] = relationship(back_populates="jobs")
    requested_by: Mapped[User] = relationship()
    findings: Mapped[list[Finding]] = relationship(back_populates="job", cascade="all, delete-orphan")
    review: Mapped[Review | None] = relationship(back_populates="job", uselist=False)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_job_severity", "job_id", "severity"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    job_id: Mapped[str] = mapped_column(ForeignKey("analysis_jobs.id", ondelete="CASCADE"), index=True)
    artifact_id: Mapped[str | None] = mapped_column(ForeignKey("artifacts.id"), nullable=True, index=True)
    agent: Mapped[str] = mapped_column(String(80))
    category: Mapped[str] = mapped_column(String(120))
    severity: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    job: Mapped[AnalysisJob] = relationship(back_populates="findings")
    artifact: Mapped[Artifact | None] = relationship(back_populates="findings")


class Review(Base):
    __tablename__ = "reviews"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    job_id: Mapped[str] = mapped_column(ForeignKey("analysis_jobs.id"), unique=True)
    reviewer_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    decision: Mapped[ReviewDecision] = mapped_column(Enum(ReviewDecision))
    comments: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    job: Mapped[AnalysisJob] = relationship(back_populates="review")
    reviewer: Mapped[User] = relationship()


class GroundTruth(Base):
    __tablename__ = "ground_truth"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id"), unique=True, index=True)
    label: Mapped[GroundTruthLabel] = mapped_column(Enum(GroundTruthLabel))
    validated_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    artifact: Mapped[Artifact] = relationship(back_populates="ground_truth")
    validated_by: Mapped[User] = relationship()


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    version: Mapped[str] = mapped_column(String(80), unique=True)
    algorithm: Mapped[str] = mapped_column(String(120))
    storage_path: Mapped[str] = mapped_column(String(1024))
    feature_names: Mapped[list] = mapped_column(JSON)
    metrics: Mapped[dict] = mapped_column(JSON)
    training_manifest_hash: Mapped[str] = mapped_column(String(64))
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    trained_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    trained_by: Mapped[User] = relationship()


class AuditEvent(Base):
    __tablename__ = "audit_events"

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(120), index=True)
    target_type: Mapped[str] = mapped_column(String(80))
    target_id: Mapped[str] = mapped_column(String(120), index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    previous_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)
