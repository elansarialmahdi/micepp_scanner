from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models import (
    CaseStatus,
    EvidenceKind,
    EvidenceStatus,
    GroundTruthLabel,
    JobStatus,
    ReviewDecision,
    UserRole,
    Verdict,
)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(ORMModel):
    id: str
    username: str
    full_name: str
    role: UserRole
    is_active: bool


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    full_name: str = Field(min_length=2, max_length=160)
    password: str = Field(min_length=14, max_length=200)
    role: UserRole = UserRole.ANALYST


class CaseCreate(BaseModel):
    reference: str = Field(min_length=2, max_length=80)
    title: str = Field(min_length=3, max_length=240)
    description: str = Field(default="", max_length=10_000)
    classification: str = Field(default="Interne", max_length=80)


class CaseOut(ORMModel):
    id: str
    reference: str
    title: str
    description: str
    classification: str
    status: CaseStatus
    created_by_id: str
    created_at: datetime
    updated_at: datetime


class EvidenceOut(ORMModel):
    id: str
    case_id: str
    label: str
    original_filename: str
    kind: EvidenceKind
    status: EvidenceStatus
    size_bytes: int
    sha256: str
    sha1: str
    md5: str
    acquisition_notes: str
    source_identifier: str | None
    created_by_id: str
    created_at: datetime
    verified_at: datetime | None


class FindingOut(ORMModel):
    id: str
    job_id: str
    artifact_id: str | None
    agent: str
    category: str
    severity: int
    title: str
    description: str
    confidence: float | None
    details: dict
    created_at: datetime


class ReviewCreate(BaseModel):
    decision: ReviewDecision
    comments: str = Field(min_length=3, max_length=10_000)


class ReviewOut(ORMModel):
    id: str
    job_id: str
    reviewer_id: str
    decision: ReviewDecision
    comments: str
    created_at: datetime


class JobOut(ORMModel):
    id: str
    evidence_id: str
    requested_by_id: str
    status: JobStatus
    pipeline_version: str
    risk_score: float | None
    verdict: Verdict | None
    summary: dict
    error_message: str | None
    requested_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class JobDetail(JobOut):
    findings: list[FindingOut] = []
    review: ReviewOut | None = None


class ArtifactOut(ORMModel):
    id: str
    evidence_id: str
    relative_path: str
    size_bytes: int
    mime_type: str
    sha256: str
    sha1: str
    md5: str
    extracted_metadata: dict
    ground_truth_label: GroundTruthLabel | None = None
    created_at: datetime


class GroundTruthCreate(BaseModel):
    label: GroundTruthLabel
    notes: str = Field(default="", max_length=5_000)


class ModelOut(ORMModel):
    id: str
    version: str
    algorithm: str
    feature_names: list
    metrics: dict
    training_manifest_hash: str
    is_active: bool
    trained_by_id: str
    created_at: datetime


class AuditVerification(BaseModel):
    valid: bool
    events_checked: int
    first_invalid_hash: str | None = None


class DashboardStats(BaseModel):
    open_cases: int
    evidence_count: int
    queued_jobs: int
    awaiting_review: int
    malicious_jobs: int
    sandbox_configured: bool
    model_active: bool
