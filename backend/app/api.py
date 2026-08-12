from __future__ import annotations

import uuid
import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.analyzers.ml import train as train_model
from app.audit import AuditAnchorError, append_event, commit_with_audit_anchor, verify_chain
from app.config import settings
from app.database import get_db
from app.models import (
    AnalysisJob,
    Artifact,
    AuditEvent,
    Case,
    CaseStatus,
    Evidence,
    EvidenceKind,
    EvidenceStatus,
    GroundTruth,
    GroundTruthLabel,
    JobStatus,
    ModelVersion,
    Review,
    ReviewDecision,
    User,
    UserRole,
    Verdict,
    utcnow,
)
from app.reports import generate_report
from app.schemas import (
    ArtifactOut,
    AuditVerification,
    CaseCreate,
    CaseOut,
    DashboardStats,
    EvidenceOut,
    GroundTruthCreate,
    JobDetail,
    JobOut,
    ModelOut,
    ReviewCreate,
    Token,
    UserCreate,
    UserOut,
)
from app.security import (
    authenticate,
    create_access_token,
    get_current_user,
    hash_password,
    require_roles,
)
from app.storage import hash_file, persist_upload, remove_readonly_tree
from app.worker import analyze_evidence_task


router = APIRouter()


@router.post("/auth/token", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)) -> Token:
    user = authenticate(db, form.username, form.password)
    if not user:
        raise HTTPException(status_code=401, detail="Identifiants invalides")
    append_event(db, actor_id=user.id, action="auth.login", target_type="user", target_id=user.id)
    commit_with_audit_anchor(db)
    return Token(access_token=create_access_token(user))


@router.get("/auth/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(
    _: User = Depends(require_roles(UserRole.ADMIN)), db: Session = Depends(get_db)
) -> list[User]:
    return list(db.scalars(select(User).order_by(User.username)))


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    payload: UserCreate,
    admin: User = Depends(require_roles(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> User:
    user = User(
        username=payload.username.lower(),
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Ce nom d'utilisateur existe déjà") from exc
    append_event(
        db,
        actor_id=admin.id,
        action="user.created",
        target_type="user",
        target_id=user.id,
        payload={"username": user.username, "role": user.role.value},
    )
    commit_with_audit_anchor(db)
    return user


@router.get("/dashboard", response_model=DashboardStats)
def dashboard(_: User = Depends(get_current_user), db: Session = Depends(get_db)) -> DashboardStats:
    return DashboardStats(
        open_cases=db.scalar(select(func.count()).select_from(Case).where(Case.status == CaseStatus.OPEN)) or 0,
        evidence_count=db.scalar(select(func.count()).select_from(Evidence)) or 0,
        queued_jobs=db.scalar(select(func.count()).select_from(AnalysisJob).where(AnalysisJob.status == JobStatus.QUEUED)) or 0,
        awaiting_review=db.scalar(
            select(func.count()).select_from(AnalysisJob).where(AnalysisJob.status == JobStatus.AWAITING_REVIEW)
        )
        or 0,
        malicious_jobs=db.scalar(
            select(func.count()).select_from(AnalysisJob).where(AnalysisJob.verdict == Verdict.MALICIOUS)
        )
        or 0,
        sandbox_configured=bool(settings.cape_base_url),
        model_active=bool(db.scalar(select(ModelVersion.id).where(ModelVersion.is_active.is_(True)))),
    )


@router.get("/cases", response_model=list[CaseOut])
def list_cases(
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
) -> list[Case]:
    return list(db.scalars(select(Case).order_by(Case.created_at.desc()).limit(limit)))


@router.post("/cases", response_model=CaseOut, status_code=201)
def create_case(payload: CaseCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Case:
    case = Case(**payload.model_dump(), created_by_id=user.id)
    db.add(case)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Cette référence de dossier existe déjà") from exc
    append_event(
        db,
        actor_id=user.id,
        action="case.created",
        target_type="case",
        target_id=case.id,
        payload={"reference": case.reference, "classification": case.classification},
    )
    commit_with_audit_anchor(db)
    return case


@router.get("/cases/{case_id}", response_model=CaseOut)
def get_case(case_id: str, _: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Case:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Dossier introuvable")
    return case


@router.post("/cases/{case_id}/seal", response_model=CaseOut)
def seal_case(
    case_id: str,
    user: User = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER)),
    db: Session = Depends(get_db),
) -> Case:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Dossier introuvable")
    case.status = CaseStatus.SEALED
    append_event(db, actor_id=user.id, action="case.sealed", target_type="case", target_id=case.id)
    commit_with_audit_anchor(db)
    return case


@router.get("/cases/{case_id}/evidence", response_model=list[EvidenceOut])
def list_evidence(case_id: str, _: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[Evidence]:
    return list(db.scalars(select(Evidence).where(Evidence.case_id == case_id).order_by(Evidence.created_at.desc())))


@router.post("/evidence", response_model=EvidenceOut, status_code=201)
async def upload_evidence(
    file: UploadFile = File(...),
    case_id: str = Form(...),
    label: str = Form(..., min_length=2, max_length=240),
    kind: EvidenceKind = Form(EvidenceKind.FILE),
    acquisition_notes: str = Form(""),
    source_identifier: str | None = Form(None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Evidence:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Dossier introuvable")
    if case.status != CaseStatus.OPEN:
        raise HTTPException(status_code=409, detail="Le dossier est scellé ou clôturé")
    evidence_id = str(uuid.uuid4())
    stored = await persist_upload(file, evidence_id)
    try:
        evidence = Evidence(
            id=evidence_id,
            case_id=case_id,
            label=label,
            original_filename=Path(file.filename or "evidence.bin").name,
            kind=kind,
            storage_path=str(stored.path),
            size_bytes=stored.size,
            sha256=stored.sha256,
            sha1=stored.sha1,
            md5=stored.md5,
            acquisition_notes=acquisition_notes,
            source_identifier=source_identifier,
            created_by_id=user.id,
        )
        db.add(evidence)
        append_event(
            db,
            actor_id=user.id,
            action="evidence.ingested",
            target_type="evidence",
            target_id=evidence.id,
            payload={
                "case_id": case_id,
                "filename": evidence.original_filename,
                "kind": kind.value,
                "size_bytes": stored.size,
                "sha256": stored.sha256,
                "source_identifier": source_identifier,
            },
        )
        commit_with_audit_anchor(db)
    except Exception:
        db.rollback()
        remove_readonly_tree(stored.path.parent)
        raise
    return evidence


@router.get("/evidence/{evidence_id}", response_model=EvidenceOut)
def get_evidence(evidence_id: str, _: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Evidence:
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Preuve introuvable")
    return evidence


@router.post("/evidence/{evidence_id}/verify", response_model=EvidenceOut)
def verify_evidence(
    evidence_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Evidence:
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Preuve introuvable")
    observed = hash_file(Path(evidence.storage_path))
    valid = observed == (evidence.size_bytes, evidence.sha256, evidence.sha1, evidence.md5)
    evidence.status = EvidenceStatus.VERIFIED if valid else EvidenceStatus.COMPROMISED
    evidence.verified_at = utcnow()
    append_event(
        db,
        actor_id=user.id,
        action="evidence.integrity_verified" if valid else "evidence.integrity_failed",
        target_type="evidence",
        target_id=evidence.id,
        payload={"valid": valid, "expected_sha256": evidence.sha256, "observed_sha256": observed[1]},
    )
    commit_with_audit_anchor(db)
    if not valid:
        raise HTTPException(status_code=409, detail="L'intégrité de la preuve est compromise")
    return evidence


@router.post("/evidence/{evidence_id}/analyze", response_model=JobOut, status_code=202)
def queue_analysis(
    evidence_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> AnalysisJob:
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Preuve introuvable")
    if evidence.status == EvidenceStatus.COMPROMISED:
        raise HTTPException(status_code=409, detail="Analyse interdite: intégrité compromise")
    active = db.scalar(
        select(AnalysisJob).where(
            AnalysisJob.evidence_id == evidence_id,
            AnalysisJob.status.in_([JobStatus.QUEUED, JobStatus.RUNNING]),
        )
    )
    if active:
        raise HTTPException(status_code=409, detail="Une analyse est déjà en cours")
    job = AnalysisJob(evidence_id=evidence_id, requested_by_id=user.id)
    db.add(job)
    db.flush()
    append_event(
        db,
        actor_id=user.id,
        action="analysis.queued",
        target_type="analysis_job",
        target_id=job.id,
        payload={"evidence_id": evidence_id},
    )
    commit_with_audit_anchor(db)
    try:
        analyze_evidence_task.delay(job.id)
    except Exception as exc:
        job.status = JobStatus.FAILED
        job.error_message = f"File de traitement indisponible: {exc}"
        append_event(
            db,
            actor_id=user.id,
            action="analysis.queue_failed",
            target_type="analysis_job",
            target_id=job.id,
            payload={"error": str(exc)},
        )
        commit_with_audit_anchor(db)
        raise HTTPException(status_code=503, detail="Le worker d'analyse est indisponible") from exc
    return job


@router.get("/jobs", response_model=list[JobOut])
def list_jobs(
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    job_status: JobStatus | None = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=500),
) -> list[AnalysisJob]:
    query = select(AnalysisJob).order_by(AnalysisJob.requested_at.desc()).limit(limit)
    if job_status:
        query = query.where(AnalysisJob.status == job_status)
    return list(db.scalars(query))


@router.get("/jobs/{job_id}", response_model=JobDetail)
def get_job(job_id: str, _: User = Depends(get_current_user), db: Session = Depends(get_db)) -> AnalysisJob:
    job = db.scalar(
        select(AnalysisJob)
        .where(AnalysisJob.id == job_id)
        .options(selectinload(AnalysisJob.findings), selectinload(AnalysisJob.review))
    )
    if not job:
        raise HTTPException(status_code=404, detail="Analyse introuvable")
    return job


@router.get("/evidence/{evidence_id}/artifacts", response_model=list[ArtifactOut])
def list_artifacts(
    evidence_id: str,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(500, ge=1, le=5000),
) -> list[Artifact]:
    return list(
        db.scalars(
            select(Artifact)
            .where(Artifact.evidence_id == evidence_id)
            .options(selectinload(Artifact.ground_truth))
            .order_by(Artifact.relative_path)
            .limit(limit)
        )
    )


@router.post("/jobs/{job_id}/review", response_model=JobDetail)
def review_job(
    job_id: str,
    payload: ReviewCreate,
    reviewer: User = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER)),
    db: Session = Depends(get_db),
) -> AnalysisJob:
    job = db.scalar(
        select(AnalysisJob)
        .where(AnalysisJob.id == job_id)
        .options(selectinload(AnalysisJob.findings), selectinload(AnalysisJob.review))
    )
    if not job:
        raise HTTPException(status_code=404, detail="Analyse introuvable")
    if job.status not in {JobStatus.AWAITING_REVIEW, JobStatus.APPROVED, JobStatus.REJECTED}:
        raise HTTPException(status_code=409, detail="Cette analyse n'est pas révisable dans son état actuel")
    if job.review:
        job.review.decision = payload.decision
        job.review.comments = payload.comments
        job.review.reviewer_id = reviewer.id
        job.review.created_at = utcnow()
    else:
        job.review = Review(
            reviewer_id=reviewer.id, decision=payload.decision, comments=payload.comments
        )
    if payload.decision == ReviewDecision.APPROVE:
        job.status = JobStatus.APPROVED
    elif payload.decision == ReviewDecision.REJECT:
        job.status = JobStatus.REJECTED
    else:
        job.status = JobStatus.AWAITING_REVIEW
    append_event(
        db,
        actor_id=reviewer.id,
        action="analysis.reviewed",
        target_type="analysis_job",
        target_id=job.id,
        payload={"decision": payload.decision.value, "comments": payload.comments},
    )
    commit_with_audit_anchor(db)
    return job


@router.get("/jobs/{job_id}/report")
def download_report(job_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    job = db.scalar(
        select(AnalysisJob)
        .where(AnalysisJob.id == job_id)
        .options(
            selectinload(AnalysisJob.findings),
            selectinload(AnalysisJob.review).selectinload(Review.reviewer),
            selectinload(AnalysisJob.evidence).selectinload(Evidence.case),
        )
    )
    if not job or job.status in {JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.FAILED}:
        raise HTTPException(status_code=409, detail="Rapport indisponible")
    path = generate_report(db, job)
    append_event(
        db,
        actor_id=user.id,
        action="report.generated",
        target_type="analysis_job",
        target_id=job.id,
        payload={"filename": path.name},
    )
    commit_with_audit_anchor(db)
    return FileResponse(path, media_type="application/pdf", filename=path.name)


@router.put("/artifacts/{artifact_id}/ground-truth", status_code=204)
def set_ground_truth(
    artifact_id: str,
    payload: GroundTruthCreate,
    reviewer: User = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER)),
    db: Session = Depends(get_db),
) -> None:
    artifact = db.get(Artifact, artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artefact introuvable")
    if not (artifact.extracted_metadata or {}).get("features"):
        raise HTTPException(status_code=409, detail="Les caractéristiques de cet artefact sont absentes")
    truth = db.scalar(select(GroundTruth).where(GroundTruth.artifact_id == artifact_id))
    if truth:
        truth.label = payload.label
        truth.notes = payload.notes
        truth.validated_by_id = reviewer.id
        truth.created_at = utcnow()
    else:
        db.add(
            GroundTruth(
                artifact_id=artifact_id,
                label=payload.label,
                notes=payload.notes,
                validated_by_id=reviewer.id,
            )
        )
    append_event(
        db,
        actor_id=reviewer.id,
        action="artifact.labeled",
        target_type="artifact",
        target_id=artifact_id,
        payload={"label": payload.label.value, "notes": payload.notes},
    )
    commit_with_audit_anchor(db)


@router.get("/models", response_model=list[ModelOut])
def list_models(_: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[ModelVersion]:
    return list(db.scalars(select(ModelVersion).order_by(ModelVersion.created_at.desc())))


@router.post("/models/train", response_model=ModelOut, status_code=201)
def train_supervised_model(
    trainer: User = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER)),
    db: Session = Depends(get_db),
) -> ModelVersion:
    records = db.execute(
        select(GroundTruth, Artifact).join(Artifact, Artifact.id == GroundTruth.artifact_id)
    ).all()
    entries = []
    for truth, artifact in records:
        features = (artifact.extracted_metadata or {}).get("features")
        if features:
            label = 1 if truth.label == GroundTruthLabel.MALICIOUS else 0
            entries.append((artifact.id, features, label))
    try:
        result = train_model(entries, trainer.id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    for existing in db.scalars(select(ModelVersion).where(ModelVersion.is_active.is_(True))):
        existing.is_active = False
    model = ModelVersion(
        version=result["version"],
        algorithm="RandomForestClassifier",
        storage_path=result["path"],
        feature_names=result["features"],
        metrics=result["metrics"],
        training_manifest_hash=result["manifest_hash"],
        is_active=True,
        trained_by_id=trainer.id,
    )
    db.add(model)
    db.flush()
    append_event(
        db,
        actor_id=trainer.id,
        action="model.trained",
        target_type="model",
        target_id=model.id,
        payload={"version": model.version, "metrics": model.metrics, "manifest_hash": model.training_manifest_hash},
    )
    commit_with_audit_anchor(db)
    return model


@router.get("/audit", response_model=list[dict])
def list_audit_events(
    _: User = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER)),
    db: Session = Depends(get_db),
    limit: int = Query(200, ge=1, le=2000),
) -> list[dict]:
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(limit))
    return [
        {
            "sequence": item.sequence,
            "actor_id": item.actor_id,
            "action": item.action,
            "target_type": item.target_type,
            "target_id": item.target_id,
            "payload": item.payload,
            "created_at": item.created_at,
            "previous_hash": item.previous_hash,
            "event_hash": item.event_hash,
        }
        for item in events
    ]


@router.get("/audit/verify", response_model=AuditVerification)
def verify_audit(
    _: User = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER)), db: Session = Depends(get_db)
) -> AuditVerification:
    valid, count, invalid = verify_chain(db)
    return AuditVerification(valid=valid, events_checked=count, first_invalid_hash=invalid)
