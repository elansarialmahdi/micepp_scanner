from __future__ import annotations

import traceback
from pathlib import Path

from sqlalchemy import select

from app.analyzers.cape import CapeUnavailable, analyze_in_cape
from app.analyzers.extractor import extract_evidence
from app.analyzers.ml import predict
from app.analyzers.static import analyze_static
from app.analyzers.types import AnalyzerFinding
from app.audit import append_event, commit_with_audit_anchor
from app.config import settings
from app.database import SessionLocal
from app.models import (
    AnalysisJob,
    Artifact,
    EvidenceStatus,
    Finding,
    JobStatus,
    ModelVersion,
    Verdict,
    utcnow,
)
from app.storage import hash_file


PIPELINE_VERSION = "1.0.0"
MAX_SANDBOX_SUBMISSIONS_PER_JOB = 20


def _add_finding(db, job_id: str, artifact_id: str | None, finding: AnalyzerFinding) -> None:
    db.add(
        Finding(
            job_id=job_id,
            artifact_id=artifact_id,
            agent=finding.agent,
            category=finding.category,
            severity=max(0, min(100, finding.severity)),
            title=finding.title,
            description=finding.description,
            confidence=finding.confidence,
            details=finding.details,
        )
    )


def run_analysis(job_id: str) -> None:
    db = SessionLocal()
    job = db.get(AnalysisJob, job_id)
    if not job:
        db.close()
        raise ValueError(f"Tâche inconnue: {job_id}")
    evidence = job.evidence
    try:
        job.status = JobStatus.RUNNING
        job.started_at = utcnow()
        job.pipeline_version = PIPELINE_VERSION
        evidence.status = EvidenceStatus.ANALYZING
        append_event(
            db,
            actor_id=job.requested_by_id,
            action="analysis.started",
            target_type="analysis_job",
            target_id=job.id,
            payload={"evidence_id": evidence.id, "pipeline_version": PIPELINE_VERSION},
        )
        commit_with_audit_anchor(db)

        source = Path(evidence.storage_path)
        size, sha256, sha1, md5 = hash_file(source)
        integrity_ok = (
            size == evidence.size_bytes
            and sha256 == evidence.sha256
            and sha1 == evidence.sha1
            and md5 == evidence.md5
        )
        if not integrity_ok:
            evidence.status = EvidenceStatus.COMPROMISED
            _add_finding(
                db,
                job.id,
                None,
                AnalyzerFinding(
                    "agent-integrity",
                    "integrity",
                    100,
                    "Échec du contrôle d'intégrité",
                    "L'empreinte de la preuve diffère de celle enregistrée à l'ingestion. L'analyse est bloquée.",
                    1.0,
                    {"expected_sha256": evidence.sha256, "observed_sha256": sha256},
                ),
            )
            job.status = JobStatus.FAILED
            job.progress = 100
            job.error_message = "Contrôle d'intégrité de la preuve échoué"
            job.finished_at = utcnow()
            append_event(
                db,
                actor_id=None,
                action="evidence.integrity_failed",
                target_type="evidence",
                target_id=str(evidence.id),
                payload={"expected_sha256": evidence.sha256, "observed_sha256": sha256},
            )
            append_event(
                db,
                actor_id=None,
                action="analysis.failed",
                target_type="analysis_job",
                target_id=str(job.id),
                payload={"error": job.error_message},
            )
            commit_with_audit_anchor(db)
            return
        evidence.status = EvidenceStatus.VERIFIED
        evidence.verified_at = utcnow()

        root, extracted_files = extract_evidence(source, evidence.kind, job.id)
        static_scores: list[float] = []
        ml_scores: list[float] = []
        cape_scores: list[float] = []
        sandbox_requested = 0
        sandbox_completed = 0
        sandbox_unavailable: list[str] = []
        active_model = db.scalar(select(ModelVersion).where(ModelVersion.is_active.is_(True)))

        for index, path in enumerate(extracted_files, start=1):
            file_size, file_sha256, file_sha1, file_md5 = hash_file(path)
            relative = path.name if evidence.kind.value == "file" else path.relative_to(root).as_posix()
            artifact = db.scalar(
                select(Artifact).where(
                    Artifact.evidence_id == evidence.id,
                    Artifact.relative_path == relative,
                )
            )
            if artifact is None:
                artifact = Artifact(
                    evidence_id=evidence.id,
                    relative_path=relative,
                    storage_path=str(path),
                    size_bytes=file_size,
                    sha256=file_sha256,
                    sha1=file_sha1,
                    md5=file_md5,
                )
                db.add(artifact)
                db.flush()

            static = analyze_static(path)
            static_scores.append(static.risk_score)
            artifact.mime_type = static.mime_type
            artifact.extracted_metadata = static.metadata
            for finding in static.findings:
                _add_finding(db, job.id, artifact.id, finding)

            ml_probability, ml_meta = predict(static.features, active_model.storage_path if active_model else None)
            artifact.extracted_metadata = {**artifact.extracted_metadata, "ml": ml_meta}
            if ml_probability is not None:
                ml_scores.append(ml_probability * 100)
                if ml_probability >= 0.5:
                    _add_finding(
                        db,
                        job.id,
                        artifact.id,
                        AnalyzerFinding(
                            "agent-ml",
                            "machine_learning",
                            round(ml_probability * 100),
                            "Classification IA malveillante",
                            "Le modèle supervisé entraîné sur des validations humaines classe cet artefact comme malveillant.",
                            ml_probability,
                            {"model": ml_meta.get("version"), "probability": ml_probability},
                        ),
                    )

            dynamic_candidate = (
                static.risk_score >= settings.sandbox_risk_threshold
                or bool(static.features["is_executable"])
                or bool(static.features["is_script"])
                or bool(static.features["has_macro"])
            )
            if dynamic_candidate and sandbox_requested < MAX_SANDBOX_SUBMISSIONS_PER_JOB:
                sandbox_requested += 1
                try:
                    cape = analyze_in_cape(path, custom=f"micepp_job={job.id};artifact={artifact.id}")
                    sandbox_completed += 1
                    cape_risk = min(100.0, cape.score * 10.0)
                    cape_scores.append(cape_risk)
                    updated = dict(artifact.extracted_metadata)
                    updated["cape"] = {
                        "task_id": cape.task_id,
                        "score": cape.score,
                        "signatures": cape.signatures,
                        "network_summary": {
                            key: len(value) if isinstance(value, list) else value
                            for key, value in cape.network.items()
                            if key in {"hosts", "domains", "dns", "http", "tcp", "udp"}
                        },
                        "process_count": len((cape.behavior.get("processes") or [])),
                    }
                    updated["features"]["sandbox_signature_count"] = float(len(cape.signatures))
                    updated["features"]["sandbox_score"] = cape_risk
                    artifact.extracted_metadata = updated
                    for signature in cape.signatures:
                        _add_finding(
                            db,
                            job.id,
                            artifact.id,
                            AnalyzerFinding(
                                "agent-sandbox",
                                "behavior",
                                min(100, max(20, int(signature.get("severity") or cape_risk or 50) * (10 if int(signature.get("severity") or 0) <= 10 else 1))),
                                f"CAPE: {signature.get('name') or 'comportement détecté'}",
                                signature.get("description") or "Signature comportementale observée dans la sandbox.",
                                float(signature.get("confidence") or 0) / 100 if signature.get("confidence") else None,
                                {"cape_task_id": cape.task_id, **signature},
                            ),
                        )
                except CapeUnavailable as exc:
                    sandbox_unavailable.append(str(exc))

            if index % 25 == 0:
                commit_with_audit_anchor(db)

        if sandbox_unavailable:
            _add_finding(
                db,
                job.id,
                None,
                AnalyzerFinding(
                    "agent-sandbox",
                    "availability",
                    15,
                    "Analyse dynamique incomplète",
                    "CAPE n'a pas pu analyser un ou plusieurs artefacts. Aucun résultat de substitution n'a été généré.",
                    None,
                    {"errors": sorted(set(sandbox_unavailable))[:20], "requested": sandbox_requested, "completed": sandbox_completed},
                ),
            )

        risk_components = {
            "static": round(max(static_scores, default=0.0), 2),
            "machine_learning": round(max(ml_scores, default=0.0), 2) if ml_scores else None,
            "sandbox": round(max(cape_scores, default=0.0), 2) if cape_scores else None,
        }
        available_components = [
            (name, score) for name, score in risk_components.items() if score is not None
        ]
        dominant_risk_signal, maximum_risk = max(
            available_components, key=lambda item: item[1], default=("static", 0.0)
        )
        if maximum_risk >= 80:
            verdict = Verdict.MALICIOUS
        elif maximum_risk >= 45:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.BENIGN
        if sandbox_requested and sandbox_completed == 0 and 45 <= maximum_risk < 80:
            verdict = Verdict.INCONCLUSIVE

        job.risk_score = round(maximum_risk, 2)
        job.verdict = verdict
        job.summary = {
            "artifacts_analyzed": len(extracted_files),
            "static_max_score": risk_components["static"],
            "ml_model": active_model.version if active_model else None,
            "ml_max_probability": round(max(ml_scores, default=0.0) / 100, 4) if ml_scores else None,
            "sandbox_configured": bool(settings.cape_base_url),
            "sandbox_requested": sandbox_requested,
            "sandbox_completed": sandbox_completed,
            "sandbox_max_score": risk_components["sandbox"],
            "analysis_complete": not sandbox_unavailable,
            "risk_components": risk_components,
            "dominant_risk_signal": dominant_risk_signal,
            "risk_method": "maximum_available_signal",
        }
        job.status = JobStatus.AWAITING_REVIEW
        job.finished_at = utcnow()
        evidence.status = EvidenceStatus.ANALYZED
        append_event(
            db,
            actor_id=job.requested_by_id,
            action="analysis.completed",
            target_type="analysis_job",
            target_id=job.id,
            payload={"verdict": verdict.value, "risk_score": job.risk_score, **job.summary},
        )
        commit_with_audit_anchor(db)
    except Exception as exc:
        db.rollback()
        job = db.get(AnalysisJob, job_id)
        if job:
            job.status = JobStatus.FAILED
            job.error_message = f"{type(exc).__name__}: {exc}"
            job.finished_at = utcnow()
            if job.evidence.status != EvidenceStatus.COMPROMISED:
                job.evidence.status = EvidenceStatus.INGESTED
            append_event(
                db,
                actor_id=job.requested_by_id,
                action="analysis.failed",
                target_type="analysis_job",
                target_id=job.id,
                payload={"error": job.error_message, "trace": traceback.format_exc()[-4000:]},
            )
            commit_with_audit_anchor(db)
        raise
    finally:
        db.close()
