from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import verify_chain
from app.config import settings
from app.models import AnalysisJob, AuditEvent


def generate_report(db: Session, job: AnalysisJob) -> Path:
    output = settings.report_root / f"rapport-{job.id}.pdf"
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CenterTitle", parent=styles["Title"], alignment=TA_CENTER, textColor=colors.HexColor("#102A43")))
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=10))
    document = SimpleDocTemplate(
        str(output), pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm, topMargin=18 * mm, bottomMargin=18 * mm
    )
    story = [
        Paragraph("MICEPP Scanner", styles["CenterTitle"]),
        Paragraph("Rapport d'analyse forensique sous supervision humaine", styles["Heading2"]),
        Spacer(1, 6 * mm),
    ]
    evidence = job.evidence
    case = evidence.case
    review = job.review
    summary_rows = [
        ["Dossier", f"{case.reference} - {case.title}"],
        ["Preuve", evidence.label],
        ["Fichier d'origine", evidence.original_filename],
        ["SHA-256", evidence.sha256],
        ["SHA-1", evidence.sha1],
        ["MD5 (compatibilité)", evidence.md5],
        ["Taille", f"{evidence.size_bytes:,} octets"],
        ["Pipeline", job.pipeline_version],
        ["Verdict automatisé", job.verdict.value if job.verdict else "indisponible"],
        ["Score de risque", str(job.risk_score) if job.risk_score is not None else "indisponible"],
        ["Validation humaine", review.decision.value if review else "EN ATTENTE"],
    ]
    table = Table(summary_rows, colWidths=[42 * mm, 128 * mm], repeatRows=0)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8EEF4")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#102A43")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#9FB3C8")),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.extend([table, Spacer(1, 6 * mm), Paragraph("Synthèse", styles["Heading2"]), Paragraph(str(job.summary), styles["BodyText"])])
    story.extend([Spacer(1, 4 * mm), Paragraph("Constats techniques", styles["Heading2"])])
    for finding in sorted(job.findings, key=lambda item: item.severity, reverse=True):
        story.append(Paragraph(f"[{finding.severity}/100] {finding.title}", styles["Heading3"]))
        story.append(Paragraph(f"Agent : {finding.agent} - Catégorie : {finding.category}", styles["Small"]))
        story.append(Paragraph(finding.description or "Aucune description.", styles["BodyText"]))
        story.append(Spacer(1, 2 * mm))
    story.append(PageBreak())
    story.append(Paragraph("Chaîne de conservation et audit", styles["Heading2"]))
    chain_valid, chain_count, invalid_hash = verify_chain(db)
    story.append(
        Paragraph(
            f"Chaîne HMAC : {'VALIDE' if chain_valid else 'INVALIDE'} - {chain_count} événement(s) vérifié(s)"
            + (f" - premier hash invalide: {invalid_hash}" if invalid_hash else ""),
            styles["BodyText"],
        )
    )
    events = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.target_id.in_([case.id, evidence.id, job.id]))
        .order_by(AuditEvent.sequence.asc())
    )
    event_rows = [["N°", "Horodatage UTC", "Action", "Cible", "Empreinte"]]
    for event in events:
        event_rows.append([event.sequence, event.created_at.isoformat(), event.action, event.target_type, event.event_hash[:16] + "…"])
    event_table = Table(event_rows, colWidths=[12 * mm, 48 * mm, 40 * mm, 30 * mm, 40 * mm], repeatRows=1)
    event_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#102A43")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#BCCCDC")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.extend([Spacer(1, 4 * mm), event_table, Spacer(1, 6 * mm)])
    story.append(Paragraph("Décision de l'expert", styles["Heading2"]))
    if review:
        story.append(Paragraph(f"Décision : {review.decision.value}", styles["BodyText"]))
        story.append(Paragraph(f"Commentaires : {review.comments}", styles["BodyText"]))
        story.append(Paragraph(f"Validateur : {review.reviewer.full_name} - {review.created_at.isoformat()}", styles["BodyText"]))
    else:
        story.append(Paragraph("Ce rapport n'a pas encore été validé par un expert judiciaire.", styles["BodyText"]))
    document.build(story)
    return output

