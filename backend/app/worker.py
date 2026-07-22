from celery import Celery

from app.config import settings
from app.pipeline import run_analysis


celery_app = Celery("micepp", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_reject_on_worker_lost=True,
    broker_transport_options={"visibility_timeout": 21600},
)


@celery_app.task(name="micepp.analyze_evidence", bind=True, acks_late=True)
def analyze_evidence_task(self, job_id: str) -> dict:
    run_analysis(job_id)
    return {"job_id": job_id, "status": "completed"}

