from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "sandbox_worker",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_time_limit=settings.celery_task_time_limit_seconds,
    worker_prefetch_multiplier=1,
)
