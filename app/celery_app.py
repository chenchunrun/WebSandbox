from celery import Celery
from kombu import Queue

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
    task_default_queue=settings.queue_standard,
    task_queues=(
        Queue(settings.queue_quick),
        Queue(settings.queue_standard),
        Queue(settings.queue_deep),
        Queue(settings.queue_retry),
    ),
)
