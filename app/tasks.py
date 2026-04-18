from __future__ import annotations

from app.celery_app import celery_app
from app.db import SessionLocal
from app.models import AnalysisTask
from app.pipeline import run_analysis


@celery_app.task(name="app.tasks.analyze_url_task")
def analyze_url_task(task_id: str, url: str, depth: str, callback_url: str | None = None) -> dict:
    db = SessionLocal()
    try:
        row = db.get(AnalysisTask, task_id)
        if row:
            row.status = "running"
            db.commit()

        result = run_analysis(task_id=task_id, url=url, depth=depth, callback_url=callback_url)

        row = db.get(AnalysisTask, task_id)
        if row:
            row.status = "done"
            row.label = result["verdict"]["label"]
            row.confidence = float(result["verdict"]["confidence"])
            row.evidence = result["verdict"].get("evidence", [])
            row.brand_target = result["verdict"].get("brand_target")
            row.layers = result.get("layers", [])
            row.collected = result.get("collected", {})
            row.metadata_json = result.get("metadata", {})
            row.processing_time_ms = result.get("processing_time_ms")
            row.error = None
            db.commit()
        return result
    except Exception as exc:
        db.rollback()
        row = db.get(AnalysisTask, task_id)
        if row:
            row.status = "failed"
            row.error = str(exc)
            db.commit()
        raise
    finally:
        db.close()
