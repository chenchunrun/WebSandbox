from __future__ import annotations

from app.celery_app import celery_app
from app.core.observability import log_event
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
            current_meta = row.metadata_json or {}
            current_meta["analysis_state"] = {
                "current": "running",
                "history": [{"stage": "queued", "status": "ok"}, {"stage": "running", "status": "ok"}],
            }
            row.metadata_json = current_meta
            db.commit()
        log_event("task_running", task_id=task_id, url=url, depth=depth)

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
            if row.metadata_json is not None:
                row.metadata_json["analysis_state"] = result.get("analysis_state", {})
            row.processing_time_ms = result.get("processing_time_ms")
            row.error = None
            db.commit()
        log_event("task_done", task_id=task_id, url=url, depth=depth, processing_time_ms=result.get("processing_time_ms"))
        return result
    except Exception as exc:
        db.rollback()
        row = db.get(AnalysisTask, task_id)
        if row:
            row.status = "failed"
            row.error = str(exc)
            current_meta = row.metadata_json or {}
            current_meta["analysis_state"] = {
                "current": "failed",
                "history": [{"stage": "failed", "status": "error", "extra": {"error": str(exc)}}],
            }
            row.metadata_json = current_meta
            db.commit()
        log_event("task_failed", task_id=task_id, url=url, depth=depth, error=str(exc))
        raise
    finally:
        db.close()
