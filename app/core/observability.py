from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.core.metrics import metrics_registry


logger = logging.getLogger("websandbox")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


def log_event(event: str, **fields: Any) -> None:
    metrics_registry.incr("events_total", event=event)

    if event == "task_queued":
        metrics_registry.incr(
            "analyze_requests_total",
            mode=fields.get("mode", "unknown"),
            depth=fields.get("depth", "unknown"),
        )
    elif event == "task_dispatched":
        metrics_registry.incr(
            "tasks_dispatched_total",
            mode=fields.get("mode", "unknown"),
            depth=fields.get("depth", "unknown"),
            queue=fields.get("queue", "unknown"),
        )
    elif event == "task_done":
        metrics_registry.incr(
            "tasks_completed_total",
            depth=fields.get("depth", "unknown"),
            queue=fields.get("queue", "unknown"),
            status="done",
        )
        if fields.get("processing_time_ms") is not None:
            metrics_registry.observe(
                "task_processing_time_ms",
                float(fields["processing_time_ms"]),
                depth=fields.get("depth", "unknown"),
                queue=fields.get("queue", "unknown"),
            )
    elif event == "task_failed":
        metrics_registry.incr(
            "tasks_completed_total",
            depth=fields.get("depth", "unknown"),
            queue=fields.get("queue", "unknown"),
            status="failed",
        )
    elif event == "analysis_stage":
        metrics_registry.observe(
            "analysis_stage_elapsed_ms",
            float(fields.get("elapsed_ms", 0)),
            stage=fields.get("stage", "unknown"),
            status=fields.get("status", "ok"),
            depth=fields.get("depth", "unknown"),
        )
    elif event == "callback_done":
        metrics_registry.incr(
            "callback_total",
            status=fields.get("status", "unknown"),
            depth=fields.get("depth", "unknown"),
        )

    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    logger.info(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
