from __future__ import annotations

import csv
from datetime import datetime
import io
import json
import uuid
from typing import Any
from collections import Counter
from pathlib import Path
import shutil
import hashlib

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from pydantic import ValidationError
from sqlalchemy import and_
from sqlalchemy.orm import Session
import joblib

from app.analyzer.model_registry import registry
from app.core.config import get_settings
from app.core.observability import log_event
from app.core.security import (
    assert_callback_url_safe,
    assert_public_http_url,
    assert_safe_model_artifact_path,
)
from app.db import SessionLocal, init_db
from app.models import AnalysisTask, FeedbackRecord, ModelEvent
from app.pipeline import run_analysis
from app.schemas import (
    AnalyzeRequest,
    AnalyzeResult,
    BulkFeedbackRequest,
    BulkFeedbackResponse,
    BatchAnalyzeRequest,
    FeedbackExportResponse,
    FeedbackStatsResponse,
    FeedbackRequest,
    FeedbackResponse,
    ModelReloadResponse,
    ModelStatusResponse,
    ModelEvaluateResponse,
    ModelPromoteRequest,
    ModelPromoteResponse,
    ModelRollbackRequest,
    ModelRollbackResponse,
    ModelEventResponse,
    ModelHistoryResponse,
    ModelHistoryCsvResponse,
    ModelHistoryVerifyResponse,
    TrainingSampleExportResponse,
)

app = FastAPI(title="Malicious Site Sandbox Detector")
settings = get_settings()


@app.on_event("startup")
def on_startup() -> None:
    init_db()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_governance_auth(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    expected = settings.governance_api_key
    if not expected:
        return
    if x_api_key != expected:
        raise HTTPException(status_code=401, detail="invalid governance api key")


def _row_to_response(row: AnalysisTask) -> AnalyzeResult:
    metadata = row.metadata_json or {}
    missing_artifacts = metadata.get("missing_artifacts")
    if missing_artifacts is None:
        missing_artifacts = []
    analysis_state = metadata.get("analysis_state") or {}
    return AnalyzeResult(
        task_id=row.task_id,
        status=row.status,
        verdict={
            "label": row.label,
            "confidence": row.confidence,
            "evidence": row.evidence or [],
            "brand_target": row.brand_target,
        }
        if row.label
        else None,
        layers=row.layers or [],
        collected=row.collected,
        analysis_state=analysis_state,
        analysis_completeness=metadata.get("analysis_completeness"),
        collection_quality=metadata.get("collection_quality"),
        missing_artifacts=missing_artifacts,
        processing_time_ms=int(row.processing_time_ms) if row.processing_time_ms else None,
        error=row.error,
        metadata=metadata,
    )


def _create_feedback_record(db: Session, payload: FeedbackRequest) -> FeedbackRecord:
    task = db.get(AnalysisTask, payload.task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"task not found: {payload.task_id}")
    if task.status != "done":
        raise HTTPException(status_code=400, detail=f"task is not completed: {payload.task_id}")

    predicted_label = task.label
    human_label = payload.human_label.value
    is_false_positive = bool(predicted_label in {"phishing", "malware"} and human_label == "benign")

    row = FeedbackRecord(
        task_id=task.task_id,
        url=task.url,
        predicted_label=predicted_label,
        human_label=human_label,
        is_false_positive=is_false_positive,
        note=payload.note,
        reviewer=payload.reviewer,
        features_json=(task.metadata_json or {}).get("features", {}),
    )
    db.add(row)
    return row


def _feedback_row_to_response(row: FeedbackRecord) -> FeedbackResponse:
    return FeedbackResponse(
        feedback_id=row.feedback_id,
        task_id=row.task_id,
        predicted_label=row.predicted_label,
        human_label=row.human_label,
        is_false_positive=row.is_false_positive,
        created_at=row.created_at.isoformat(),
    )


def _log_model_event(
    db: Session,
    event_type: str,
    status: str = "ok",
    payload: dict[str, Any] | None = None,
    actor: str | None = "system",
) -> ModelEvent:
    latest = db.query(ModelEvent).order_by(ModelEvent.created_at.desc()).first()
    prev_hash = latest.event_hash if latest and latest.event_hash else ""
    created_at = datetime.utcnow()
    safe_payload = payload or {}
    payload_json = json.dumps(safe_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    material = "|".join([prev_hash, event_type, status, actor or "", created_at.isoformat(), payload_json])
    event_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()

    row = ModelEvent(
        event_type=event_type,
        status=status,
        actor=actor,
        prev_hash=prev_hash or None,
        event_hash=event_hash,
        payload=safe_payload,
        created_at=created_at,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _model_event_to_response(row: ModelEvent) -> ModelEventResponse:
    return ModelEventResponse(
        event_id=row.event_id,
        event_type=row.event_type,
        status=row.status,
        actor=row.actor,
        prev_hash=row.prev_hash,
        event_hash=row.event_hash,
        payload=row.payload or {},
        created_at=row.created_at.isoformat() if row.created_at else "",
    )


def _to_binary_metrics(y_true: list[int], y_pred: list[int]) -> dict[str, Any]:
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    total = len(y_true)
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "accuracy": round(accuracy, 6),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def _feedback_feature_vector(features: dict[str, Any]) -> list[float]:
    return [
        float(int(bool(features.get("is_new_domain", False)))),
        float(int(bool(features.get("self_signed_cert", False)))),
        float(int(bool(features.get("brand_domain_mismatch", False)))),
        float(features.get("js_obfuscation_hits", 0) or 0),
        float(features.get("hidden_iframe_count", 0) or 0),
        float(features.get("cross_domain_form_submit", 0) or 0),
        float(features.get("keyword_hit_count", 0) or 0),
        float(features.get("high_risk_xhr_count", 0) or 0),
    ]


def _parse_iso_or_400(value: str | None, field: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"{field} must be ISO datetime") from exc


def _validate_request_urls_or_400(target_url: str, callback_url: str | None) -> None:
    try:
        assert_public_http_url(
            target_url,
            allow_private=settings.allow_private_target_urls,
            field_name="url",
        )
        if callback_url:
            assert_callback_url_safe(
                callback_url,
                allow_private=settings.allow_private_callback_urls,
                allowlist_csv=settings.callback_allowlist,
            )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _collect_eval_samples(db: Session, limit: int, from_ts: str | None, to_ts: str | None) -> tuple[list[list[float]], list[int]]:
    filters = []
    from_dt = _parse_iso_or_400(from_ts, "from_ts")
    to_dt = _parse_iso_or_400(to_ts, "to_ts")
    if from_dt:
        filters.append(FeedbackRecord.created_at >= from_dt)
    if to_dt:
        filters.append(FeedbackRecord.created_at <= to_dt)

    query = db.query(FeedbackRecord)
    if filters:
        query = query.filter(and_(*filters))
    rows = query.order_by(FeedbackRecord.created_at.desc()).limit(limit).all()

    X: list[list[float]] = []
    y_true: list[int] = []
    for row in rows:
        if row.human_label not in {"benign", "phishing", "malware"}:
            continue
        features = row.features_json or {}
        X.append(_feedback_feature_vector(features))
        y_true.append(0 if row.human_label == "benign" else 1)
    return X, y_true


def _query_model_events(
    db: Session,
    limit: int,
    event_type: str | None = None,
    event_status: str | None = None,
    from_ts: str | None = None,
    to_ts: str | None = None,
) -> list[ModelEvent]:
    from_dt = _parse_iso_or_400(from_ts, "from_ts")
    to_dt = _parse_iso_or_400(to_ts, "to_ts")
    filters = []
    if event_type:
        filters.append(ModelEvent.event_type == event_type)
    if event_status:
        filters.append(ModelEvent.status == event_status)
    if from_dt:
        filters.append(ModelEvent.created_at >= from_dt)
    if to_dt:
        filters.append(ModelEvent.created_at <= to_dt)

    query = db.query(ModelEvent)
    if filters:
        query = query.filter(and_(*filters))
    return query.order_by(ModelEvent.created_at.desc()).limit(limit).all()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/model/status", response_model=ModelStatusResponse)
def model_status(
    _: None = Depends(require_governance_auth),
    x_actor: str | None = Header(default=None, alias="X-Actor"),
) -> ModelStatusResponse:
    status = registry.status()
    return ModelStatusResponse(
        path=status.path,
        exists=status.exists,
        loaded=status.loaded,
        last_loaded_ts=status.last_loaded_ts,
        mtime=status.mtime,
        error=status.error,
    )


@app.post("/model/reload", response_model=ModelReloadResponse)
def model_reload(
    db: Session = Depends(get_db),
    _: None = Depends(require_governance_auth),
    x_actor: str | None = Header(default=None, alias="X-Actor"),
) -> ModelReloadResponse:
    status = registry.force_reload()
    payload = ModelStatusResponse(
        path=status.path,
        exists=status.exists,
        loaded=status.loaded,
        last_loaded_ts=status.last_loaded_ts,
        mtime=status.mtime,
        error=status.error,
    )
    reloaded = payload.loaded and payload.error is None
    _log_model_event(
        db=db,
        event_type="reload",
        status="ok" if reloaded else "error",
        payload={"reloaded": reloaded, "path": payload.path, "error": payload.error},
        actor=x_actor or "system",
    )
    return ModelReloadResponse(reloaded=reloaded, status=payload)


@app.get("/model/evaluate", response_model=ModelEvaluateResponse)
def model_evaluate(
    limit: int = 2000,
    from_ts: str | None = None,
    to_ts: str | None = None,
    db: Session = Depends(get_db),
    _: None = Depends(require_governance_auth),
    x_actor: str | None = Header(default=None, alias="X-Actor"),
) -> ModelEvaluateResponse:
    if limit <= 0 or limit > 20000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 20000")

    model = registry.get_model()
    status = registry.status()
    if model is None:
        _log_model_event(
            db=db,
            event_type="evaluate",
            status="error",
            payload={"reason": "model_not_loaded", "error": status.error},
            actor=x_actor or "system",
        )
        raise HTTPException(status_code=400, detail=f"model not loaded: {status.error or 'unknown error'}")

    X, y_true = _collect_eval_samples(db, limit, from_ts, to_ts)
    if not X:
        _log_model_event(
            db=db,
            event_type="evaluate",
            status="error",
            payload={"reason": "no_valid_samples", "limit": limit},
            actor=x_actor or "system",
        )
        raise HTTPException(status_code=400, detail="no valid feedback samples for evaluation")

    y_pred = [int(v) for v in model.predict(X)]
    metrics = _to_binary_metrics(y_true, y_pred)
    metrics["count"] = len(X)

    status = registry.status()
    model_payload = ModelStatusResponse(
        path=status.path,
        exists=status.exists,
        loaded=status.loaded,
        last_loaded_ts=status.last_loaded_ts,
        mtime=status.mtime,
        error=status.error,
    )
    response = ModelEvaluateResponse(
        model=model_payload,
        sample_count=len(X),
        metrics=metrics,
        filters={"limit": limit, "from_ts": from_ts, "to_ts": to_ts},
    )
    _log_model_event(
        db=db,
        event_type="evaluate",
        status="ok",
        payload={
            "sample_count": len(X),
            "metrics": metrics,
            "filters": {"limit": limit, "from_ts": from_ts, "to_ts": to_ts},
        },
        actor=x_actor or "system",
    )
    return response


@app.post("/model/promote", response_model=ModelPromoteResponse)
def model_promote(
    payload: ModelPromoteRequest,
    db: Session = Depends(get_db),
    _: None = Depends(require_governance_auth),
    x_actor: str | None = Header(default=None, alias="X-Actor"),
) -> ModelPromoteResponse:
    if payload.limit <= 0 or payload.limit > 20000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 20000")

    try:
        active_path = assert_safe_model_artifact_path(
            registry.status().path,
            base_dir=settings.model_artifact_dir,
        )
        challenger_path = assert_safe_model_artifact_path(
            payload.challenger_path,
            base_dir=settings.model_artifact_dir,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not challenger_path.exists():
        _log_model_event(
            db=db,
            event_type="promote",
            status="error",
            payload={"reason": "challenger_not_found", "challenger_path": str(challenger_path)},
            actor=x_actor or "system",
        )
        raise HTTPException(status_code=400, detail=f"challenger model not found: {challenger_path}")
    if not active_path.exists():
        _log_model_event(
            db=db,
            event_type="promote",
            status="error",
            payload={"reason": "active_not_found", "active_path": str(active_path)},
            actor=x_actor or "system",
        )
        raise HTTPException(status_code=400, detail=f"active model not found: {active_path}")

    X, y_true = _collect_eval_samples(db, payload.limit, payload.from_ts, payload.to_ts)
    if not X:
        _log_model_event(
            db=db,
            event_type="promote",
            status="error",
            payload={"reason": "no_valid_samples", "limit": payload.limit},
            actor=x_actor or "system",
        )
        raise HTTPException(status_code=400, detail="no valid feedback samples for promotion evaluation")

    baseline = registry.get_model()
    if baseline is None:
        _log_model_event(
            db=db,
            event_type="promote",
            status="error",
            payload={"reason": "active_model_not_loaded"},
            actor=x_actor or "system",
        )
        raise HTTPException(status_code=400, detail="active model is not loaded")
    challenger = joblib.load(challenger_path)

    baseline_pred = [int(v) for v in baseline.predict(X)]
    challenger_pred = [int(v) for v in challenger.predict(X)]
    base_metrics = _to_binary_metrics(y_true, baseline_pred)
    chal_metrics = _to_binary_metrics(y_true, challenger_pred)

    delta = {
        "f1": round(chal_metrics["f1"] - base_metrics["f1"], 6),
        "precision": round(chal_metrics["precision"] - base_metrics["precision"], 6),
        "recall": round(chal_metrics["recall"] - base_metrics["recall"], 6),
        "accuracy": round(chal_metrics["accuracy"] - base_metrics["accuracy"], 6),
    }
    eligible = delta["f1"] >= payload.min_delta_f1 and chal_metrics["recall"] >= base_metrics["recall"]
    reason = "challenger accepted"
    if not eligible:
        reason = "challenger did not satisfy min_delta_f1/recall gate"
    if payload.dry_run:
        reason = "dry_run: no file promoted"

    backup_path_str: str | None = None
    promoted = False
    if eligible and not payload.dry_run:
        backup_dir = active_path.parent / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_name = f"{active_path.stem}.{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.joblib"
        backup_path = backup_dir / backup_name
        shutil.copy2(active_path, backup_path)
        shutil.copy2(challenger_path, active_path)
        registry.force_reload()
        backup_path_str = str(backup_path)
        promoted = True

    response = ModelPromoteResponse(
        promoted=promoted,
        reason=reason,
        active_path=str(active_path),
        backup_path=backup_path_str,
        baseline_metrics=base_metrics,
        challenger_metrics=chal_metrics,
        delta=delta,
    )
    _log_model_event(
        db=db,
        event_type="promote",
        status="ok" if promoted or payload.dry_run else "rejected",
        payload={
            "promoted": promoted,
            "dry_run": payload.dry_run,
            "reason": reason,
            "active_path": str(active_path),
            "challenger_path": str(challenger_path),
            "backup_path": backup_path_str,
            "delta": delta,
            "baseline_metrics": base_metrics,
            "challenger_metrics": chal_metrics,
        },
        actor=x_actor or "system",
    )
    return response


@app.post("/model/rollback", response_model=ModelRollbackResponse)
def model_rollback(
    payload: ModelRollbackRequest,
    db: Session = Depends(get_db),
    _: None = Depends(require_governance_auth),
    x_actor: str | None = Header(default=None, alias="X-Actor"),
) -> ModelRollbackResponse:
    try:
        active_path = assert_safe_model_artifact_path(
            registry.status().path,
            base_dir=settings.model_artifact_dir,
        )
        backup_path = assert_safe_model_artifact_path(
            payload.backup_path,
            base_dir=settings.model_artifact_dir,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not backup_path.exists():
        _log_model_event(
            db=db,
            event_type="rollback",
            status="error",
            payload={"reason": "backup_not_found", "backup_path": str(backup_path)},
            actor=x_actor or "system",
        )
        raise HTTPException(status_code=400, detail=f"backup not found: {backup_path}")
    if not active_path.parent.exists():
        active_path.parent.mkdir(parents=True, exist_ok=True)

    shutil.copy2(backup_path, active_path)
    status = registry.force_reload()
    model_status_payload = ModelStatusResponse(
        path=status.path,
        exists=status.exists,
        loaded=status.loaded,
        last_loaded_ts=status.last_loaded_ts,
        mtime=status.mtime,
        error=status.error,
    )
    response = ModelRollbackResponse(
        rolled_back=model_status_payload.loaded and model_status_payload.error is None,
        active_path=str(active_path),
        status=model_status_payload,
    )
    _log_model_event(
        db=db,
        event_type="rollback",
        status="ok" if response.rolled_back else "error",
        payload={
            "backup_path": str(backup_path),
            "active_path": str(active_path),
            "rolled_back": response.rolled_back,
            "error": model_status_payload.error,
        },
        actor=x_actor or "system",
    )
    return response


@app.get("/model/history", response_model=ModelHistoryResponse)
def model_history(
    limit: int = 100,
    event_type: str | None = None,
    event_status: str | None = None,
    from_ts: str | None = None,
    to_ts: str | None = None,
    db: Session = Depends(get_db),
    _: None = Depends(require_governance_auth),
    x_actor: str | None = Header(default=None, alias="X-Actor"),
) -> ModelHistoryResponse:
    if limit <= 0 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 1000")
    rows = _query_model_events(
        db=db,
        limit=limit,
        event_type=event_type,
        event_status=event_status,
        from_ts=from_ts,
        to_ts=to_ts,
    )
    return ModelHistoryResponse(count=len(rows), rows=[_model_event_to_response(r) for r in rows])


@app.get("/model/history/export.csv", response_model=ModelHistoryCsvResponse)
def model_history_export_csv(
    limit: int = 1000,
    event_type: str | None = None,
    event_status: str | None = None,
    from_ts: str | None = None,
    to_ts: str | None = None,
    db: Session = Depends(get_db),
    _: None = Depends(require_governance_auth),
    x_actor: str | None = Header(default=None, alias="X-Actor"),
) -> ModelHistoryCsvResponse:
    if limit <= 0 or limit > 5000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 5000")
    rows = _query_model_events(
        db=db,
        limit=limit,
        event_type=event_type,
        event_status=event_status,
        from_ts=from_ts,
        to_ts=to_ts,
    )
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=["event_id", "event_type", "status", "actor", "prev_hash", "event_hash", "created_at", "payload_json"],
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                "event_id": row.event_id,
                "event_type": row.event_type,
                "status": row.status,
                "actor": row.actor,
                "prev_hash": row.prev_hash,
                "event_hash": row.event_hash,
                "created_at": row.created_at.isoformat() if row.created_at else "",
                "payload_json": json.dumps(row.payload or {}, ensure_ascii=False),
            }
        )
    return ModelHistoryCsvResponse(count=len(rows), csv=buffer.getvalue())


@app.get("/model/history/verify", response_model=ModelHistoryVerifyResponse)
def model_history_verify(
    limit: int = 5000,
    from_ts: str | None = None,
    to_ts: str | None = None,
    db: Session = Depends(get_db),
    _: None = Depends(require_governance_auth),
    x_actor: str | None = Header(default=None, alias="X-Actor"),
) -> ModelHistoryVerifyResponse:
    if limit <= 0 or limit > 50000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 50000")

    from_dt = _parse_iso_or_400(from_ts, "from_ts")
    to_dt = _parse_iso_or_400(to_ts, "to_ts")
    filters = []
    if from_dt:
        filters.append(ModelEvent.created_at >= from_dt)
    if to_dt:
        filters.append(ModelEvent.created_at <= to_dt)

    query = db.query(ModelEvent)
    if filters:
        query = query.filter(and_(*filters))
    rows = query.order_by(ModelEvent.created_at.asc()).limit(limit).all()

    prev_hash = ""
    checked = 0
    for row in rows:
        payload_json = json.dumps(row.payload or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        material = "|".join([prev_hash, row.event_type, row.status, row.actor or "", (row.created_at.isoformat() if row.created_at else ""), payload_json])
        expected = hashlib.sha256(material.encode("utf-8")).hexdigest()
        if (row.prev_hash or "") != prev_hash or (row.event_hash or "") != expected:
            return ModelHistoryVerifyResponse(
                valid=False,
                checked=checked + 1,
                first_error_event_id=row.event_id,
                message="audit hash chain mismatch",
                last_hash=prev_hash or None,
            )
        prev_hash = row.event_hash or ""
        checked += 1

    return ModelHistoryVerifyResponse(
        valid=True,
        checked=checked,
        first_error_event_id=None,
        message="audit hash chain verified",
        last_hash=prev_hash or None,
    )


@app.get("/analyze/{task_id}", response_model=AnalyzeResult)
def get_result(task_id: str, db: Session = Depends(get_db)) -> AnalyzeResult:
    row = db.get(AnalysisTask, task_id)
    if not row:
        raise HTTPException(status_code=404, detail="task not found")
    return _row_to_response(row)


@app.post("/analyze", response_model=AnalyzeResult)
def analyze(payload: AnalyzeRequest, db: Session = Depends(get_db)) -> AnalyzeResult:
    task_id = str(uuid.uuid4())
    callback_url = str(payload.callback_url) if payload.callback_url else None
    _validate_request_urls_or_400(str(payload.url), callback_url)

    row = AnalysisTask(
        task_id=task_id,
        url=str(payload.url),
        depth=payload.depth.value,
        status="queued",
        metadata_json={"analysis_state": {"current": "queued", "history": [{"stage": "queued", "status": "ok"}]}},
    )
    db.add(row)
    db.commit()
    log_event("task_queued", task_id=task_id, url=str(payload.url), depth=payload.depth.value, mode=payload.mode)

    if payload.mode == "sync":
        try:
            row.status = "running"
            row.metadata_json = {
                "analysis_state": {
                    "current": "running",
                    "history": [{"stage": "queued", "status": "ok"}, {"stage": "running", "status": "ok"}],
                }
            }
            db.commit()
            log_event("task_running", task_id=task_id, url=str(payload.url), depth=payload.depth.value, mode="sync")
            result = run_analysis(task_id, str(payload.url), payload.depth.value, callback_url)
            row = db.get(AnalysisTask, task_id)
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
            db.commit()
            log_event(
                "task_done",
                task_id=task_id,
                url=str(payload.url),
                depth=payload.depth.value,
                mode="sync",
                processing_time_ms=result.get("processing_time_ms"),
            )
        except Exception as exc:
            row = db.get(AnalysisTask, task_id)
            row.status = "failed"
            row.error = str(exc)
            row.metadata_json = {
                "analysis_state": {
                    "current": "failed",
                    "history": [{"stage": "failed", "status": "error", "extra": {"error": str(exc)}}],
                }
            }
            db.commit()
            log_event("task_failed", task_id=task_id, url=str(payload.url), depth=payload.depth.value, mode="sync", error=str(exc))
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return _row_to_response(row)

    try:
        from app.tasks import analyze_url_task
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"async worker unavailable: {exc}") from exc

    analyze_url_task.delay(task_id, str(payload.url), payload.depth.value, callback_url)
    log_event("task_dispatched", task_id=task_id, url=str(payload.url), depth=payload.depth.value, mode="async")
    row = db.get(AnalysisTask, task_id)
    return _row_to_response(row)


@app.post("/analyze/batch")
async def analyze_batch(
    request: Request,
    file: UploadFile | None = File(default=None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    urls: list[str] = []
    depth = "standard"
    callback_url = None

    if "application/json" in (request.headers.get("content-type") or "").lower():
        try:
            raw_payload = await request.json()
        except Exception as exc:
            raise HTTPException(status_code=400, detail="invalid json payload") from exc
        if raw_payload:
            try:
                payload = BatchAnalyzeRequest.model_validate(raw_payload)
            except ValidationError as exc:
                raise HTTPException(status_code=422, detail=exc.errors()) from exc
            urls = [str(u) for u in payload.urls]
            depth = payload.depth.value
            callback_url = str(payload.callback_url) if payload.callback_url else None

    if file is not None:
        raw = file.file.read().decode("utf-8", errors="ignore")
        reader = csv.DictReader(io.StringIO(raw))
        for row in reader:
            if row.get("url"):
                urls.append(row["url"].strip())

    if not urls:
        raise HTTPException(status_code=400, detail="no urls provided")

    if len(urls) > settings.max_batch_size:
        raise HTTPException(status_code=400, detail=f"batch exceeds {settings.max_batch_size}")

    if callback_url:
        _validate_request_urls_or_400(urls[0], callback_url)
    for u in urls:
        _validate_request_urls_or_400(u, None)

    task_ids = []
    for u in urls:
        task_id = str(uuid.uuid4())
        db.add(
            AnalysisTask(
                task_id=task_id,
                url=u,
                depth=depth,
                status="queued",
                metadata_json={"analysis_state": {"current": "queued", "history": [{"stage": "queued", "status": "ok"}]}},
            )
        )
        task_ids.append(task_id)
    db.commit()

    try:
        from app.tasks import analyze_url_task
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"async worker unavailable: {exc}") from exc

    for task_id, u in zip(task_ids, urls):
        analyze_url_task.delay(task_id, u, depth, callback_url)
        log_event("task_dispatched", task_id=task_id, url=u, depth=depth, mode="async_batch")

    return {"count": len(task_ids), "task_ids": task_ids}


@app.post("/feedback", response_model=FeedbackResponse)
def submit_feedback(payload: FeedbackRequest, db: Session = Depends(get_db)) -> FeedbackResponse:
    row = _create_feedback_record(db, payload)
    db.commit()
    db.refresh(row)
    return _feedback_row_to_response(row)


@app.post("/feedback/bulk", response_model=BulkFeedbackResponse)
def submit_feedback_bulk(payload: BulkFeedbackRequest, db: Session = Depends(get_db)) -> BulkFeedbackResponse:
    if not payload.items:
        raise HTTPException(status_code=400, detail="items cannot be empty")

    rows: list[FeedbackRecord] = []
    try:
        for item in payload.items:
            rows.append(_create_feedback_record(db, item))
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise
    for row in rows:
        db.refresh(row)
    return BulkFeedbackResponse(count=len(rows), rows=[_feedback_row_to_response(r) for r in rows])


@app.get("/feedback/export", response_model=FeedbackExportResponse)
def export_feedback(limit: int = 500, db: Session = Depends(get_db)) -> FeedbackExportResponse:
    if limit <= 0 or limit > 5000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 5000")

    rows = (
        db.query(FeedbackRecord)
        .order_by(FeedbackRecord.created_at.desc())
        .limit(limit)
        .all()
    )
    result_rows = []
    for row in rows:
        result_rows.append(
            {
                "feedback_id": row.feedback_id,
                "task_id": row.task_id,
                "url": row.url,
                "predicted_label": row.predicted_label,
                "human_label": row.human_label,
                "is_false_positive": row.is_false_positive,
                "note": row.note,
                "reviewer": row.reviewer,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "features": row.features_json or {},
            }
        )
    return FeedbackExportResponse(count=len(result_rows), rows=result_rows)


@app.get("/feedback/export.csv")
def export_feedback_csv(limit: int = 500, db: Session = Depends(get_db)) -> dict[str, Any]:
    if limit <= 0 or limit > 5000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 5000")

    rows = (
        db.query(FeedbackRecord)
        .order_by(FeedbackRecord.created_at.desc())
        .limit(limit)
        .all()
    )
    csv_buffer = io.StringIO()
    writer = csv.DictWriter(
        csv_buffer,
        fieldnames=[
            "feedback_id",
            "task_id",
            "url",
            "predicted_label",
            "human_label",
            "is_false_positive",
            "note",
            "reviewer",
            "created_at",
            "features_json",
        ],
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                "feedback_id": row.feedback_id,
                "task_id": row.task_id,
                "url": row.url,
                "predicted_label": row.predicted_label,
                "human_label": row.human_label,
                "is_false_positive": row.is_false_positive,
                "note": row.note,
                "reviewer": row.reviewer,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "features_json": json.dumps(row.features_json or {}, ensure_ascii=False),
            }
        )
    return {"count": len(rows), "csv": csv_buffer.getvalue()}


@app.get("/feedback/training-samples", response_model=TrainingSampleExportResponse)
def export_training_samples(
    limit: int = 1000,
    from_ts: str | None = None,
    to_ts: str | None = None,
    human_label: str | None = None,
    only_false_positive: bool = False,
    balanced: bool = False,
    db: Session = Depends(get_db),
) -> TrainingSampleExportResponse:
    if limit <= 0 or limit > 10000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 10000")

    filters = []
    from_dt = None
    to_dt = None

    if from_ts:
        try:
            from_dt = datetime.fromisoformat(from_ts)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="from_ts must be ISO datetime") from exc
        filters.append(FeedbackRecord.created_at >= from_dt)

    if to_ts:
        try:
            to_dt = datetime.fromisoformat(to_ts)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="to_ts must be ISO datetime") from exc
        filters.append(FeedbackRecord.created_at <= to_dt)

    if human_label:
        if human_label not in {"phishing", "malware", "benign"}:
            raise HTTPException(status_code=400, detail="human_label must be phishing|malware|benign")
        filters.append(FeedbackRecord.human_label == human_label)

    if only_false_positive:
        filters.append(FeedbackRecord.is_false_positive.is_(True))

    query = db.query(FeedbackRecord)
    if filters:
        query = query.filter(and_(*filters))
    query = query.order_by(FeedbackRecord.created_at.desc())

    rows = query.limit(limit).all()

    if balanced:
        by_label: dict[str, list[FeedbackRecord]] = {"phishing": [], "malware": [], "benign": []}
        for row in rows:
            if row.human_label in by_label:
                by_label[row.human_label].append(row)
        min_count = min(len(v) for v in by_label.values() if v) if any(by_label.values()) else 0
        if min_count > 0:
            balanced_rows: list[FeedbackRecord] = []
            for label in ("phishing", "malware", "benign"):
                balanced_rows.extend(by_label[label][:min_count])
            rows = balanced_rows

    result_rows = []
    for row in rows:
        result_rows.append(
            {
                "feedback_id": row.feedback_id,
                "task_id": row.task_id,
                "url": row.url,
                "predicted_label": row.predicted_label,
                "human_label": row.human_label,
                "is_false_positive": row.is_false_positive,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "features": row.features_json or {},
            }
        )

    return TrainingSampleExportResponse(
        count=len(result_rows),
        rows=result_rows,
        filters={
            "limit": limit,
            "from_ts": from_ts,
            "to_ts": to_ts,
            "human_label": human_label,
            "only_false_positive": only_false_positive,
            "balanced": balanced,
        },
    )


@app.get("/feedback/stats", response_model=FeedbackStatsResponse)
def feedback_stats(
    from_ts: str | None = None,
    to_ts: str | None = None,
    reviewer: str | None = None,
    db: Session = Depends(get_db),
) -> FeedbackStatsResponse:
    filters = []
    if from_ts:
        try:
            from_dt = datetime.fromisoformat(from_ts)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="from_ts must be ISO datetime") from exc
        filters.append(FeedbackRecord.created_at >= from_dt)

    if to_ts:
        try:
            to_dt = datetime.fromisoformat(to_ts)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="to_ts must be ISO datetime") from exc
        filters.append(FeedbackRecord.created_at <= to_dt)

    if reviewer:
        filters.append(FeedbackRecord.reviewer == reviewer)

    query = db.query(FeedbackRecord)
    if filters:
        query = query.filter(and_(*filters))
    rows = query.order_by(FeedbackRecord.created_at.asc()).all()

    total = len(rows)
    fp_count = sum(1 for r in rows if r.is_false_positive)
    fp_rate = (fp_count / total) if total else 0.0

    human_dist = Counter((r.human_label or "unknown") for r in rows)
    pred_dist = Counter((r.predicted_label or "unknown") for r in rows)
    daily = Counter((r.created_at.date().isoformat() if r.created_at else "unknown") for r in rows)
    daily_counts = [{"date": day, "count": count} for day, count in sorted(daily.items())]

    return FeedbackStatsResponse(
        total_feedback=total,
        false_positive_count=fp_count,
        false_positive_rate=round(fp_rate, 4),
        human_label_distribution=dict(human_dist),
        predicted_label_distribution=dict(pred_dist),
        daily_counts=daily_counts,
        filters={"from_ts": from_ts, "to_ts": to_ts, "reviewer": reviewer},
    )
