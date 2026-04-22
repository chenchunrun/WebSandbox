from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field, HttpUrl


class Depth(str, Enum):
    quick = "quick"
    standard = "standard"
    deep = "deep"


class VerdictLabel(str, Enum):
    phishing = "phishing"
    malware = "malware"
    benign = "benign"


class AnalyzeRequest(BaseModel):
    url: HttpUrl
    depth: Depth = Depth.standard
    callback_url: HttpUrl | None = None
    mode: str = Field(default="async", pattern="^(async|sync)$")


class BatchAnalyzeRequest(BaseModel):
    urls: list[HttpUrl] = Field(default_factory=list, max_length=1000)
    depth: Depth = Depth.standard
    callback_url: HttpUrl | None = None


class Verdict(BaseModel):
    label: VerdictLabel
    confidence: float
    evidence: list[str] = Field(default_factory=list)
    brand_target: str | None = None
    risk_type: str | None = None
    action: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    evidence_score: int | None = None


class Collected(BaseModel):
    final_url: str | None = None
    redirect_count: int = 0
    screenshot_path: str | None = None
    domain_age_days: int | None = None


class AnalyzeResult(BaseModel):
    task_id: str
    status: str
    verdict: Verdict | None = None
    layers: list[str] = Field(default_factory=list)
    collected: Collected | None = None
    analysis_state: dict[str, Any] = Field(default_factory=dict)
    analysis_completeness: str | None = None
    collection_quality: str | None = None
    missing_artifacts: list[str] = Field(default_factory=list)
    processing_time_ms: int | None = None
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class FeedbackRequest(BaseModel):
    task_id: str
    human_label: VerdictLabel
    note: str | None = None
    reviewer: str | None = None


class FeedbackResponse(BaseModel):
    feedback_id: str
    task_id: str
    predicted_label: str | None = None
    human_label: VerdictLabel
    is_false_positive: bool
    created_at: str


class FeedbackExportResponse(BaseModel):
    count: int
    raw_count: int | None = None
    deduped: bool | None = None
    dataset_version: str | None = None
    rows: list[dict[str, Any]] = Field(default_factory=list)


class BulkFeedbackRequest(BaseModel):
    items: list[FeedbackRequest] = Field(default_factory=list, max_length=1000)


class BulkFeedbackResponse(BaseModel):
    count: int
    rows: list[FeedbackResponse] = Field(default_factory=list)


class TrainingSampleExportResponse(BaseModel):
    count: int
    raw_count: int | None = None
    deduped: bool | None = None
    dataset_version: str | None = None
    rows: list[dict[str, Any]] = Field(default_factory=list)
    filters: dict[str, Any] = Field(default_factory=dict)


class FeedbackStatsResponse(BaseModel):
    total_feedback: int
    false_positive_count: int
    false_positive_rate: float
    human_label_distribution: dict[str, int] = Field(default_factory=dict)
    predicted_label_distribution: dict[str, int] = Field(default_factory=dict)
    daily_counts: list[dict[str, Any]] = Field(default_factory=list)
    filters: dict[str, Any] = Field(default_factory=dict)


class ModelStatusResponse(BaseModel):
    path: str
    exists: bool
    loaded: bool
    last_loaded_ts: float | None = None
    mtime: float | None = None
    error: str | None = None


class ModelReloadResponse(BaseModel):
    reloaded: bool
    status: ModelStatusResponse


class ModelEvaluateResponse(BaseModel):
    model: ModelStatusResponse
    sample_count: int
    metrics: dict[str, Any] = Field(default_factory=dict)
    filters: dict[str, Any] = Field(default_factory=dict)


class ModelPromoteRequest(BaseModel):
    challenger_path: str
    min_delta_f1: float = 0.0
    limit: int = 2000
    from_ts: str | None = None
    to_ts: str | None = None
    dry_run: bool = False


class ModelPromoteResponse(BaseModel):
    promoted: bool
    reason: str
    active_path: str
    backup_path: str | None = None
    baseline_metrics: dict[str, Any] = Field(default_factory=dict)
    challenger_metrics: dict[str, Any] = Field(default_factory=dict)
    delta: dict[str, Any] = Field(default_factory=dict)


class ModelRollbackRequest(BaseModel):
    backup_path: str


class ModelRollbackResponse(BaseModel):
    rolled_back: bool
    active_path: str
    status: ModelStatusResponse


class ModelEventResponse(BaseModel):
    event_id: str
    event_type: str
    status: str
    actor: str | None = None
    prev_hash: str | None = None
    event_hash: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: str


class ModelHistoryResponse(BaseModel):
    count: int
    rows: list[ModelEventResponse] = Field(default_factory=list)


class ModelHistoryCsvResponse(BaseModel):
    count: int
    csv: str


class ModelHistoryVerifyResponse(BaseModel):
    valid: bool
    checked: int
    first_error_event_id: str | None = None
    message: str
    last_hash: str | None = None


class RulePolicySchema(BaseModel):
    malicious_threshold: float
    benign_threshold: float


class ActionPolicySchema(BaseModel):
    block_confidence: float
    benign_observe_confidence: float


class DeepEscalationPolicySchema(BaseModel):
    enabled: bool
    keyword_hit_threshold: int
    high_risk_xhr_threshold: int


class DetectionPolicyResponse(BaseModel):
    rule: RulePolicySchema
    action: ActionPolicySchema
    deep_escalation: DeepEscalationPolicySchema


class RulePolicyUpdate(BaseModel):
    malicious_threshold: float | None = Field(default=None, ge=0, le=1)
    benign_threshold: float | None = Field(default=None, ge=0, le=1)


class ActionPolicyUpdate(BaseModel):
    block_confidence: float | None = Field(default=None, ge=0, le=1)
    benign_observe_confidence: float | None = Field(default=None, ge=0, le=1)


class DeepEscalationPolicyUpdate(BaseModel):
    enabled: bool | None = None
    keyword_hit_threshold: int | None = Field(default=None, ge=0)
    high_risk_xhr_threshold: int | None = Field(default=None, ge=0)


class DetectionPolicyUpdateRequest(BaseModel):
    rule: RulePolicyUpdate | None = None
    action: ActionPolicyUpdate | None = None
    deep_escalation: DeepEscalationPolicyUpdate | None = None
    dry_run: bool = False


class DetectionPolicyUpdateResponse(BaseModel):
    updated: bool
    source: str
    policy: DetectionPolicyResponse
