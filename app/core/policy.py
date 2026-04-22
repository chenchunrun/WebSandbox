from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any

from app.core.config import get_settings


@dataclass(frozen=True)
class RuleThresholdPolicy:
    malicious_threshold: float
    benign_threshold: float


@dataclass(frozen=True)
class ActionPolicy:
    block_confidence: float
    benign_observe_confidence: float


@dataclass(frozen=True)
class DeepEscalationPolicy:
    enabled: bool
    keyword_hit_threshold: int
    high_risk_xhr_threshold: int

    def should_escalate(self, depth: str, decision_tier: str, features: dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        if depth == "deep":
            return False
        if decision_tier == "gray":
            return True
        if bool(features.get("brand_domain_mismatch")):
            return True
        if float(features.get("cross_domain_form_submit", 0) or 0) > 0:
            return True
        if int(features.get("keyword_hit_count", 0) or 0) >= self.keyword_hit_threshold:
            return True
        if int(features.get("high_risk_xhr_count", 0) or 0) >= self.high_risk_xhr_threshold:
            return True
        return False


@dataclass(frozen=True)
class DetectionPolicy:
    rule: RuleThresholdPolicy
    action: ActionPolicy
    deep_escalation: DeepEscalationPolicy

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": {
                "malicious_threshold": self.rule.malicious_threshold,
                "benign_threshold": self.rule.benign_threshold,
            },
            "action": {
                "block_confidence": self.action.block_confidence,
                "benign_observe_confidence": self.action.benign_observe_confidence,
            },
            "deep_escalation": {
                "enabled": self.deep_escalation.enabled,
                "keyword_hit_threshold": self.deep_escalation.keyword_hit_threshold,
                "high_risk_xhr_threshold": self.deep_escalation.high_risk_xhr_threshold,
            },
        }


_cached_policy: DetectionPolicy | None = None
_cached_policy_source: str = "env_default"
_cached_policy_until: float = 0.0


def _build_policy_from_settings() -> DetectionPolicy:
    settings = get_settings()
    return DetectionPolicy(
        rule=RuleThresholdPolicy(
            malicious_threshold=float(settings.rule_malicious_threshold),
            benign_threshold=float(settings.rule_benign_threshold),
        ),
        action=ActionPolicy(
            block_confidence=float(settings.action_block_confidence),
            benign_observe_confidence=float(settings.action_benign_observe_confidence),
        ),
        deep_escalation=DeepEscalationPolicy(
            enabled=bool(settings.deep_escalation_enabled),
            keyword_hit_threshold=int(settings.deep_escalation_keyword_hit_threshold),
            high_risk_xhr_threshold=int(settings.deep_escalation_high_risk_xhr_threshold),
        ),
    )


def _policy_from_payload(payload: dict[str, Any]) -> DetectionPolicy:
    candidate = DetectionPolicy(
        rule=RuleThresholdPolicy(
            malicious_threshold=float(payload.get("rule", {}).get("malicious_threshold")),
            benign_threshold=float(payload.get("rule", {}).get("benign_threshold")),
        ),
        action=ActionPolicy(
            block_confidence=float(payload.get("action", {}).get("block_confidence")),
            benign_observe_confidence=float(payload.get("action", {}).get("benign_observe_confidence")),
        ),
        deep_escalation=DeepEscalationPolicy(
            enabled=bool(payload.get("deep_escalation", {}).get("enabled")),
            keyword_hit_threshold=int(payload.get("deep_escalation", {}).get("keyword_hit_threshold")),
            high_risk_xhr_threshold=int(payload.get("deep_escalation", {}).get("high_risk_xhr_threshold")),
        ),
    )
    _validate(candidate)
    return candidate


def _load_policy_from_db() -> tuple[DetectionPolicy | None, str]:
    from app.db import SessionLocal
    from app.models import PolicyConfig

    db = SessionLocal()
    try:
        row = db.get(PolicyConfig, 1)
        if not row or not row.policy_json:
            return None, "env_default"
        return _policy_from_payload(row.policy_json), "db_override"
    finally:
        db.close()


def _set_cache(policy: DetectionPolicy, source: str) -> None:
    global _cached_policy, _cached_policy_source, _cached_policy_until
    settings = get_settings()
    _cached_policy = policy
    _cached_policy_source = source
    _cached_policy_until = time.monotonic() + max(0, int(settings.policy_cache_ttl_seconds))


def _invalidate_cache() -> None:
    global _cached_policy_until
    _cached_policy_until = 0.0


def _validate(policy: DetectionPolicy) -> None:
    if not 0 <= policy.rule.benign_threshold <= 1:
        raise ValueError("rule.benign_threshold must be between 0 and 1")
    if not 0 <= policy.rule.malicious_threshold <= 1:
        raise ValueError("rule.malicious_threshold must be between 0 and 1")
    if policy.rule.malicious_threshold <= policy.rule.benign_threshold:
        raise ValueError("rule.malicious_threshold must be greater than rule.benign_threshold")
    if not 0 <= policy.action.block_confidence <= 1:
        raise ValueError("action.block_confidence must be between 0 and 1")
    if not 0 <= policy.action.benign_observe_confidence <= 1:
        raise ValueError("action.benign_observe_confidence must be between 0 and 1")
    if policy.deep_escalation.keyword_hit_threshold < 0:
        raise ValueError("deep_escalation.keyword_hit_threshold must be >= 0")
    if policy.deep_escalation.high_risk_xhr_threshold < 0:
        raise ValueError("deep_escalation.high_risk_xhr_threshold must be >= 0")


def get_detection_policy() -> DetectionPolicy:
    now = time.monotonic()
    if _cached_policy is not None and now <= _cached_policy_until:
        return _cached_policy

    default_policy = _build_policy_from_settings()
    db_policy, source = _load_policy_from_db()
    policy = db_policy or default_policy
    _validate(policy)
    _set_cache(policy, source)
    return policy


def policy_source() -> str:
    get_detection_policy()
    return _cached_policy_source


def preview_detection_policy(
    *,
    rule_malicious_threshold: float | None = None,
    rule_benign_threshold: float | None = None,
    action_block_confidence: float | None = None,
    action_benign_observe_confidence: float | None = None,
    deep_escalation_enabled: bool | None = None,
    deep_escalation_keyword_hit_threshold: int | None = None,
    deep_escalation_high_risk_xhr_threshold: int | None = None,
) -> DetectionPolicy:
    current = get_detection_policy()
    candidate = DetectionPolicy(
        rule=RuleThresholdPolicy(
            malicious_threshold=(
                current.rule.malicious_threshold if rule_malicious_threshold is None else float(rule_malicious_threshold)
            ),
            benign_threshold=current.rule.benign_threshold if rule_benign_threshold is None else float(rule_benign_threshold),
        ),
        action=ActionPolicy(
            block_confidence=(
                current.action.block_confidence if action_block_confidence is None else float(action_block_confidence)
            ),
            benign_observe_confidence=(
                current.action.benign_observe_confidence
                if action_benign_observe_confidence is None
                else float(action_benign_observe_confidence)
            ),
        ),
        deep_escalation=DeepEscalationPolicy(
            enabled=current.deep_escalation.enabled if deep_escalation_enabled is None else bool(deep_escalation_enabled),
            keyword_hit_threshold=(
                current.deep_escalation.keyword_hit_threshold
                if deep_escalation_keyword_hit_threshold is None
                else int(deep_escalation_keyword_hit_threshold)
            ),
            high_risk_xhr_threshold=(
                current.deep_escalation.high_risk_xhr_threshold
                if deep_escalation_high_risk_xhr_threshold is None
                else int(deep_escalation_high_risk_xhr_threshold)
            ),
        ),
    )
    _validate(candidate)
    return candidate


def update_detection_policy(
    *,
    rule_malicious_threshold: float | None = None,
    rule_benign_threshold: float | None = None,
    action_block_confidence: float | None = None,
    action_benign_observe_confidence: float | None = None,
    deep_escalation_enabled: bool | None = None,
    deep_escalation_keyword_hit_threshold: int | None = None,
    deep_escalation_high_risk_xhr_threshold: int | None = None,
) -> DetectionPolicy:
    from app.db import SessionLocal
    from app.models import PolicyConfig

    candidate = preview_detection_policy(
        rule_malicious_threshold=rule_malicious_threshold,
        rule_benign_threshold=rule_benign_threshold,
        action_block_confidence=action_block_confidence,
        action_benign_observe_confidence=action_benign_observe_confidence,
        deep_escalation_enabled=deep_escalation_enabled,
        deep_escalation_keyword_hit_threshold=deep_escalation_keyword_hit_threshold,
        deep_escalation_high_risk_xhr_threshold=deep_escalation_high_risk_xhr_threshold,
    )

    db = SessionLocal()
    try:
        row = db.get(PolicyConfig, 1)
        if not row:
            row = PolicyConfig(config_id=1, policy_json=candidate.as_dict())
            db.add(row)
        else:
            row.policy_json = candidate.as_dict()
        db.commit()
    finally:
        db.close()

    _set_cache(candidate, "db_override")
    return candidate


def set_detection_policy(policy: DetectionPolicy) -> DetectionPolicy:
    from app.db import SessionLocal
    from app.models import PolicyConfig

    _validate(policy)
    db = SessionLocal()
    try:
        row = db.get(PolicyConfig, 1)
        if not row:
            row = PolicyConfig(config_id=1, policy_json=policy.as_dict())
            db.add(row)
        else:
            row.policy_json = policy.as_dict()
        db.commit()
    finally:
        db.close()

    _set_cache(policy, "db_override")
    return policy


def detection_policy_from_dict(payload: dict[str, Any]) -> DetectionPolicy:
    return _policy_from_payload(payload)


def reset_detection_policy() -> DetectionPolicy:
    from app.db import SessionLocal
    from app.models import PolicyConfig

    db = SessionLocal()
    try:
        row = db.get(PolicyConfig, 1)
        if row:
            db.delete(row)
            db.commit()
    finally:
        db.close()

    _invalidate_cache()
    policy = _build_policy_from_settings()
    _set_cache(policy, "env_default")
    return policy
