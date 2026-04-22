from __future__ import annotations

from dataclasses import dataclass
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


def get_detection_policy() -> DetectionPolicy:
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
