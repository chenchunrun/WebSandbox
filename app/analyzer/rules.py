from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.analyzer.model_registry import registry


@dataclass
class RuleDecision:
    tier: str
    label: str
    confidence: float
    evidence: list[str]


class RuleModel:
    def decide(self, features: dict[str, Any]) -> RuleDecision:
        model = registry.get_model()
        if model is not None:
            vector = [[
                int(features.get("is_new_domain", False)),
                int(features.get("self_signed_cert", False)),
                int(features.get("brand_domain_mismatch", False)),
                float(features.get("js_obfuscation_hits", 0)),
                float(features.get("hidden_iframe_count", 0)),
                float(features.get("cross_domain_form_submit", 0)),
                float(features.get("keyword_hit_count", 0)),
                float(features.get("high_risk_xhr_count", 0)),
            ]]
            score = float(model.predict_proba(vector)[0][1])
            return self._score_to_decision(score, features)

        risk_score = 0.0
        evidence: list[str] = []

        if features.get("is_new_domain"):
            risk_score += 0.2
            evidence.append("新注册域名")
        if features.get("self_signed_cert"):
            risk_score += 0.2
            evidence.append("疑似自签名证书")
        if features.get("brand_domain_mismatch"):
            risk_score += 0.25
            evidence.append("品牌与域名不匹配")
        if features.get("cross_domain_form_submit", 0) > 0:
            risk_score += 0.2
            evidence.append("跨域表单提交")
        if features.get("hidden_iframe_count", 0) > 0:
            risk_score += 0.1
            evidence.append("隐藏iframe")
        if features.get("js_obfuscation_hits", 0) > 0:
            risk_score += 0.1
            evidence.append("疑似JS混淆")
        if features.get("keyword_hit_count", 0) > 0:
            risk_score += min(0.2, 0.05 * float(features.get("keyword_hit_count", 0)))
            evidence.append("高风险语义关键词")

        decision = self._score_to_decision(min(1.0, risk_score), features)
        if not decision.evidence:
            decision.evidence.extend(evidence)
        return decision

    def _score_to_decision(self, score: float, features: dict[str, Any]) -> RuleDecision:
        evidence = []
        if features.get("brand_domain_mismatch"):
            evidence.append("域名与品牌不匹配")
        if features.get("cross_domain_form_submit", 0) > 0:
            evidence.append("跨域表单提交")

        if score >= 0.82:
            return RuleDecision(tier="malicious", label="phishing", confidence=score, evidence=evidence)
        if score <= 0.25:
            return RuleDecision(tier="benign", label="benign", confidence=1 - score, evidence=evidence)
        return RuleDecision(tier="gray", label="benign", confidence=0.5, evidence=evidence)
