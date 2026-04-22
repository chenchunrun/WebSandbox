from __future__ import annotations

import time
from typing import Any

import httpx

from app.analyzer.llm import LLMAnalyzer
from app.analyzer.rules import RuleModel
from app.core.config import get_settings
from app.core.observability import log_event
from app.core.security import assert_callback_url_safe
from app.crawler.sandbox_runner import SandboxRunner
from app.extractor.features import extract_features
from app.storage import ArtifactStore


settings = get_settings()


def run_analysis(task_id: str, url: str, depth: str, callback_url: str | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    layers: list[str] = ["layer2_static_started", "layer3_sandbox_started"]
    stage_history: list[dict[str, Any]] = []
    stage_started = time.perf_counter()

    def stage(stage_name: str, status: str = "ok", **extra: Any) -> None:
        nonlocal stage_started
        now = time.perf_counter()
        elapsed_ms = int((now - stage_started) * 1000)
        entry = {
            "stage": stage_name,
            "status": status,
            "elapsed_ms": max(0, elapsed_ms),
        }
        if extra:
            entry["extra"] = extra
        stage_history.append(entry)
        log_event(
            "analysis_stage",
            task_id=task_id,
            url=url,
            depth=depth,
            stage=stage_name,
            status=status,
            elapsed_ms=max(0, elapsed_ms),
            **extra,
        )
        stage_started = now

    runner = SandboxRunner()
    stage("crawling_started")
    artifacts = runner.run(url, depth, task_id)
    stage("crawling_succeeded")
    layers.extend(["layer2_static_collected", "layer3_sandbox_rendered"])
    if settings.isolation_mode == "docker_task":
        layers.append("layer3_isolated_container_executed")
    if runner.last_execution.get("fallback_used"):
        layers.append("layer3_local_fallback_executed")

    store = ArtifactStore()
    stage("persisting_artifacts_started")
    crawl_json_path = store.upload_json(
        f"{task_id}/crawl.json",
        {
            "raw_response": artifacts.raw_response,
            "final_url": artifacts.final_url,
            "redirect_chain": artifacts.redirect_chain,
            "ssl": artifacts.ssl,
            "network_events": artifacts.network_events,
            "cta_interaction": artifacts.cta_interaction,
        },
    )
    stage("persisting_artifacts_succeeded")

    stage("feature_extracting_started")
    features = extract_features(
        url=artifacts.final_url,
        dom_html=artifacts.dom_html,
        ssl=artifacts.ssl,
        network_events=artifacts.network_events,
    )
    stage("feature_extracting_succeeded")
    layers.append("layer2_features_extracted")

    stage("rule_scoring_started")
    rule_model = RuleModel()
    decision = rule_model.decide(features)
    stage("rule_scoring_succeeded", tier=decision.tier, label=decision.label)
    layers.append("layer3_rule_model_done")

    verdict: dict[str, Any]
    if decision.tier == "gray":
        stage("llm_reviewing_started")
        analyzer = LLMAnalyzer()
        screenshot_bytes = store.read_bytes(artifacts.desktop_screenshot_path or "")
        llm_verdict = analyzer.analyze(features, features.get("text_excerpt", ""), screenshot_bytes)
        verdict = {
            "label": llm_verdict["label"],
            "confidence": float(llm_verdict["confidence"]),
            "evidence": llm_verdict.get("evidence", []),
            "brand_target": llm_verdict.get("brand_target"),
        }
        stage("llm_reviewing_succeeded", label=verdict["label"])
        layers.append("layer4_llm_vlm_executed")
    else:
        verdict = {
            "label": decision.label,
            "confidence": decision.confidence,
            "evidence": decision.evidence,
            "brand_target": features.get("brand_target"),
        }

    missing_artifacts: list[str] = []
    if not artifacts.desktop_screenshot_path:
        missing_artifacts.append("desktop_screenshot")
    if not artifacts.mobile_screenshot_path:
        missing_artifacts.append("mobile_screenshot")
    if not crawl_json_path:
        missing_artifacts.append("crawl_json")

    analysis_completeness = "complete" if not missing_artifacts else "partial"
    collection_quality = "high"
    if len(missing_artifacts) == 1:
        collection_quality = "medium"
    elif len(missing_artifacts) >= 2:
        collection_quality = "low"

    collected = {
        "final_url": artifacts.final_url,
        "redirect_count": max(0, len(artifacts.redirect_chain) - 1),
        "screenshot_path": artifacts.desktop_screenshot_path,
        "domain_age_days": features.get("domain_age_days"),
        "crawl_json_path": crawl_json_path,
        "mobile_screenshot_path": artifacts.mobile_screenshot_path,
    }

    processing_time_ms = int((time.perf_counter() - started) * 1000)
    result = {
        "task_id": task_id,
        "status": "done",
        "verdict": verdict,
        "layers": layers,
        "collected": collected,
        "analysis_state": {
            "current": "finished",
            "history": stage_history,
        },
        "analysis_completeness": analysis_completeness,
        "collection_quality": collection_quality,
        "missing_artifacts": missing_artifacts,
        "processing_time_ms": processing_time_ms,
        "metadata": {
            "features": features,
            "cta_interaction": artifacts.cta_interaction,
            "network_event_count": len(artifacts.network_events),
            "resource_budget": (artifacts.raw_response or {}).get("resource_budget", {}),
            "isolation_mode": settings.isolation_mode,
            "execution": runner.last_execution,
            "analysis_completeness": analysis_completeness,
            "collection_quality": collection_quality,
            "missing_artifacts": missing_artifacts,
            "analysis_state": {
                "current": "finished",
                "history": stage_history,
            },
        },
    }
    stage("analysis_finished", completeness=analysis_completeness, quality=collection_quality)

    if callback_url:
        try:
            stage("callbacking_started")
            assert_callback_url_safe(
                callback_url,
                allow_private=settings.allow_private_callback_urls,
                allowlist_csv=settings.callback_allowlist,
            )
            httpx.post(callback_url, json=result, timeout=10)
            stage("callbacking_succeeded")
            log_event("callback_done", task_id=task_id, depth=depth, status="ok")
        except Exception:
            stage("callbacking_failed", status="error")
            log_event("callback_done", task_id=task_id, depth=depth, status="error")
            pass

    return result
