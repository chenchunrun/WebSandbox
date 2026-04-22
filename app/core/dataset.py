from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit, urlunsplit


FEATURE_KEY_COLUMNS = [
    "is_new_domain",
    "self_signed_cert",
    "brand_domain_mismatch",
    "js_obfuscation_hits",
    "hidden_iframe_count",
    "cross_domain_form_submit",
    "keyword_hit_count",
    "high_risk_xhr_count",
    "domain_age_days",
]


def normalize_url(url: str) -> str:
    try:
        p = urlsplit((url or "").strip())
    except Exception:
        return (url or "").strip().lower()
    netloc = p.netloc.lower()
    path = p.path or "/"
    return urlunsplit((p.scheme.lower(), netloc, path, "", ""))


def sample_key(url: str, human_label: str, features: dict) -> str:
    canonical = {
        "url": normalize_url(url),
        "human_label": human_label or "unknown",
        "features": {k: features.get(k) for k in FEATURE_KEY_COLUMNS},
    }
    payload = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def dataset_version(sample_keys: list[str], filters: dict) -> str:
    payload = {
        "filters": filters,
        "sample_keys": sorted(sample_keys),
        "count": len(sample_keys),
    }
    material = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
