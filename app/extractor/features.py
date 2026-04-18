from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from bs4 import BeautifulSoup
import tldextract
import whois


RISK_KEYWORDS = [
    "账户冻结",
    "验证码",
    "退款",
    "立即验证",
    "账号异常",
    "verify account",
    "security alert",
    "refund",
    "wallet",
    "seed phrase",
]

BRANDS = ["taobao", "alipay", "paypal", "wechat", "apple", "microsoft", "amazon", "google", "bank"]


OBFUSCATION_PATTERNS = [
    re.compile(r"eval\(function\(p,a,c,k,e,d\)"),
    re.compile(r"atob\("),
    re.compile(r"String\.fromCharCode"),
    re.compile(r"\b0x[a-f0-9]{6,}\b", re.IGNORECASE),
]


def _extract_domain_age_days(hostname: str) -> int | None:
    try:
        record = whois.whois(hostname)
        created = record.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - created).days)
    except Exception:
        return None


def extract_features(url: str, dom_html: str, ssl: dict, network_events: list[dict]) -> dict:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    ext = tldextract.extract(host)
    root_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else host

    soup = BeautifulSoup(dom_html, "html.parser")
    text = soup.get_text(" ", strip=True)
    title = (soup.title.get_text(strip=True) if soup.title else "").lower()

    domain_age_days = _extract_domain_age_days(host) if host else None

    ssl_issuer = (ssl or {}).get("issuer")
    ssl_subject = (ssl or {}).get("subjectName")
    self_signed = bool(ssl_issuer and ssl_subject and ssl_issuer in ssl_subject)

    scripts = [s.get_text(" ", strip=True) for s in soup.find_all("script") if s.get_text(strip=True)]
    joined_scripts = "\n".join(scripts)
    js_obfuscation_hits = sum(bool(p.search(joined_scripts)) for p in OBFUSCATION_PATTERNS)

    hidden_iframe_count = len(
        [
            f
            for f in soup.find_all("iframe")
            if "display:none" in ((f.get("style") or "").replace(" ", "").lower())
            or f.get("hidden") is not None
        ]
    )

    cross_domain_form_submit = 0
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        if not action:
            continue
        action_host = urlparse(action).hostname
        if action_host and action_host not in host:
            cross_domain_form_submit += 1

    normalized_text = text.lower()
    keyword_hits = [kw for kw in RISK_KEYWORDS if kw.lower() in normalized_text]

    brand_target = None
    for brand in BRANDS:
        if brand in title or brand in normalized_text:
            brand_target = brand
            break
    brand_domain_mismatch = bool(brand_target and brand_target not in root_domain.lower())

    high_risk_xhr = sum(
        1 for ev in network_events if any(k in ev["url"].lower() for k in ["/verify", "/wallet", "/seed", "/otp", "/password"])
    )

    return {
        "domain": host,
        "root_domain": root_domain,
        "domain_age_days": domain_age_days,
        "is_new_domain": bool(domain_age_days is not None and domain_age_days <= 30),
        "self_signed_cert": self_signed,
        "brand_target": brand_target,
        "brand_domain_mismatch": brand_domain_mismatch,
        "js_obfuscation_hits": js_obfuscation_hits,
        "hidden_iframe_count": hidden_iframe_count,
        "cross_domain_form_submit": cross_domain_form_submit,
        "keyword_hits": keyword_hits,
        "keyword_hit_count": len(keyword_hits),
        "high_risk_xhr_count": high_risk_xhr,
        "text_excerpt": text[:3000],
    }
