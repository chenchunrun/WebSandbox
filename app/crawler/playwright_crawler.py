from __future__ import annotations

import asyncio
import inspect
import re
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from playwright.async_api import Browser, BrowserContext, Page, async_playwright

from app.core.config import get_settings
from app.storage import ArtifactStore

settings = get_settings()


@dataclass
class CrawlArtifacts:
    raw_response: dict
    final_url: str
    redirect_chain: list[str]
    ssl: dict
    dom_html: str
    desktop_screenshot_path: str | None
    mobile_screenshot_path: str | None
    network_events: list[dict]
    cta_interaction: dict
    processing_time_ms: int

    def to_dict(self) -> dict:
        return {
            "raw_response": self.raw_response,
            "final_url": self.final_url,
            "redirect_chain": self.redirect_chain,
            "ssl": self.ssl,
            "dom_html": self.dom_html,
            "desktop_screenshot_path": self.desktop_screenshot_path,
            "mobile_screenshot_path": self.mobile_screenshot_path,
            "network_events": self.network_events,
            "cta_interaction": self.cta_interaction,
            "processing_time_ms": self.processing_time_ms,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "CrawlArtifacts":
        return cls(
            raw_response=payload.get("raw_response", {}),
            final_url=payload.get("final_url", ""),
            redirect_chain=payload.get("redirect_chain", []),
            ssl=payload.get("ssl", {}),
            dom_html=payload.get("dom_html", ""),
            desktop_screenshot_path=payload.get("desktop_screenshot_path"),
            mobile_screenshot_path=payload.get("mobile_screenshot_path"),
            network_events=payload.get("network_events", []),
            cta_interaction=payload.get("cta_interaction", {}),
            processing_time_ms=int(payload.get("processing_time_ms", 0)),
        )


SUSPICIOUS_KEYWORDS = [
    "verify",
    "frozen",
    "refund",
    "password",
    "账户",
    "冻结",
    "验证码",
    "退款",
]


def _build_redirect_chain(response) -> list[str]:
    chain = []
    request = response.request
    while request:
        chain.append(request.url)
        request = request.redirected_from
    chain.reverse()
    return chain


def _is_download_like(url: str) -> bool:
    lowered = url.lower()
    return bool(re.search(r"\.(exe|msi|dmg|zip|rar|7z|apk|iso|pdf)(\?|$)", lowered))


async def _capture_mobile(browser: Browser, target_url: str) -> bytes:
    context = await browser.new_context(viewport={"width": 390, "height": 844}, is_mobile=True)
    page = await context.new_page()
    try:
        await page.goto(target_url, wait_until="domcontentloaded", timeout=10000)
        await page.wait_for_timeout(1200)
        try:
            return await page.screenshot(type="png", full_page=True, timeout=15000)
        except Exception:
            return await page.screenshot(type="png", full_page=False, timeout=10000)
    finally:
        await context.close()


async def _find_and_click_cta(page: Page) -> dict:
    candidates = page.locator(
        "a:visible, button:visible, input[type='button']:visible, input[type='submit']:visible"
    )
    count = min(await candidates.count(), 8)

    for idx in range(count):
        handle = candidates.nth(idx)
        text = (await handle.inner_text() if await handle.is_visible() else "").strip().lower()
        if not text:
            text = ((await handle.get_attribute("value")) or "").strip().lower()
        if any(k in text for k in ["login", "verify", "continue", "立即", "登录", "验证", "领取"]):
            before = page.url
            try:
                await handle.click(timeout=2000, no_wait_after=True)
                await page.wait_for_timeout(1200)
                return {
                    "clicked": text[:80] or "cta",
                    "before_url": before,
                    "after_url": page.url,
                    "redirected": page.url != before,
                }
            except Exception as exc:
                return {"clicked": text[:80], "error": str(exc), "redirected": False}
    return {"clicked": None, "redirected": False}


async def crawl_url(url: str, depth: str, task_id: str, timeout_seconds: int | None = None) -> CrawlArtifacts:
    started_at = time.perf_counter()
    store = ArtifactStore()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context: BrowserContext = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            java_script_enabled=True,
            accept_downloads=False,
            ignore_https_errors=True,
        )

        network_events: list[dict] = []
        network_events_truncated = False
        page: Page = await context.new_page()

        async def route_handler(route):
            req = route.request
            if _is_download_like(req.url):
                await route.abort()
                return
            if req.method.upper() == "POST" and req.resource_type == "document":
                await route.abort()
                return
            await route.continue_()

        await page.route("**/*", route_handler)

        def on_response(resp):
            nonlocal network_events_truncated
            resource_type = resp.request.resource_type
            if resource_type in {"xhr", "fetch"}:
                if len(network_events) >= settings.max_network_events:
                    network_events_truncated = True
                    return
                network_events.append(
                    {
                        "url": resp.url,
                        "method": resp.request.method,
                        "status": resp.status,
                        "resource_type": resource_type,
                    }
                )

        page.on("response", on_response)

        effective_timeout_seconds = max(5, int(timeout_seconds or settings.crawl_timeout_seconds))
        response = await page.goto(
            url,
            wait_until="domcontentloaded",
            timeout=effective_timeout_seconds * 1000,
        )

        await page.wait_for_timeout(1800)
        html = await page.content()
        dom_truncated = False
        if len(html) > settings.max_dom_chars:
            html = html[: settings.max_dom_chars]
            dom_truncated = True

        desktop_s3: str | None = None
        try:
            try:
                desktop_png = await page.screenshot(type="png", full_page=True, timeout=15000)
            except Exception:
                desktop_png = await page.screenshot(type="png", full_page=False, timeout=10000)
            desktop_s3 = store.upload_bytes(f"{task_id}/desktop.png", desktop_png, "image/png")
        except Exception:
            desktop_s3 = None

        mobile_s3: str | None = None
        try:
            mobile_png = await _capture_mobile(browser, page.url)
            mobile_s3 = store.upload_bytes(f"{task_id}/mobile.png", mobile_png, "image/png")
        except Exception:
            mobile_s3 = None

        cta_interaction = {"clicked": None, "redirected": False}
        if depth == "deep" or any(k in html.lower() for k in SUSPICIOUS_KEYWORDS):
            cta_interaction = await _find_and_click_cta(page)

        raw_headers = dict(response.headers) if response else {}
        ssl_info = None
        if response:
            ssl_raw = response.security_details()
            if inspect.isawaitable(ssl_raw):
                ssl_info = await ssl_raw
            else:
                ssl_info = ssl_raw
        redirect_chain = _build_redirect_chain(response) if response else [url]
        redirect_chain_truncated = False
        if len(redirect_chain) > settings.max_redirect_chain:
            redirect_chain = redirect_chain[: settings.max_redirect_chain]
            redirect_chain_truncated = True

        raw_response = {
            "status": response.status if response else None,
            "headers": raw_headers,
            "url": response.url if response else url,
            "resource_budget": {
                "dom_truncated": dom_truncated,
                "network_events_truncated": network_events_truncated,
                "redirect_chain_truncated": redirect_chain_truncated,
            },
        }

        await context.close()
        await browser.close()

    elapsed_ms = int((time.perf_counter() - started_at) * 1000)
    return CrawlArtifacts(
        raw_response=raw_response,
        final_url=urlparse(raw_response["url"]).geturl(),
        redirect_chain=redirect_chain,
        ssl=ssl_info or {},
        dom_html=html,
        desktop_screenshot_path=desktop_s3,
        mobile_screenshot_path=mobile_s3,
        network_events=network_events,
        cta_interaction=cta_interaction,
        processing_time_ms=elapsed_ms,
    )


def crawl_url_sync(url: str, depth: str, task_id: str, timeout_seconds: int | None = None) -> CrawlArtifacts:
    return asyncio.run(crawl_url(url, depth, task_id, timeout_seconds=timeout_seconds))
