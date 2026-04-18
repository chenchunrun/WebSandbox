import html
import ipaddress
import os
from pathlib import Path
import re
import socket
from urllib.parse import urlsplit


ZERO_WIDTH_PATTERN = re.compile(r"[\u200b\u200c\u200d\ufeff]")
CONTROL_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def sanitize_untrusted_text(text: str, max_len: int = 20000) -> str:
    cleaned = html.unescape(text or "")
    cleaned = ZERO_WIDTH_PATTERN.sub("", cleaned)
    cleaned = CONTROL_PATTERN.sub(" ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:max_len]


def _is_non_public_ip(ip_text: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve_host_ips(host: str) -> set[str]:
    ips: set[str] = set()
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except Exception:
        return ips
    for rec in records:
        sockaddr = rec[4]
        if not sockaddr:
            continue
        ip = sockaddr[0]
        if ip:
            ips.add(ip)
    return ips


def assert_public_http_url(url: str, *, allow_private: bool = False, field_name: str = "url") -> None:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise ValueError(f"{field_name} must use http/https")
    if not parts.hostname:
        raise ValueError(f"{field_name} must include hostname")
    host = parts.hostname.strip().lower()
    if not allow_private:
        if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
            raise ValueError(f"{field_name} private/localhost target is not allowed")
        if "." not in host and not host.replace("-", "").isdigit():
            raise ValueError(f"{field_name} single-label host is not allowed")
        try:
            ipaddress.ip_address(host)
            is_ip_literal = True
        except ValueError:
            is_ip_literal = False
        if is_ip_literal and _is_non_public_ip(host):
            raise ValueError(f"{field_name} private IP target is not allowed")
        resolved_ips = _resolve_host_ips(host)
        if any(_is_non_public_ip(ip) for ip in resolved_ips):
            raise ValueError(f"{field_name} resolves to non-public IP")


def assert_callback_url_safe(
    callback_url: str,
    *,
    allow_private: bool = False,
    allowlist_csv: str | None = None,
) -> None:
    assert_public_http_url(callback_url, allow_private=allow_private, field_name="callback_url")
    if not allowlist_csv:
        return
    host = (urlsplit(callback_url).hostname or "").lower()
    if not host:
        raise ValueError("callback_url must include hostname")
    allowed = [item.strip().lower() for item in allowlist_csv.split(",") if item.strip()]
    if not allowed:
        return
    if not any(host == item or host.endswith(f".{item}") for item in allowed):
        raise ValueError("callback_url host is not in allowlist")


def assert_safe_model_artifact_path(path_text: str, *, base_dir: str) -> Path:
    candidate = Path(path_text).expanduser().resolve(strict=False)
    base = Path(base_dir).expanduser().resolve(strict=False)
    try:
        common = Path(os.path.commonpath([str(candidate), str(base)]))
    except Exception as exc:
        raise ValueError("invalid model artifact path") from exc
    if common != base:
        raise ValueError("model artifact path escapes allowed directory")
    return candidate
