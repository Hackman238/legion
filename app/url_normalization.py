from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse, urlunparse


_HTTP_SCHEMES = {"http", "https"}
_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
}


def normalize_discovered_url(value: Any) -> str:
    text = str(value or "").strip()
    if not text or "://" not in text:
        return ""

    text = text.rstrip(".,;)]}>\"'")
    scheme_marker = text.find("://")
    if scheme_marker > 0:
        prefix = text[:scheme_marker + 3]
        suffix = text[scheme_marker + 3:].rstrip("/:")
        text = f"{prefix}{suffix}"

    try:
        parsed = urlparse(text)
    except Exception:
        return ""

    scheme = str(parsed.scheme or "").strip().lower()
    if scheme not in _HTTP_SCHEMES:
        return ""

    hostname = str(parsed.hostname or "").strip().lower()
    if not hostname:
        return ""

    try:
        port = parsed.port
    except ValueError:
        return ""

    if port == _DEFAULT_PORTS.get(scheme):
        port = None

    rendered_host = hostname
    if ":" in hostname and not hostname.startswith("["):
        rendered_host = f"[{hostname}]"
    netloc = rendered_host if port is None else f"{rendered_host}:{int(port)}"

    path = str(parsed.path or "")
    if path:
        path = re.sub(r"/{2,}", "/", path)
        path = path.rstrip("/:").strip()
        if path == "/":
            path = ""
        elif path and not path.startswith("/"):
            path = f"/{path}"

    query = str(parsed.query or "").strip()
    return urlunparse((scheme, netloc, path, "", query, ""))
