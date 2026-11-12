"""One shared redaction helper for every message the tool prints or raises."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s'\"<>)\]]+")


def _one(match: re.Match[str]) -> str:
    raw = match.group(0)
    try:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
    except ValueError:
        return f"{raw.split('://', 1)[0]}://[redacted]"
    return f"{parts.scheme}://{host}{parts.path}"


_BARE_USERINFO = re.compile(r"[^\s/@'\"<>:]+:[^\s/@'\"<>]+@")


def secrets_in(source: str) -> list[str]:
    """Literal secret substrings of a source URL: userinfo parts, query and its values, fragment."""
    if "://" not in source:
        return []
    try:
        parts = urlsplit(source)
    except ValueError:
        return []
    found: list[str] = []
    if "@" in parts.netloc:
        userinfo = parts.netloc.rsplit("@", 1)[0]
        found += [userinfo, *userinfo.split(":", 1)]
    found += [parts.query, parts.fragment, *(v for _, v in parse_qsl(parts.query))]
    return sorted({s for s in found if s}, key=len, reverse=True)


def redact(text: str, secrets: list[str] | None = None) -> str:
    """Strip userinfo, query and fragment from URLs, literal ``secrets``, and bare ``user:pw@``."""
    out = _URL.sub(_one, text)
    for secret in secrets or []:
        out = out.replace(secret, "[redacted]")
    return _BARE_USERINFO.sub("[redacted]@", out)
