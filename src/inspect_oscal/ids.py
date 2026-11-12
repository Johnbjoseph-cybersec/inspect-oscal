"""Deterministic identifiers and the clock."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

from .constants import UUID_NAMESPACE


def stable_uuid(*parts: str) -> str:
    """uuid5 over the parts, so equal inputs always give equal ids."""
    return str(uuid.uuid5(UUID_NAMESPACE, "\x1f".join(parts)))


def to_oscal_time(value: str) -> str:
    """Normalise an ISO 8601 string to UTC ``YYYY-MM-DDTHH:MM:SSZ``."""
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_now(now: str | None = None) -> str:
    """``now`` argument, else ``SOURCE_DATE_EPOCH``, else the wall clock."""
    if now:
        return to_oscal_time(now)
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        return datetime.fromtimestamp(int(epoch), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
