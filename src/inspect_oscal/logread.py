"""Read an Inspect eval log once, hash the exact bytes, then parse those bytes."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Literal
from urllib.parse import unquote, urlsplit

from inspect_ai.log import EvalLog, read_eval_log

from .redact import redact, secrets_in

LogFormat = Literal["eval", "json"]
MAX_LOG_BYTES = 1 << 30  # 1 GiB; the whole log is held in memory
ABNORMAL_REASONS = frozenset({"scoring_failed", "grader_failed"})


class LogReadError(Exception):
    """The log could not be read or has an unsupported extension. Messages are redacted."""

    def __init__(self, message: str) -> None:
        super().__init__(redact(message))


@dataclass(frozen=True)
class LogEvidence:
    """A parsed log. ``href`` and ``file_name`` are already sanitised for output."""

    file_name: str
    href: str
    sha256: str
    size: int
    log_format: LogFormat
    log: EvalLog
    abnormal_scores: int | None
    modified: float | None = None


def _detect_format(name: str) -> LogFormat:
    lowered = name.lower()
    if lowered.endswith(".eval"):
        return "eval"
    if lowered.endswith(".json"):
        return "json"
    raise LogReadError(f"{name}: unsupported extension (expected .eval or .json)")


def clean_source(source: str) -> tuple[str, str, str]:
    """Return ``(fetch_target, file_name, href)`` for an input.

    The href never carries userinfo, query, fragment or an absolute local path: local files and
    ``file://`` URLs give a bare file name; other URLs keep scheme, host and path only.
    """
    if "://" not in source:
        name = Path(source).name
        return source, name, name
    parts = urlsplit(source)
    name = PurePosixPath(unquote(parts.path)).name
    if parts.scheme == "file":
        return unquote(parts.path), name, name
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return source, name, f"{parts.scheme}://{host}{parts.path}"


def clean_base_url(base: str) -> str:
    """Sanitise ``--evidence-base-url``: a relative label or a URL, never a local absolute path."""
    if base.startswith(("/", "~")) or "\\" in base or ".." in PurePosixPath(base).parts:
        raise LogReadError("evidence base must be a relative label or a URL, not a local path")
    if "://" not in base:
        return base.rstrip("/")
    parts = urlsplit(base)
    if parts.scheme == "file":
        raise LogReadError("evidence base must not be a file:// URL")
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return f"{parts.scheme}://{host}{parts.path}".rstrip("/")


def _fetch(target: str, max_bytes: int) -> bytes:
    if "://" in target:
        import fsspec

        with fsspec.open(target, "rb") as handle:
            data: bytes = handle.read(max_bytes + 1)
    else:
        path = Path(target)
        if path.stat().st_size > max_bytes:
            raise LogReadError(f"{path.name}: larger than the {max_bytes} byte limit")
        data = path.read_bytes()
    if len(data) > max_bytes:
        raise LogReadError(f"log is larger than the {max_bytes} byte limit")
    return data


def count_abnormal_scores(log: EvalLog) -> int:
    """Count sample scores whose reason says the scorer or grader failed. Counts only."""
    total = 0
    for sample in log.samples or []:
        for score in (sample.scores or {}).values():
            if getattr(score, "reason", None) in ABNORMAL_REASONS:
                total += 1
    return total


def read_log(
    source: str | Path, *, samples: bool = True, max_bytes: int = MAX_LOG_BYTES
) -> LogEvidence:
    """Read ``source``, record SHA-256 of the bytes parsed, and parse it.

    With ``samples=True`` (default) samples are read to count abnormal scores (counts only).
    The whole log is read into memory; ``max_bytes`` caps that.
    """
    target, name, href = clean_source(str(source))
    secrets = secrets_in(str(source))
    fmt = _detect_format(name)
    try:
        data = _fetch(target, max_bytes)
    except LogReadError:
        raise
    except OSError as exc:
        text = redact(exc.strerror or type(exc).__name__, secrets)
        raise LogReadError(f"{name}: {text}") from None
    except Exception as exc:
        text = redact(str(exc), secrets)
        raise LogReadError(f"{name}: could not read ({type(exc).__name__}: {text})") from None
    digest = hashlib.sha256(data).hexdigest()
    try:
        log = read_eval_log(BytesIO(data), header_only=not samples, format=fmt)
    except Exception as exc:
        text = redact(str(exc), secrets)
        raise LogReadError(f"{name}: not a readable Inspect log ({text})") from None
    abnormal = count_abnormal_scores(log) if samples else None
    modified = Path(target).stat().st_mtime if "://" not in target else None
    return LogEvidence(name, href, digest, len(data), fmt, log, abnormal, modified)
