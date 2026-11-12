from __future__ import annotations

import hashlib
import http.server
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from conftest import make_evidence
from inspect_oscal.logread import (
    LogReadError,
    clean_base_url,
    clean_source,
    count_abnormal_scores,
    read_log,
)
from inspect_oscal.redact import redact


def test_reads_both_formats_and_hashes_bytes(example_logs: list[Path]) -> None:
    for path in example_logs:
        ev = read_log(path, samples=False)
        assert ev.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
        assert ev.size == path.stat().st_size
        assert ev.log_format == path.suffix[1:]
        assert ev.log.eval.task == "cyber_smoke"
        assert ev.log.results is not None
        assert ev.abnormal_scores is None


def test_tampered_byte_changes_hash(tmp_path: Path, example_logs: list[Path]) -> None:
    raw = bytearray(example_logs[1].read_bytes())
    original = read_log(example_logs[1]).sha256
    raw.extend(b" ")  # trailing whitespace keeps JSON parseable
    copy = tmp_path / "copy.json"
    copy.write_bytes(bytes(raw))
    assert read_log(copy).sha256 != original


def test_samples_read_by_default(example_logs: list[Path]) -> None:
    assert read_log(example_logs[0]).abnormal_scores == 0
    assert read_log(example_logs[0], samples=False).abnormal_scores is None


def test_bad_extension_and_garbage(tmp_path: Path) -> None:
    with pytest.raises(LogReadError, match="unsupported"):
        read_log(tmp_path / "x.txt")
    bad = tmp_path / "bad.json"
    bad.write_text("{not a log")
    with pytest.raises(LogReadError, match="not a readable"):
        read_log(bad)
    with pytest.raises(LogReadError):
        read_log(tmp_path / "missing.eval")


def test_href_never_leaks_absolute_paths(tmp_path: Path, example_logs: list[Path]) -> None:
    ev = read_log(example_logs[0])
    assert ev.href == example_logs[0].name
    rel = make_evidence()
    assert rel.href == "cyber_x.eval"


def test_count_abnormal_scores() -> None:
    from inspect_ai.log import EvalSample
    from inspect_ai.scorer import Score

    ev = make_evidence()
    sample = EvalSample(
        id=1,
        epoch=1,
        input="q",
        target="t",
        scores={
            "a": Score(value=0, reason="scoring_failed"),
            "b": Score(value=1),
            "c": Score(value=0, reason="refusal"),
        },
    )
    ev.log.samples = [sample]
    assert count_abnormal_scores(ev.log) == 1


CRED = "bob" + ":" + "hunter2"


@pytest.mark.parametrize(
    ("source", "name", "href"),
    [
        ("/Users/someone/clients/run.eval", "run.eval", "run.eval"),
        ("../../clients/acme/run.eval", "run.eval", "run.eval"),
        ("file:///private/tmp/x/run.eval", "run.eval", "run.eval"),
        (
            "https://" + CRED + "@example.org:8443/logs/run.eval?sig=TOKEN#frag",
            "run.eval",
            "https://example.org:8443/logs/run.eval",
        ),
        ("s3://bucket/logs/run.json?X-Amz-Signature=abc", "run.json", "s3://bucket/logs/run.json"),
    ],
)
def test_sources_are_sanitised(source: str, name: str, href: str) -> None:
    _, got_name, got_href = clean_source(source)
    assert (got_name, got_href) == (name, href)
    for secret in ("hunter2", "TOKEN", "Signature", "/Users", "/private", "file:", ".."):
        assert secret not in got_href
        assert secret not in got_name


@pytest.mark.parametrize("base", ["/abs/path", "~/logs", "file:///x", "../up", "a\\b"])
def test_bad_evidence_base_rejected(base: str) -> None:
    with pytest.raises(LogReadError):
        clean_base_url(base)


def test_evidence_base_sanitised() -> None:
    assert clean_base_url("https://" + CRED + "@h.org/logs/?q=1") == "https://h.org/logs"
    assert clean_base_url("evidence/run-7/") == "evidence/run-7"


def test_size_cap(example_logs: list[Path]) -> None:
    with pytest.raises(LogReadError, match="limit"):
        read_log(example_logs[0], max_bytes=10)


def _serve_404() -> tuple[http.server.HTTPServer, int]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


PASSWORD = "hunter2"
TOKEN = "sig-TOP-SECRET-123"


def test_redact_helper() -> None:
    raw = "failed https://" + CRED + "@h.org:9/a/b.eval?sig=" + TOKEN + "#frag (retry)"
    got = redact(raw)
    assert got == "failed https://h.org:9/a/b.eval (retry)"
    assert redact("no url here") == "no url here"
    assert PASSWORD not in LogReadError(raw).args[0]


def test_failing_credentialed_url_never_shows_password_or_token(tmp_path: Path) -> None:
    server, port = _serve_404()
    try:
        url = f"http://{CRED}@127.0.0.1:{port}/nope.eval?sig={TOKEN}#frag"
        exe = Path(sys.executable).parent / "inspect-oscal"
        run = subprocess.run(
            [str(exe), "convert", url, "-o", str(tmp_path / "o")],
            capture_output=True,
            text=True,
            check=False,
        )
        assert run.returncode == 1
        assert run.stderr.startswith("error:")
        for secret in (PASSWORD, TOKEN, "frag", "bob"):
            assert secret not in run.stderr
            assert secret not in run.stdout
        with pytest.raises(LogReadError) as info:
            read_log(url)
        assert PASSWORD not in str(info.value)
        assert TOKEN not in str(info.value)
    finally:
        server.shutdown()


S3_PW = "pw-S3-SECRET"
S3_SOURCE = f"s3://user:{S3_PW}@bucket/x.eval?X-Amz-Signature=TOK-S3"


def test_scheme_less_credential_in_backend_error_is_scrubbed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A backend (botocore) can echo userinfo without any scheme; it must still be removed."""
    import inspect_oscal.logread as lr

    def boom(target: str, max_bytes: int) -> bytes:
        raise ValueError(f'Invalid bucket name "user:{S3_PW}@bucket" sig=TOK-S3')

    monkeypatch.setattr(lr, "_fetch", boom)
    with pytest.raises(LogReadError) as info:
        read_log(S3_SOURCE)
    msg = str(info.value)
    assert "ValueError" in msg
    for secret in (S3_PW, "TOK-S3", "user:"):
        assert secret not in msg


def test_bare_userinfo_pattern_redacted_without_known_source() -> None:
    assert S3_PW not in redact(f'Invalid bucket name "user:{S3_PW}@bucket"')


def test_s3_credentialed_source_never_leaks_on_cli(tmp_path: Path) -> None:
    exe = Path(sys.executable).parent / "inspect-oscal"
    run = subprocess.run(
        [str(exe), "convert", S3_SOURCE, "-o", str(tmp_path / "o")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 1
    for secret in (S3_PW, "TOK-S3"):
        assert secret not in run.stderr
        assert secret not in run.stdout
