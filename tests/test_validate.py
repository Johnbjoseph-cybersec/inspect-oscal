from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from inspect_oscal import convert_logs, load_mapping, validate_bundle
from inspect_oscal.validate import find_oscal_cli

ROOT = Path(__file__).resolve().parent.parent
THRESHOLDS = ROOT / "examples" / "mapping-with-thresholds.yaml"


@pytest.fixture
def bundle(tmp_path: Path, example_logs: list[Path]) -> Path:
    convert_logs(
        example_logs,
        out_dir=tmp_path,
        mapping=load_mapping(THRESHOLDS),
        now="2026-11-12T12:00:00Z",
        findings=True,
    )
    return tmp_path


def refresh_manifest(bundle: Path) -> None:
    import hashlib

    m = json.loads((bundle / "MANIFEST.json").read_text())
    m["files"] = {n: hashlib.sha256((bundle / n).read_bytes()).hexdigest() for n in m["files"]}
    (bundle / "MANIFEST.json").write_text(json.dumps(m))


def edit(path: Path, fn: Any) -> None:
    doc = json.loads(path.read_text())
    fn(doc)
    path.write_text(json.dumps(doc, indent=2))


def errors(bundle: Path) -> list[str]:
    return validate_bundle(bundle).errors


def test_clean_bundle_is_valid(bundle: Path) -> None:
    report = validate_bundle(bundle)
    assert report.ok, report.errors


def test_tampered_file_flagged_by_manifest(bundle: Path) -> None:
    (bundle / "ssp.json").write_text((bundle / "ssp.json").read_text() + " ")
    assert any("differs from the manifest" in e for e in errors(bundle))


def test_missing_manifest_is_an_error(bundle: Path) -> None:
    (bundle / "MANIFEST.json").unlink()
    assert any("MANIFEST.json: missing" in e for e in errors(bundle))


def test_manifest_traversal_rejected(bundle: Path) -> None:
    m = json.loads((bundle / "MANIFEST.json").read_text())
    m["files"]["../../../etc/hosts"] = "0" * 64
    (bundle / "MANIFEST.json").write_text(json.dumps(m))
    assert any("unexpected path" in e for e in errors(bundle))


def test_manifest_claim_is_accidental_change_only(bundle: Path) -> None:
    checks = validate_bundle(bundle).checks
    assert any("not tamper-proof" in c for c in checks)


def test_malformed_document_is_invalid_not_a_traceback(bundle: Path) -> None:
    def bad(d: dict[str, Any]) -> None:
        del d["assessment-results"]["results"][0]["observations"][0]["uuid"]

    edit(bundle / "assessment-results.json", bad)
    report = validate_bundle(bundle)
    assert not report.ok
    assert any("malformed document" in e or "uuid" in e for e in report.errors)


def test_cli_reports_invalid_with_exit_three_on_malformed(bundle: Path) -> None:
    from click.testing import CliRunner

    from inspect_oscal.cli import cli

    def bad(d: dict[str, Any]) -> None:
        del d["assessment-results"]["results"][0]["observations"][0]["uuid"]

    edit(bundle / "assessment-results.json", bad)
    res = CliRunner().invoke(cli, ["validate", str(bundle)])
    assert res.exit_code == 3
    assert "INVALID" in res.output


def test_honest_task_name_is_not_flagged(tmp_path: Path, example_logs: list[Path]) -> None:
    from conftest import make_evidence
    from inspect_oscal.catalog import load_catalog
    from inspect_oscal.convert import build_results
    from inspect_oscal.mapping import parse_mapping

    m = parse_mapping(
        "version: 1\nrules:\n  - id: f\n    match: {all: true}\n"
        "    targets: [MEASURE_2.1]\n    observe: {kind: log-facts}\n"
    )
    ev = make_evidence(task="non-compliant-cyber", abnormal=0)
    out = build_results([ev], m, load_catalog(), now="2026-11-12T12:00:00Z", oscal_version="1.2.1")
    from inspect_oscal.bundle import _dump

    (tmp_path / "x").mkdir()
    convert_logs(example_logs[:1], out_dir=tmp_path / "x", now="2026-11-12T12:00:00Z")
    (tmp_path / "x" / "assessment-results.json").write_bytes(_dump(out.document))
    refresh_manifest(tmp_path / "x")
    report = validate_bundle(tmp_path / "x")
    assert not any("forbidden wording" in e for e in report.errors)


@pytest.mark.parametrize(
    "word", ["noncompliant", "non-compliant", "certified", "conforms", "passed"]
)
def test_authored_wording_variants_flagged(bundle: Path, word: str) -> None:
    def bad(d: dict[str, Any]) -> None:
        d["assessment-results"]["results"][0]["description"] = f"The system {word}."

    edit(bundle / "assessment-results.json", bad)
    assert any("forbidden wording" in e for e in errors(bundle))


def test_oscal_cli_timeout_reported(bundle: Path, tmp_path: Path) -> None:
    slow = tmp_path / "slow-cli"
    slow.write_text("#!/bin/sh\nsleep 5\n")
    slow.chmod(0o755)
    report = validate_bundle(bundle, use_oscal_cli=True, oscal_cli=slow, timeout=0.5)
    assert any("timed out" in e for e in report.errors)


def test_missing_file_flagged(bundle: Path) -> None:
    (bundle / "profile.json").unlink()
    assert any("profile.json" in e for e in errors(bundle))


def test_wrong_catalog_flagged(bundle: Path) -> None:
    (bundle / "NIST_AI-RMF_v1_catalog.json").write_text("{}")
    assert any("pinned hash" in e for e in errors(bundle))


def drop_manifest(bundle: Path) -> None:
    # Re-write the manifest after an edit so only the intended defect is reported.
    refresh_manifest(bundle)


def test_nonexistent_control_id_caught(bundle: Path) -> None:
    drop_manifest(bundle)

    def bad(d: dict[str, Any]) -> None:
        d["assessment-plan"]["reviewed-controls"]["control-selections"][0][
            "include-controls"
        ].append({"control-id": "NOPE_1.1"})

    edit(bundle / "assessment-plan.json", bad)
    assert any("NOPE_1.1" in e and "does not exist" in e for e in errors(bundle))


def test_nonexistent_target_id_caught(bundle: Path) -> None:
    drop_manifest(bundle)

    def bad(d: dict[str, Any]) -> None:
        d["assessment-results"]["results"][0]["findings"][0]["target"]["target-id"] = "NOPE_9.9_ovw"

    edit(bundle / "assessment-results.json", bad)
    assert any("NOPE_9.9_ovw" in e for e in errors(bundle))


def test_unresolved_references_caught(bundle: Path) -> None:
    drop_manifest(bundle)

    def bad(d: dict[str, Any]) -> None:
        r = d["assessment-results"]["results"][0]
        r["observations"][0]["subjects"][0]["subject-uuid"] = "00000000-0000-4000-8000-000000000000"
        r["observations"][0]["relevant-evidence"][0]["href"] = (
            "#00000000-0000-4000-8000-000000000001"
        )
        r["findings"][0]["related-observations"][0]["observation-uuid"] = (
            "00000000-0000-4000-8000-000000000002"
        )

    edit(bundle / "assessment-results.json", bad)
    msgs = errors(bundle)
    assert any("subject-uuid does not resolve" in e for e in msgs)
    assert any("unresolved" in e for e in msgs)
    assert any("related observation does not resolve" in e for e in msgs)


def test_missing_hash_caught(bundle: Path) -> None:
    drop_manifest(bundle)

    def bad(d: dict[str, Any]) -> None:
        d["assessment-results"]["back-matter"]["resources"][0]["rlinks"][0]["hashes"] = []

    edit(bundle / "assessment-results.json", bad)
    assert any("no valid SHA-256" in e for e in errors(bundle))


def test_duplicate_uuid_caught(bundle: Path) -> None:
    drop_manifest(bundle)

    def bad(d: dict[str, Any]) -> None:
        d["profile"]["uuid"] = json.loads((bundle / "ssp.json").read_text())[
            "system-security-plan"
        ]["uuid"]

    edit(bundle / "profile.json", bad)
    assert any("not unique" in e for e in errors(bundle))


def test_honesty_lint(bundle: Path) -> None:
    drop_manifest(bundle)

    def bad(d: dict[str, Any]) -> None:
        f = d["assessment-results"]["results"][0]["findings"][0]
        f["description"] = "The system is compliant."
        for o in d["assessment-results"]["results"][0]["observations"]:
            o["props"] = [p for p in o["props"] if p["name"] != "mapping-statement"]
        d["assessment-results"]["metadata"]["props"] = []

    edit(bundle / "assessment-results.json", bad)
    msgs = errors(bundle)
    assert any("forbidden wording" in e for e in msgs)
    assert any("partial-evidence" in e for e in msgs)
    assert any("mapping-statement" in e for e in msgs)


def test_oscal_cli_validates_bundle(bundle: Path, oscal_cli: str) -> None:
    report = validate_bundle(bundle, use_oscal_cli=True, oscal_cli=oscal_cli)
    assert report.ok, report.errors
    assert sum("oscal-cli" in c and "valid" in c for c in report.checks) == 4


def test_oscal_cli_rejects_negative(bundle: Path, oscal_cli: str) -> None:
    drop_manifest(bundle)

    def bad(d: dict[str, Any]) -> None:
        d["assessment-results"]["results"][0]["findings"][0]["target"]["status"]["state"] = "maybe"

    edit(bundle / "assessment-results.json", bad)
    report = validate_bundle(bundle, use_oscal_cli=True, oscal_cli=oscal_cli)
    assert any("oscal-cli rejected assessment-results.json" in e for e in report.errors)


def test_oscal_cli_default_mapping_bundle(
    tmp_path: Path, example_logs: list[Path], oscal_cli: str
) -> None:
    convert_logs(example_logs, out_dir=tmp_path, now="2026-11-12T12:00:00Z")
    assert validate_bundle(tmp_path, use_oscal_cli=True, oscal_cli=oscal_cli).ok


def test_missing_cli_reported(bundle: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INSPECT_OSCAL_CLI", raising=False)
    monkeypatch.setenv("PATH", "/nonexistent")
    assert find_oscal_cli() is None
    assert any("not found" in e for e in validate_bundle(bundle, use_oscal_cli=True).errors)
    assert shutil.which("oscal-cli") is None


def test_oscal_cli_validates_shipped_example_bundle(oscal_cli: str) -> None:
    report = validate_bundle(ROOT / "examples" / "bundle", use_oscal_cli=True, oscal_cli=oscal_cli)
    assert report.ok, report.errors
