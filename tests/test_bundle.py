from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from inspect_oscal import BundleError, convert_logs, load_mapping, validate_bundle
from inspect_oscal.constants import MANIFEST_FILENAME
from inspect_oscal.mapping import MappingError, parse_mapping

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "examples" / "bundle"
NOW = "2026-11-12T12:00:00Z"
THRESHOLDS = ROOT / "examples" / "mapping-with-thresholds.yaml"


def make(
    logs: list[Path],
    out: Path,
    oscal_version: str = "1.2.1",
    evidence_base_url: str | None = None,
    findings: bool = True,
) -> list[Path]:
    b = convert_logs(
        logs,
        out_dir=out,
        mapping=load_mapping(THRESHOLDS),
        now=NOW,
        system_name="Example claims assistant",
        oscal_version=oscal_version,
        evidence_base_url=evidence_base_url,
        findings=findings,
    )
    return b.files


REGEN_ARGS = [
    "convert",
    "examples/logs/2026-11-12T10-49-06-00-00_cyber-smoke_nBUNx2qxeFBX5hEKfxBAE2.eval",
    "examples/logs/2026-11-12T10-49-20-00-00_cyber-smoke_7hCcydFzWkn6yYmqCJN8Bt.json",
    "--mapping",
    "examples/mapping-with-thresholds.yaml",
    "--system-name",
    "Example claims assistant",
    "--now",
    NOW,
]


def test_example_bundle_regenerates_byte_identically_with_documented_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The README command (default flags, no --findings) reproduces examples/bundle."""
    from click.testing import CliRunner

    from inspect_oscal.cli import cli

    monkeypatch.chdir(ROOT)
    out = tmp_path / "out"
    res = CliRunner().invoke(cli, [*REGEN_ARGS, "-o", str(out)])
    assert res.exit_code == 0, res.output
    if os.environ.get("UPDATE_GOLDEN") == "1":
        GOLDEN.mkdir(exist_ok=True)
        for f in out.iterdir():
            (GOLDEN / f.name).write_bytes(f.read_bytes())
    assert sorted(p.name for p in GOLDEN.iterdir()) == sorted(os.listdir(out))
    for name in os.listdir(out):
        assert (out / name).read_bytes() == (GOLDEN / name).read_bytes(), name
    assert "satisfied" not in (GOLDEN / "assessment-results.json").read_text()


def test_example_bundle_validates_as_shipped() -> None:
    report = validate_bundle(GOLDEN)
    assert report.ok, report.errors


def test_findings_example_is_regenerable(tmp_path: Path, example_logs: list[Path]) -> None:
    make(example_logs, tmp_path)
    text = (tmp_path / "assessment-results.json").read_text()
    assert '"satisfied"' in text
    assert validate_bundle(tmp_path).ok


def test_deterministic_and_order_independent(tmp_path: Path, example_logs: list[Path]) -> None:
    make(example_logs, tmp_path / "a")
    make(list(reversed(example_logs)), tmp_path / "b")
    for name in ("assessment-results.json", MANIFEST_FILENAME, "ssp.json"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()


def test_bundle_content(tmp_path: Path, example_logs: list[Path]) -> None:
    make(example_logs, tmp_path)
    ar = json.loads((tmp_path / "assessment-results.json").read_text())["assessment-results"]
    assert ar["metadata"]["oscal-version"] == "1.2.1"
    assert ar["import-ap"]["href"] == "./assessment-plan.json"
    assert len(ar["results"]) == 2
    hashes = {r["rlinks"][0]["hashes"][0]["value"] for r in ar["back-matter"]["resources"]}
    assert len(hashes) == 2 and all(len(h) == 64 for h in hashes)
    states = {f["target"]["status"]["state"] for r in ar["results"] for f in r["findings"]}
    assert states == {"satisfied"}
    assert "/Users/" not in json.dumps(ar)
    assert validate_bundle(tmp_path).ok


def test_oscal_version_override(tmp_path: Path, example_logs: list[Path]) -> None:
    make(example_logs[:1], tmp_path, oscal_version="1.2.0")
    assert '"oscal-version": "1.2.0"' in (tmp_path / "ssp.json").read_text()
    with pytest.raises(BundleError):
        make(example_logs[:1], tmp_path, oscal_version="v1.2")


def test_evidence_base_url(tmp_path: Path, example_logs: list[Path]) -> None:
    make(example_logs[:1], tmp_path, evidence_base_url="https://example.org/logs/")
    ar = json.loads((tmp_path / "assessment-results.json").read_text())["assessment-results"]
    assert ar["back-matter"]["resources"][0]["rlinks"][0]["href"].startswith(
        "https://example.org/logs/"
    )


def test_errors(tmp_path: Path, example_logs: list[Path]) -> None:
    with pytest.raises(BundleError):
        convert_logs([], out_dir=tmp_path)
    nothing = parse_mapping(
        "version: 1\nrules:\n  - id: x\n    match: {any: [{task_glob: ['zzz']}]}\n"
        "    targets: [MEASURE_2.1]\n    observe: {kind: log-facts}\n"
    )
    with pytest.raises(BundleError, match="no log matched"):
        convert_logs(example_logs, out_dir=tmp_path, mapping=nothing)
    bad = parse_mapping(
        "version: 1\nrules:\n  - id: x\n    match: {all: true}\n"
        "    targets: [NOPE_9.9]\n    observe: {kind: log-facts}\n"
    )
    with pytest.raises(MappingError, match=r"NOPE_9\.9"):
        convert_logs(example_logs, out_dir=tmp_path, mapping=bad)


def test_source_date_epoch(
    tmp_path: Path, example_logs: list[Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    convert_logs(example_logs[:1], out_dir=tmp_path, mapping=load_mapping(THRESHOLDS))
    assert "2023-11-14T22:13:20Z" in (tmp_path / "ssp.json").read_text()


def test_default_bundle_has_observations_and_no_findings(
    tmp_path: Path, example_logs: list[Path]
) -> None:
    make(example_logs, tmp_path, findings=False)
    ar = json.loads((tmp_path / "assessment-results.json").read_text())["assessment-results"]
    assert all("findings" not in r for r in ar["results"])
    assert "satisfied" not in (tmp_path / "assessment-results.json").read_text()
    assert validate_bundle(tmp_path).ok


def test_same_log_twice_writes_valid_bundle(tmp_path: Path, example_logs: list[Path]) -> None:
    b = convert_logs(
        [example_logs[0], example_logs[0]],
        out_dir=tmp_path,
        mapping=load_mapping(THRESHOLDS),
        now=NOW,
    )
    assert b.results == 1
    assert any("identical bytes" in w or "same eval_id" in w for w in b.warnings)
    assert validate_bundle(tmp_path).ok


def test_eval_and_json_of_one_run_collapse(tmp_path: Path, example_logs: list[Path]) -> None:
    # The two example logs are separate runs; fabricate a .json export of the first.
    from inspect_ai.log import read_eval_log, write_eval_log

    log = read_eval_log(str(example_logs[0]))
    twin = tmp_path / "twin.json"
    write_eval_log(log, str(twin), format="json")
    b = convert_logs([example_logs[0], twin], out_dir=tmp_path / "o", now=NOW)
    assert b.results == 1
    assert any("same eval_id" in w for w in b.warnings)
    assert validate_bundle(tmp_path / "o").ok


def test_no_paths_or_credentials_in_output(tmp_path: Path, example_logs: list[Path]) -> None:
    b = convert_logs(
        [example_logs[0]], out_dir=tmp_path / "o", now=NOW, evidence_base_url="evidence/run-1/"
    )
    text = "".join(p.read_text() for p in b.files if p.name != "NIST_AI-RMF_v1_catalog.json")
    assert "evidence/run-1/" in text
    for bad in ("/Users/", "/private/", "file://", "?sig", "@"):
        assert bad not in text
    abs_in = tmp_path / "abs"
    abs_in.mkdir()
    copy = abs_in / example_logs[0].name
    copy.write_bytes(example_logs[0].read_bytes())
    b2 = convert_logs([str(copy)], out_dir=tmp_path / "o2", now=NOW)
    text2 = (tmp_path / "o2" / "assessment-results.json").read_text()
    assert str(abs_in) not in text2
    assert b2.results == 1


def test_bad_evidence_base_rejected(tmp_path: Path, example_logs: list[Path]) -> None:
    from inspect_oscal.logread import LogReadError

    with pytest.raises(LogReadError):
        convert_logs([example_logs[0]], out_dir=tmp_path, evidence_base_url="/abs/dir")


def test_overwrite_warns(tmp_path: Path, example_logs: list[Path]) -> None:
    convert_logs([example_logs[0]], out_dir=tmp_path, now=NOW)
    b = convert_logs([example_logs[0]], out_dir=tmp_path, now=NOW)
    assert any("overwriting" in w for w in b.warnings)


def test_integrity_failure_writes_nothing(
    tmp_path: Path, example_logs: list[Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from inspect_oscal import bundle as bundle_mod
    from inspect_oscal.validate import ValidationReport

    monkeypatch.setattr(bundle_mod, "check_integrity", lambda _d: ValidationReport(errors=["boom"]))
    with pytest.raises(BundleError, match="boom"):
        convert_logs([example_logs[0]], out_dir=tmp_path / "o", now=NOW)
    assert not (tmp_path / "o").exists()
