from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from inspect_oscal.cli import cli, main

ROOT = Path(__file__).resolve().parent.parent
THRESHOLDS = ROOT / "examples" / "mapping-with-thresholds.yaml"


def test_convert_validate_roundtrip(tmp_path: Path, example_logs: list[Path]) -> None:
    r = CliRunner()
    out = tmp_path / "o"
    res = r.invoke(
        cli,
        [
            "convert",
            *map(str, example_logs),
            "-o",
            str(out),
            "--mapping",
            str(THRESHOLDS),
            "--findings",
            "--now",
            "2026-11-12T12:00:00Z",
        ],
    )
    assert res.exit_code == 0, res.output
    v = r.invoke(cli, ["validate", str(out), "--json"])
    assert v.exit_code == 0, v.output
    assert json.loads(v.output[v.output.index("{") :])["ok"] is True


def test_strict_exit_code_two(tmp_path: Path, example_logs: list[Path]) -> None:
    r = CliRunner()
    # default mapping: safety rule etc. do not match; cyber matches. Force a warning with --samples
    # off by using a mapping whose metric is absent.
    m = tmp_path / "m.yaml"
    m.write_text(
        "version: 1\nrules:\n  - id: a\n    match: {all: true}\n"
        "    targets: [MEASURE_2.7]\n    scores: [{metric: f1}]\n"
        "  - id: b\n    match: {all: true}\n    targets: [MEASURE_2.1]\n"
        "    observe: {kind: log-facts}\n"
    )
    ok = r.invoke(
        cli, ["convert", str(example_logs[0]), "-o", str(tmp_path / "x"), "--mapping", str(m)]
    )
    assert ok.exit_code == 0
    strict = r.invoke(
        cli,
        [
            "convert",
            str(example_logs[0]),
            "-o",
            str(tmp_path / "y"),
            "--mapping",
            str(m),
            "--strict",
        ],
    )
    assert strict.exit_code == 2


def test_validate_failure_exit_three(tmp_path: Path, example_logs: list[Path]) -> None:
    r = CliRunner()
    out = tmp_path / "o"
    r.invoke(cli, ["convert", str(example_logs[0]), "-o", str(out)])
    (out / "ssp.json").write_text("{}")
    assert r.invoke(cli, ["validate", str(out)]).exit_code == 3


def test_mapping_and_catalog_commands(tmp_path: Path) -> None:
    r = CliRunner()
    init = r.invoke(cli, ["mapping", "init"])
    assert init.exit_code == 0 and "NOT A NIST MAPPING" in init.output
    f = tmp_path / "m.yaml"
    f.write_text(init.output)
    assert r.invoke(cli, ["mapping", "check", str(f)]).exit_code == 0
    f.write_text(init.output.replace("MEASURE_2.7", "NOPE_1.1"))
    assert r.invoke(cli, ["mapping", "check", str(f)]).exit_code == 1
    info = r.invoke(cli, ["catalog", "info"])
    assert "09de09ecd15f861c4ec05aa192872dc2faafc3bef41c4bc57e19247e84f92545" in info.output
    assert r.invoke(cli, ["catalog", "verify"]).exit_code == 0
    assert r.invoke(cli, ["--version"]).exit_code == 0


def test_main_maps_errors_to_exit_one(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["inspect-oscal", "convert", str(tmp_path / "no.eval"), "-o", str(tmp_path / "o")],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    monkeypatch.setattr(sys, "argv", ["inspect-oscal", "bogus"])
    with pytest.raises(SystemExit) as exc2:
        main()
    assert exc2.value.code == 1


def test_real_mockllm_log_end_to_end(real_mockllm_log: Path, tmp_path: Path) -> None:
    """A log produced by `inspect eval --model mockllm/model`, through the installed script."""
    script = Path(sys.executable).parent / "inspect-oscal"
    assert script.exists()
    out = tmp_path / "out"
    run = subprocess.run(
        [
            str(script),
            "convert",
            str(real_mockllm_log),
            "-o",
            str(out),
            "--mapping",
            str(THRESHOLDS),
            "--findings",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stderr
    ar = json.loads((out / "assessment-results.json").read_text())["assessment-results"]
    (result,) = ar["results"]
    assert result["title"] == "cyber_smoke on mockllm/model"
    values = {p["name"]: p["value"] for o in result["observations"] for p in o["props"]}
    assert values["metric-value"] in {"1.0", "0.0"} or float(values["metric-value"]) >= 0
    (finding,) = result["findings"]
    assert finding["target"]["status"]["state"] == "satisfied"
    check = subprocess.run(
        [str(script), "validate", str(out)], capture_output=True, text=True, check=False
    )
    assert check.returncode == 0, check.stdout


def test_real_mockllm_log_default_is_observations_only(
    real_mockllm_log: Path, tmp_path: Path
) -> None:
    script = Path(sys.executable).parent / "inspect-oscal"
    out = tmp_path / "out"
    run = subprocess.run(
        [
            str(script),
            "convert",
            str(real_mockllm_log),
            "-o",
            str(out),
            "--mapping",
            str(THRESHOLDS),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stderr
    text = (out / "assessment-results.json").read_text()
    ar = json.loads(text)["assessment-results"]
    assert "findings" not in ar["results"][0]
    assert '"threshold-result"' in text
    assert "/Users/" not in text
    assert str(real_mockllm_log.parent) not in text
