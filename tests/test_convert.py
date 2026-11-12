from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pytest

from conftest import make_evidence
from inspect_oscal.catalog import load_catalog
from inspect_oscal.constants import NS, PARTIAL_EVIDENCE
from inspect_oscal.convert import build_results
from inspect_oscal.logread import LogEvidence
from inspect_oscal.mapping import Mapping, parse_mapping

TEMPLATE = """
version: 1
rules:
  - id: sec
    match: {any: [{task_glob: ['*cyber*']}]}
    targets: [MEASURE_2.7]
    require_complete: %s
    scores:
      - {scorer: "*", metric: accuracy%s}
"""


def mapping(
    threshold: str = ", threshold: {op: '>=', value: 0.7}", complete: str = "true"
) -> Mapping:
    return parse_mapping(TEMPLATE % (complete, threshold))


def run(ev: LogEvidence, m: Mapping, findings: bool = True) -> tuple[dict[str, Any], list[str]]:
    out = build_results(
        [ev], m, load_catalog(), now="2026-11-12T12:00:00Z", oscal_version="1.2.1",
        findings=findings,
    )  # fmt: skip
    return out.document["assessment-results"], out.warnings


def findings(doc: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in doc["results"]:
        out += r.get("findings", [])
    return out


@pytest.mark.parametrize(
    ("value", "state"),
    [(0.9, "satisfied"), (0.7, "satisfied"), (0.69, "not-satisfied"), (0.0, "not-satisfied")],
)
def test_threshold_truth_table(value: float, state: str) -> None:
    doc, _ = run(make_evidence(value=value), mapping())
    (f,) = findings(doc)
    assert f["target"]["status"]["state"] == state
    assert f["target"]["target-id"] == "MEASURE_2.7_ovw"
    if state == "satisfied":
        assert PARTIAL_EVIDENCE in f["description"]
    assert f["related-observations"]


def test_nan_metric_gives_no_finding() -> None:
    doc, warns = run(make_evidence(value=math.nan), mapping())
    assert findings(doc) == []
    assert any("NaN" in w for w in warns)
    assert doc["results"][0]["observations"]


def test_absent_metric_gives_no_finding() -> None:
    doc, warns = run(make_evidence(metric="f1"), mapping())
    assert findings(doc) == []
    assert any("found no metric" in w for w in warns)


def test_require_complete_with_unscored() -> None:
    doc, warns = run(make_evidence(unscored=2), mapping())
    assert findings(doc) == []
    assert any("were scored" in w for w in warns)
    doc2, _ = run(make_evidence(unscored=2), mapping(complete="false"))
    assert len(findings(doc2)) == 1


@pytest.mark.parametrize("status", ["error", "cancelled", "started"])
def test_incomplete_status_gives_no_finding(status: str) -> None:
    doc, warns = run(make_evidence(status=status, value=0.99), mapping())
    assert findings(doc) == []
    assert any(status in w for w in warns)
    props = {p["name"]: p["value"] for p in doc["results"][0]["observations"][0]["props"]}
    assert props["eval-status"] == status


def test_success_status() -> None:
    doc, _ = run(make_evidence(), mapping())
    assert len(findings(doc)) == 1


def test_no_threshold_means_observations_only() -> None:
    doc, _ = run(make_evidence(), mapping(threshold=""))
    assert findings(doc) == []
    (obs,) = doc["results"][0]["observations"]
    props = {p["name"]: p["value"] for p in obs["props"]}
    assert props["metric-value"] == "0.9"
    assert props["mapping-statement"] == "derived"
    assert all(p["ns"] == NS for p in obs["props"])


def test_abnormal_scores_withhold_finding() -> None:
    doc, warns = run(make_evidence(abnormal=3), mapping())
    assert findings(doc) == []
    assert any("abnormal" in w for w in warns)


def test_unmatched_log_is_skipped_with_warning() -> None:
    out = build_results(
        [make_evidence(task="poetry")],
        mapping(),
        load_catalog(),
        now="2026-11-12T12:00:00Z",
        oscal_version="1.2.1",
    )
    assert out.converted == 0
    assert any("no mapping rule matched" in w for w in out.warnings)


def test_no_results_log_still_gives_facts() -> None:
    m = parse_mapping(
        "version: 1\nrules:\n  - id: f\n    match: {all: true}\n"
        "    targets: [MEASURE_2.1]\n    observe: {kind: log-facts}\n"
    )
    doc, _ = run(make_evidence(with_results=False), m)
    assert len(doc["results"][0]["observations"]) == 1


def test_uuids_stable_when_log_order_changes() -> None:
    a, b = make_evidence(eval_id="aaa"), make_evidence(eval_id="bbb", task="cyber_y")
    m = mapping()
    one = build_results(
        [a, b], m, load_catalog(), now="2026-11-12T12:00:00Z", oscal_version="1.2.1"
    )
    two = build_results(
        [b, a], m, load_catalog(), now="2026-11-12T12:00:00Z", oscal_version="1.2.1"
    )
    assert json.dumps(one.document) == json.dumps(two.document)


def test_no_log_content_recorded(tmp_path: Path) -> None:
    doc, _ = run(make_evidence(), mapping())
    assert "Default output" not in json.dumps(doc)


def obs_props(doc: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p["value"] for p in doc["results"][0]["observations"][0]["props"]}


def test_no_findings_by_default_but_threshold_result_always_recorded() -> None:
    doc, _ = run(make_evidence(value=0.9), mapping(), findings=False)
    assert findings(doc) == []
    props = obs_props(doc)
    assert props["threshold-result"] == "met"
    assert props["threshold"] == ">= 0.7"
    doc2, _ = run(make_evidence(value=0.5), mapping(), findings=False)
    assert obs_props(doc2)["threshold-result"] == "missed"
    meta = {p["name"]: p["value"] for p in doc["metadata"]["props"]}
    assert meta["findings-included"] == "false"


def test_finding_carries_non_verdict_fields() -> None:
    doc, _ = run(make_evidence(value=0.5), mapping())
    (f,) = findings(doc)
    props = {p["name"]: p["value"] for p in f["props"]}
    assert props["threshold-result"] == "missed"
    assert "not a determination" in props["status-meaning"]
    assert "completed 10 of 10 samples" in f["description"]


def test_not_evaluated_threshold_result() -> None:
    doc, _ = run(make_evidence(status="error"), mapping(), findings=False)
    props = obs_props(doc)
    assert props["threshold-result"] == "not-evaluated"
    assert "error" in props["threshold-note"]


@pytest.mark.parametrize(
    ("kw", "word"),
    [
        ({"completed": 1, "total": 2}, "only 1 of 2"),
        ({"scored": None}, "scored sample count is missing"),
        ({"scored": 9}, "9 of 10 samples were scored"),
        ({"with_results": False}, "metric not found"),
    ],
)
def test_require_complete_withholds(kw: dict[str, Any], word: str) -> None:
    doc, warns = run(make_evidence(**kw), mapping())
    assert findings(doc) == []
    assert any(word in w for w in warns)


def test_require_complete_missing_counts() -> None:
    ev = make_evidence()
    assert ev.log.results is not None
    ev.log.results.total_samples = None  # type: ignore[assignment]
    doc, warns = run(ev, mapping())
    assert findings(doc) == []
    assert any("sample counts are missing" in w for w in warns)


def test_completed_less_than_total_warns_with_or_without_flag() -> None:
    _, warns = run(make_evidence(completed=1, total=2), mapping(complete="false"))
    assert any("only 1 of 2 samples completed" in w for w in warns)


def test_partial_completion_withholds_finding_even_with_flag_off() -> None:
    doc, warns = run(make_evidence(completed=1, total=2), mapping(complete="false"))
    assert findings(doc) == []
    assert any("no finding" in w and "only 1 of 2" in w for w in warns)
    assert obs_props(doc)["threshold-result"] == "not-evaluated"


def test_missing_counts_withhold_even_with_flag_off() -> None:
    ev = make_evidence()
    assert ev.log.results is not None
    ev.log.results.completed_samples = None  # type: ignore[assignment]
    doc, warns = run(ev, mapping(complete="false"))
    assert findings(doc) == []
    assert any("sample counts are missing" in w for w in warns)


def test_require_complete_defaults_to_true() -> None:
    m = parse_mapping(
        "version: 1\nrules:\n  - id: s\n    match: {all: true}\n    targets: [MEASURE_2.7]\n"
        "    scores: [{metric: accuracy, threshold: {op: '>=', value: 0.7}}]\n"
    )
    assert m.rules[0].require_complete is True
    doc, _ = run(make_evidence(unscored=2), m)
    assert findings(doc) == []


def test_samples_not_read_is_flagged() -> None:
    ev = make_evidence()
    _, warns = run(ev, mapping())
    assert any("abnormal scores were not checked" in w for w in warns)
    assert obs_props(run(ev, mapping())[0])["abnormal-scores-checked"] == "false"
    ok, w2 = run(make_evidence(abnormal=0), mapping())
    assert obs_props(ok)["abnormal-scores-checked"] == "true"
    assert not any("not checked" in w for w in w2)


def test_all_thresholded_metrics_must_pass_and_reducer_is_named() -> None:
    m = parse_mapping(TEMPLATE % ("false", ", threshold: {op: '>=', value: 0.7}"))
    doc, _ = run(make_evidence(value=0.2, reducer="max"), m)
    (f,) = findings(doc)
    assert "includes[max].accuracy" in f["description"]
    assert "All thresholded metrics must meet" in f["description"]


def test_same_run_twice_gives_no_duplicate_uuids() -> None:
    a = make_evidence()
    b = make_evidence()
    out = build_results(
        [a, b], mapping(), load_catalog(), now="2026-11-12T12:00:00Z",
        oscal_version="1.2.1", findings=True,
    )  # fmt: skip
    assert out.converted == 1
    assert any("identical bytes" in w or "same eval_id" in w for w in out.warnings)
    seen: list[str] = []
    _collect(out.document, seen)
    assert len(seen) == len(set(seen))


def test_eval_and_json_of_same_run_are_deduplicated() -> None:
    eval_log = make_evidence(eval_id="same", sha="a" * 64)
    json_log = make_evidence(eval_id="same", sha="b" * 64)
    object.__setattr__(json_log, "log_format", "json")
    for order in ([eval_log, json_log], [json_log, eval_log]):
        out = build_results(
            order, mapping(), load_catalog(), now="2026-11-12T12:00:00Z",
            oscal_version="1.2.1",
        )  # fmt: skip
        assert out.converted == 1
        assert any("same eval_id" in w for w in out.warnings)
        res = out.document["assessment-results"]["back-matter"]["resources"]
        assert res[0]["rlinks"][0]["hashes"][0]["value"] == "a" * 64


def test_uuids_seeded_from_hash_not_eval_id() -> None:
    a = make_evidence(eval_id="x", sha="a" * 64)
    b = make_evidence(eval_id="x", sha="b" * 64)
    da, _ = run(a, mapping())
    db, _ = run(b, mapping())
    assert da["results"][0]["uuid"] != db["results"][0]["uuid"]
    assert (
        da["results"][0]["observations"][0]["uuid"] != db["results"][0]["observations"][0]["uuid"]
    )


def _collect(node: Any, out: list[str]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "uuid":
                out.append(v)
            else:
                _collect(v, out)
    elif isinstance(node, list):
        for i in node:
            _collect(i, out)


def _twin(sha: str, name: str, modified: float | None, fmt: str = "eval") -> LogEvidence:
    from dataclasses import replace

    ev = make_evidence(eval_id="same", sha=sha)
    return replace(ev, file_name=name, log_format=fmt, modified=modified)  # type: ignore[arg-type]


@pytest.mark.parametrize("order", [0, 1])
def test_dedupe_prefers_most_recently_modified_and_names_both(order: int) -> None:
    old = _twin("a" * 64, "run.eval", 1000.0)
    new = _twin("b" * 64, "rescored.eval", 2000.0)
    logs = [old, new] if order == 0 else [new, old]
    out = build_results(
        logs, mapping(), load_catalog(), now="2026-11-12T12:00:00Z", oscal_version="1.2.1"
    )
    hashes = [
        r["rlinks"][0]["hashes"][0]["value"]
        for r in out.document["assessment-results"]["back-matter"]["resources"]
    ]
    assert hashes == ["b" * 64]
    (warn,) = [w for w in out.warnings if "same eval_id" in w]
    assert "run.eval" in warn
    assert "rescored.eval" in warn
    assert "most recently modified" in warn
    assert "ontents differ" in warn
    assert "expected for a .eval/.json pair" in warn
    assert "alarm" not in warn


def test_dedupe_known_mtime_beats_unknown() -> None:
    a = _twin("a" * 64, "url.eval", None)
    b = _twin("b" * 64, "local.json", 5.0, fmt="json")
    out = build_results(
        [a, b], mapping(), load_catalog(), now="2026-11-12T12:00:00Z", oscal_version="1.2.1"
    )
    res = out.document["assessment-results"]["back-matter"]["resources"]
    assert res[0]["rlinks"][0]["hashes"][0]["value"] == "b" * 64
