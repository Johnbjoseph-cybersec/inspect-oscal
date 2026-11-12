"""Turn parsed Inspect logs into the OSCAL assessment-results document.

Observations are always written. A threshold result is carried in a namespaced
``threshold-result`` property. Findings (OSCAL ``target.status.state``) are opt-in.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from inspect_ai.log import EvalScore

from .catalog import Catalog
from .constants import (
    HASH_ALGORITHM,
    MAPPING_NOTICE,
    MAPPING_STATEMENT,
    NS,
    PARTIAL_EVIDENCE,
    PARTIAL_EVIDENCE_MISSED,
    STATUS_MEANING,
    TOOL_NAME,
    __version__,
)
from .ids import stable_uuid, to_oscal_time
from .logread import LogEvidence
from .mapping import LogView, Mapping, Rule, ScoreSpec, Threshold, glob_match, rule_matches

Json = dict[str, Any]


def prop(name: str, value: object | None) -> Json | None:
    if value is None or str(value) == "":
        return None
    return {"name": name, "value": str(value), "ns": NS}


def props(*items: tuple[str, object | None]) -> list[Json]:
    return [p for n, v in items if (p := prop(n, v)) is not None]


@dataclass
class Check:
    """One thresholded metric. ``withheld`` is why it could not be evaluated, if so."""

    rule_id: str
    scorer: str
    reducer: str | None
    metric: str
    value: float | None
    threshold: Threshold
    withheld: str | None
    observation: str | None = None

    @property
    def met(self) -> bool:
        assert self.value is not None
        return self.threshold.evaluate(self.value)

    @property
    def label(self) -> str:
        reducer = f"[{self.reducer}]" if self.reducer else ""
        return f"{self.scorer}{reducer}.{self.metric}"


@dataclass
class ConversionResult:
    document: Json
    controls: list[str]
    warnings: list[str] = field(default_factory=list)
    converted: int = 0


def log_view(ev: LogEvidence) -> LogView:
    spec = ev.log.eval
    tags = set(spec.tags or []) | set(ev.log.tags or [])
    merged = {**(spec.metadata or {}), **(ev.log.metadata or {})}
    metadata = {str(k): str(v) for k, v in merged.items()}
    return LogView(
        task=spec.task,
        task_registry_name=spec.task_registry_name or "",
        tags=frozenset(tags),
        dataset=spec.dataset.name or "",
        model=spec.model,
        metadata=metadata,
    )


def _fmt(value: float | int) -> str:
    return repr(value)


def _inspect_version(ev: LogEvidence) -> str:
    return str((ev.log.eval.packages or {}).get("inspect_ai", "unknown"))


def _counts(ev: LogEvidence) -> tuple[int | None, int | None]:
    res = ev.log.results
    return (res.total_samples, res.completed_samples) if res else (None, None)


def _count_text(ev: LogEvidence) -> str:
    total, completed = _counts(ev)
    return (
        f"completed {completed if completed is not None else 'unknown'} of "
        f"{total if total is not None else 'unknown'} samples"
    )


def _resource(ev: LogEvidence) -> Json:
    spec = ev.log.eval
    return {
        "uuid": stable_uuid("resource", ev.sha256),
        "title": ev.file_name,
        "description": f"Inspect eval log, format .{ev.log_format}, eval_id {spec.eval_id}.",
        "props": props(
            ("eval-id", spec.eval_id),
            ("log-format", ev.log_format),
            ("inspect-log-version", ev.log.version),
        ),
        "rlinks": [
            {
                "href": ev.href,
                "media-type": "application/zip" if ev.log_format == "eval" else "application/json",
                "hashes": [{"algorithm": HASH_ALGORITHM, "value": ev.sha256}],
            }
        ],
    }


def _common_props(
    ev: LogEvidence, rule: Rule, scorer: str | None, metric: str | None, reducer: str | None
) -> list[Json]:
    spec = ev.log.eval
    total, completed = _counts(ev)
    return props(
        ("task", spec.task),
        ("task-version", spec.task_version),
        ("eval-id", spec.eval_id),
        ("run-id", spec.run_id),
        ("scorer", scorer),
        ("metric", metric),
        ("reducer", reducer),
        ("total-samples", total),
        ("completed-samples", completed),
        ("eval-status", ev.log.status),
        ("rule-id", rule.id),
        ("abnormal-scores-checked", str(ev.abnormal_scores is not None).lower()),
        ("abnormal-scores", ev.abnormal_scores),
        ("mapping-statement", MAPPING_STATEMENT),
    )


def _observation(
    ev: LogEvidence,
    seed: tuple[str, ...],
    title: str,
    description: str,
    extra: list[Json],
    ids: tuple[str, str, str],
) -> Json:
    component_id, platform_id, resource_id = ids
    collected = ev.log.stats.completed_at or ev.log.eval.created
    return {
        "uuid": stable_uuid("observation", ev.sha256, *seed),
        "title": title,
        "description": description,
        "props": extra,
        "methods": ["TEST"],
        "types": ["finding"],
        "origins": [{"actors": [{"type": "tool", "actor-uuid": platform_id}]}],
        "subjects": [{"subject-uuid": component_id, "type": "component"}],
        "relevant-evidence": [
            {
                "href": f"#{resource_id}",
                "description": "Inspect eval log; its SHA-256 is recorded in the back-matter.",
            }
        ],
        "collected": to_oscal_time(collected),
    }


def _facts_description(ev: LogEvidence) -> str:
    spec = ev.log.eval
    scorers = ", ".join(s.name for s in spec.scorers or []) or "none recorded"
    total, _ = _counts(ev)
    return (
        f"Task {spec.task} was run on model {spec.model} against dataset "
        f"{spec.dataset.name or 'unnamed'} ({total if total is not None else 'unknown'} samples). "
        f"Scorers: {scorers}. Log status: {ev.log.status}."
    )


def _score_matches(spec: ScoreSpec, scorer: str, metric: str, reducer: str | None) -> bool:
    return (
        glob_match(scorer, spec.scorer)
        and glob_match(metric, spec.metric)
        and (spec.reducer is None or spec.reducer == reducer)
    )


def _withhold_reason(
    ev: LogEvidence, rule: Rule, score: EvalScore | None, value: float | None
) -> str | None:
    """Why a threshold on this metric cannot be evaluated, or None if it can."""
    if ev.log.status != "success":
        return f"eval status is {ev.log.status!r}"
    if ev.abnormal_scores:
        return f"{ev.abnormal_scores} abnormal sample scores"
    if value is None or score is None:
        return "metric not found"
    if math.isnan(value):
        return "metric is NaN"
    total, completed = _counts(ev)
    if total is None or completed is None:
        return "sample counts are missing from the log"
    if completed != total:
        return f"only {completed} of {total} samples completed"
    if rule.require_complete:
        if score.scored_samples is None:
            return "scored sample count is missing from the log"
        if score.scored_samples < total or (score.unscored_samples or 0) > 0:
            return f"{score.scored_samples} of {total} samples were scored"
    return None


def _convert_one(
    ev: LogEvidence,
    mapping: Mapping,
    catalog: Catalog,
    warnings: list[str],
    findings_on: bool,
) -> tuple[Json, list[str]] | None:
    spec = ev.log.eval
    name = ev.file_name
    view = log_view(ev)
    rules = [r for r in mapping.rules if rule_matches(r, view)]
    if not rules:
        warnings.append(f"{name}: no mapping rule matched; log skipped")
        return None

    ids = (
        stable_uuid("component", ev.sha256, spec.model),
        stable_uuid("platform", ev.sha256),
        stable_uuid("resource", ev.sha256),
    )
    status = ev.log.status
    total, completed = _counts(ev)
    if status != "success":
        warnings.append(f"{name}: eval status is {status!r}; thresholds are not evaluated")
    if total is not None and completed is not None and completed < total:
        warnings.append(f"{name}: only {completed} of {total} samples completed")
    if ev.abnormal_scores:
        warnings.append(f"{name}: {ev.abnormal_scores} sample scores were abnormal")
    thresholded = any(s.threshold for r in rules for s in r.scores)
    if thresholded and ev.abnormal_scores is None:
        warnings.append(f"{name}: samples were not read, so abnormal scores were not checked")

    observations: dict[str, Json] = {}
    checks: dict[str, list[Check]] = {}
    controls: set[str] = set()
    scores = ev.log.results.scores if ev.log.results else []

    for rule in rules:
        controls.update(rule.targets)
        if rule.observe is not None:
            obs = _observation(
                ev,
                (rule.id, "log-facts"),
                f"{spec.task}: log facts",
                _facts_description(ev),
                _common_props(ev, rule, None, None, None)
                + props(
                    ("dataset", spec.dataset.name),
                    ("git-revision", spec.revision.commit if spec.revision else None),
                    ("inspect-version", _inspect_version(ev)),
                ),
                ids,
            )
            observations.setdefault(obs["uuid"], obs)
        for sspec in rule.scores:
            found = False
            for score in scores:
                for key, metric in score.metrics.items():
                    mname = metric.name or key
                    if not _score_matches(sspec, score.scorer, mname, score.reducer):
                        continue
                    found = True
                    value = metric.value
                    scored = score.scored_samples
                    extra = props(
                        ("metric-value", _fmt(value)),
                        ("scored-samples", scored),
                        ("unscored-samples", score.unscored_samples),
                    )
                    check: Check | None = None
                    if sspec.threshold is not None:
                        reason = _withhold_reason(ev, rule, score, float(value))
                        check = Check(
                            rule.id, score.scorer, score.reducer, mname, float(value),
                            sspec.threshold, reason,
                        )  # fmt: skip
                        outcome = "not-evaluated" if reason else ("met" if check.met else "missed")
                        extra += props(
                            ("threshold", f"{sspec.threshold.op} {sspec.threshold.value}"),
                            ("threshold-result", outcome),
                            ("threshold-note", reason),
                        )
                        if reason:
                            warnings.append(
                                f"{name}: threshold on {check.label} not evaluated: {reason}"
                            )
                    desc = (
                        f"Task {spec.task} on model {spec.model}: scorer {score.scorer}, "
                        f"metric {mname} = {_fmt(value)} over "
                        f"{scored if scored is not None else 'unknown'}/"
                        f"{total if total is not None else 'unknown'} samples "
                        f"(log status: {status})."
                    )
                    obs = _observation(
                        ev,
                        (rule.id, score.scorer, score.reducer or "", mname),
                        f"{spec.task}: {score.scorer}.{mname}",
                        desc,
                        _common_props(ev, rule, score.scorer, mname, score.reducer) + extra,
                        ids,
                    )
                    observations.setdefault(obs["uuid"], obs)
                    if check is not None:
                        check.observation = obs["uuid"]
                        for target in rule.targets:
                            checks.setdefault(target, []).append(check)
            if not found:
                warnings.append(
                    f"{name}: rule {rule.id!r} found no metric matching "
                    f"scorer={sspec.scorer!r} metric={sspec.metric!r}"
                )
                if sspec.threshold is not None:
                    missing = Check(
                        rule.id, sspec.scorer, sspec.reducer, sspec.metric, None,
                        sspec.threshold, "metric not found",
                    )  # fmt: skip
                    for target in rule.targets:
                        checks.setdefault(target, []).append(missing)

    findings = _findings(ev, checks, catalog, warnings) if findings_on else []
    sorted_controls = sorted(controls)
    result: Json = {
        "uuid": stable_uuid("result", ev.sha256),
        "title": f"{spec.task} on {spec.model}",
        "description": "Evidence from one Inspect eval log. " + MAPPING_NOTICE,
        "start": to_oscal_time(ev.log.stats.started_at or spec.created),
        "local-definitions": {
            "components": [
                {
                    "uuid": ids[0],
                    "type": "software",
                    "title": f"{spec.model} (model under test)",
                    "description": "Model evaluated in the referenced Inspect eval log.",
                    "status": {"state": "operational"},
                }
            ],
            "assessment-assets": {
                "assessment-platforms": [
                    {
                        "uuid": ids[1],
                        "title": f"Inspect AI {_inspect_version(ev)}",
                        "props": props(("tool-version", _inspect_version(ev))),
                    }
                ]
            },
        },
        "reviewed-controls": {
            "control-selections": [
                {"include-controls": [{"control-id": c} for c in sorted_controls]}
            ]
        },
        "observations": list(observations.values()),
    }
    if ev.log.stats.completed_at:
        result["end"] = to_oscal_time(ev.log.stats.completed_at)
    if findings:
        result["findings"] = findings
    return result, sorted_controls


def _findings(
    ev: LogEvidence, checks: dict[str, list[Check]], catalog: Catalog, warnings: list[str]
) -> list[Json]:
    out: list[Json] = []
    for target in sorted(checks):
        items = checks[target]
        part = catalog.overview_part(target)
        if part is None:
            warnings.append(f"{ev.file_name}: {target} has no overview part; no finding written")
            continue
        held = next((c for c in items if c.withheld), None)
        if held is not None:
            warnings.append(
                f"{ev.file_name}: no finding for {target}: {held.label}: {held.withheld}"
            )
            continue
        missed = [c for c in items if not c.met]
        lines = "; ".join(
            f"{c.label} = {_fmt(c.value) if c.value is not None else 'n/a'} "
            f"(threshold {c.threshold.op} {c.threshold.value})"
            for c in items
        )
        state = "not-satisfied" if missed else "satisfied"
        lead = PARTIAL_EVIDENCE_MISSED if missed else PARTIAL_EVIDENCE
        out.append(
            {
                "uuid": stable_uuid("finding", ev.sha256, target),
                "title": f"{target} evidence from {ev.log.eval.task}",
                "description": (
                    f"{lead} All thresholded metrics must meet their thresholds. "
                    f"Metrics: {lines}. Run: {_count_text(ev)}."
                ),
                "props": props(
                    ("rule-id", ",".join(sorted({c.rule_id for c in items}))),
                    ("mapping-statement", MAPPING_STATEMENT),
                    ("threshold-result", "missed" if missed else "met"),
                    ("status-meaning", STATUS_MEANING),
                ),
                "target": {
                    "type": "statement-id",
                    "target-id": part,
                    "status": {"state": state, "reason": "other"},
                },
                "related-observations": [
                    {"observation-uuid": u}
                    for u in sorted({c.observation for c in items if c.observation})
                ],
            }
        )
    return out


def _dedupe_key(e: LogEvidence) -> tuple[str, int, float, int, str]:
    """Per eval_id: most recently modified file first, then .eval before .json, then hash."""
    known = e.modified is not None
    return (
        e.log.eval.eval_id,
        0 if known else 1,
        -(e.modified or 0.0),
        0 if e.log_format == "eval" else 1,
        e.sha256,
    )


def _why_kept(kept: LogEvidence, skipped: LogEvidence) -> str:
    if kept.modified is not None and (skipped.modified is None or kept.modified > skipped.modified):
        return "most recently modified"
    return "ties on modification time: .eval preferred, then lowest hash"


def _dedupe(evidences: list[LogEvidence], warnings: list[str]) -> list[LogEvidence]:
    """Order-independent: one log per byte-identical content and per eval_id."""
    ordered = sorted(evidences, key=_dedupe_key)
    kept: list[LogEvidence] = []
    seen_sha: set[str] = set()
    seen_eval: dict[str, LogEvidence] = {}
    for ev in ordered:
        if ev.sha256 in seen_sha:
            warnings.append(f"{ev.file_name}: identical bytes already converted; skipped")
        elif ev.log.eval.eval_id in seen_eval:
            first = seen_eval[ev.log.eval.eval_id]
            differ = (
                " Contents differ (expected for a .eval/.json pair;"
                " re-scored or edited logs also differ)."
                if first.sha256 != ev.sha256
                else ""
            )
            warnings.append(
                f"{ev.file_name}: same eval_id as {first.file_name} (the same run); kept "
                f"{first.file_name} ({_why_kept(first, ev)}), skipped {ev.file_name}.{differ}"
            )
        else:
            kept.append(ev)
            seen_eval[ev.log.eval.eval_id] = ev
        seen_sha.add(ev.sha256)
    return kept


def build_results(
    evidences: list[LogEvidence],
    mapping: Mapping,
    catalog: Catalog,
    *,
    now: str,
    oscal_version: str,
    findings: bool = False,
) -> ConversionResult:
    """Build the assessment-results document for ``evidences``."""
    warnings: list[str] = []
    results: list[Json] = []
    controls: set[str] = set()
    resources: dict[str, Json] = {}
    for ev in _dedupe(evidences, warnings):
        done = _convert_one(ev, mapping, catalog, warnings, findings)
        if done is None:
            continue
        result, cids = done
        results.append(result)
        controls.update(cids)
        res = _resource(ev)
        resources.setdefault(res["uuid"], res)
    results.sort(key=lambda r: r["uuid"])
    seed = sorted(r["uuid"] for r in results)
    doc: Json = {
        "assessment-results": {
            "uuid": stable_uuid("assessment-results", mapping.sha256, *seed),
            "metadata": {
                "title": "Inspect eval evidence mapped to NIST AI RMF 1.0",
                "last-modified": now,
                "version": __version__,
                "oscal-version": oscal_version,
                "props": props(
                    ("tool", f"{TOOL_NAME} {__version__}"),
                    ("mapping-statement", MAPPING_STATEMENT),
                    ("mapping-sha256", mapping.sha256),
                    ("catalog-sha256", catalog.sha256),
                    ("findings-included", str(findings).lower()),
                ),
                "remarks": MAPPING_NOTICE,
            },
            "import-ap": {"href": "./assessment-plan.json"},
            "results": results,
            "back-matter": {"resources": sorted(resources.values(), key=lambda r: r["uuid"])},
        }
    }
    return ConversionResult(doc, sorted(controls), warnings, len(results))
