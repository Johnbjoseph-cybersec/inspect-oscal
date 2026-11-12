from __future__ import annotations

import pytest

from inspect_oscal.catalog import load_catalog
from inspect_oscal.mapping import (
    LogView,
    MappingError,
    check_targets,
    load_mapping,
    parse_mapping,
    rule_matches,
)

BASE = """
version: 1
rules:
  - id: r1
    match: {all: true}
    targets: [MEASURE_2.1]
    observe: {kind: log-facts}
"""


def view(**kw: object) -> LogView:
    base: dict[str, object] = dict(
        task="cyber_x",
        task_registry_name="",
        tags=frozenset(),
        dataset="ds",
        model="mockllm/model",
        metadata={},
    )
    base.update(kw)
    return LogView(**base)  # type: ignore[arg-type]


def test_default_mapping_loads_and_targets_exist() -> None:
    m = load_mapping()
    assert len(m.rules) == 6
    assert check_targets(m, load_catalog()) == []
    assert len(m.sha256) == 64
    assert all(s.threshold is None for r in m.rules for s in r.scores)


@pytest.mark.parametrize(
    "text",
    [
        BASE + "extra: 1\n",
        BASE.replace("observe: {kind: log-facts}", "observe: {kind: nope}"),
        BASE.replace("match: {all: true}", "match: {all: false}"),
        BASE.replace("match: {all: true}", "match: {all: true, any: [{tags: [a]}]}"),
        BASE.replace("observe: {kind: log-facts}", ""),
        BASE.replace("version: 1", "version: 2"),
        BASE.replace("match: {all: true}", "match: {any: [{}]}"),
        BASE.replace(
            "observe: {kind: log-facts}",
            "scores: [{metric: accuracy, threshold: {op: '=>', value: 1}}]",
        ),
        "not: [valid",
    ],
)
def test_invalid_mappings_rejected(text: str) -> None:
    with pytest.raises(MappingError):
        parse_mapping(text)


def test_duplicate_rule_ids_rejected() -> None:
    dup = BASE + "  - id: r1\n    match: {all: true}\n    targets: [MEASURE_2.1]\n"
    dup += "    observe: {kind: log-facts}\n"
    with pytest.raises(MappingError, match="duplicate"):
        parse_mapping(dup)


def test_unknown_target_reported() -> None:
    m = parse_mapping(BASE.replace("MEASURE_2.1", "NOPE_9.9"))
    assert "NOPE_9.9" in check_targets(m, load_catalog())[0]


def test_missing_file() -> None:
    with pytest.raises(MappingError):
        load_mapping("/nonexistent/mapping.yaml")


@pytest.mark.parametrize(
    ("cond", "v", "expected"),
    [
        ("{task_glob: ['*cyber*']}", view(), True),
        ("{task_glob: ['*CYBER*']}", view(), True),
        ("{task_glob: ['*bias*']}", view(), False),
        ("{task_registry_glob: ['x/*']}", view(task_registry_name="x/y"), True),
        ("{tags: [a, b]}", view(tags=frozenset({"b"})), True),
        ("{tags: [a]}", view(tags=frozenset({"b"})), False),
        ("{dataset_glob: ['d*']}", view(), True),
        ("{model_glob: ['openai/*']}", view(), False),
        ("{metadata: {team: 7}}", view(metadata={"team": "7"}), True),
        ("{metadata: {team: 7}}", view(), False),
        ("{task_glob: ['*cyber*'], tags: [z]}", view(), False),
    ],
)
def test_any_matching_table(cond: str, v: LogView, expected: bool) -> None:
    m = parse_mapping(BASE.replace("{all: true}", "{any: [" + cond + "]}"))
    assert rule_matches(m.rules[0], v) is expected


def test_all_combinator() -> None:
    m = parse_mapping(BASE.replace("{all: true}", "{all: [{task_glob: ['*cyber*']}, {tags: [t]}]}"))
    assert rule_matches(m.rules[0], view(tags=frozenset({"t"})))
    assert not rule_matches(m.rules[0], view())
