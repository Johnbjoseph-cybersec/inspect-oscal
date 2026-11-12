from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from inspect_ai.log import (
    EvalConfig,
    EvalDataset,
    EvalLog,
    EvalMetric,
    EvalResults,
    EvalScore,
    EvalSpec,
    EvalStats,
)

from inspect_oscal.logread import LogEvidence

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
FIXED_NOW = "2026-11-12T12:00:00Z"
TOOLS = Path(os.environ.get("INSPECT_OSCAL_TOOLS", "/nonexistent"))


@pytest.fixture(scope="session")
def example_logs() -> list[Path]:
    logs = sorted((EXAMPLES / "logs").iterdir())
    assert [p.suffix for p in logs] == [".eval", ".json"]
    return logs


@pytest.fixture(scope="session")
def real_mockllm_log(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A log produced just now by `inspect eval --model mockllm/model`."""
    work = tmp_path_factory.mktemp("real")
    shutil.copy(EXAMPLES / "tiny_cyber_task.py", work / "tiny_cyber_task.py")
    exe = Path(sys.executable).parent / "inspect"
    assert exe.exists(), "inspect executable missing next to the interpreter"
    subprocess.run(
        [
            str(exe),
            "eval",
            "tiny_cyber_task.py",
            "--model",
            "mockllm/model",
            "--log-dir",
            "logs",
            "--log-format",
            "eval",
        ],
        cwd=work,
        check=True,
        capture_output=True,
    )
    found = list((work / "logs").glob("*.eval"))
    assert len(found) == 1
    return found[0]


def find_cli() -> str | None:
    explicit = os.environ.get("INSPECT_OSCAL_CLI")
    if explicit:
        return explicit
    on_path = shutil.which("oscal-cli")
    if on_path:
        return on_path
    for sub in ("oscal-cli", "bin/oscal-cli", "ocli/bin/oscal-cli"):
        local = TOOLS / sub
        if local.is_file():
            return str(local)
    return None


@pytest.fixture(scope="session")
def oscal_cli() -> str:
    cli = find_cli()
    if cli is None:
        if os.environ.get("INSPECT_OSCAL_REQUIRE_CLI") == "1":
            pytest.fail("oscal-cli required but not found")
        pytest.skip("oscal-cli not found (set INSPECT_OSCAL_REQUIRE_CLI=1 to make this fail)")
    return cli


def make_evidence(
    *,
    status: str = "success",
    value: float = 0.9,
    unscored: int = 0,
    task: str = "cyber_x",
    tags: list[str] | None = None,
    metric: str = "accuracy",
    scorer: str = "includes",
    with_results: bool = True,
    abnormal: int | None = None,
    eval_id: str = "evalid123",
    sha: str | None = None,
    total: int = 10,
    completed: int | None = None,
    scored: int | None = -1,
    reducer: str | None = None,
) -> LogEvidence:
    sha = sha or hashlib.sha256(eval_id.encode()).hexdigest()
    results = None
    if with_results:
        results = EvalResults(
            total_samples=total,
            completed_samples=total if completed is None else completed,
            scores=[
                EvalScore(
                    name=scorer,
                    scorer=scorer,
                    reducer=reducer,
                    scored_samples=(total - unscored) if scored == -1 else scored,
                    unscored_samples=unscored,
                    metrics={metric: EvalMetric(name=metric, value=value)},
                )
            ],
        )
    log = EvalLog(
        status=status,  # type: ignore[arg-type]
        eval=EvalSpec(
            eval_id=eval_id,
            created="2026-11-10T09:00:00+00:00",
            task=task,
            tags=tags,
            dataset=EvalDataset(name="ds", samples=10),
            model="mockllm/model",
            config=EvalConfig(),
        ),
        results=results,
        stats=EvalStats(
            started_at="2026-11-10T09:00:00+00:00", completed_at="2026-11-10T09:30:00+00:00"
        ),
    )
    return LogEvidence(f"{task}.eval", f"{task}.eval", sha, 1, "eval", log, abnormal)
