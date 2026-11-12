"""User-editable mapping from Inspect logs to NIST AI RMF subcategories."""

from __future__ import annotations

import hashlib
import math
import operator
from collections.abc import Callable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from importlib import resources
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
    model_validator,
)

from .catalog import Catalog


class MappingError(Exception):
    """The mapping file is invalid or names targets absent from the pinned catalog."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Cond(_Strict):
    """One condition. Every key given must match (AND); list values match if any item does."""

    task_glob: list[str] | None = None
    task_registry_glob: list[str] | None = None
    tags: list[str] | None = None
    dataset_glob: list[str] | None = None
    model_glob: list[str] | None = None
    metadata: dict[str, str | int | float | bool] | None = None

    @model_validator(mode="after")
    def _not_empty(self) -> Cond:
        if not self.model_fields_set:
            raise ValueError("a condition needs at least one key")
        return self


class Match(_Strict):
    all: bool | list[Cond] | None = None
    any: list[Cond] | None = None

    @model_validator(mode="after")
    def _one_form(self) -> Match:
        if (self.all is None) == (self.any is None):
            raise ValueError("match needs exactly one of 'all' or 'any'")
        if self.all is False:
            raise ValueError("'all: false' would match nothing; remove the rule instead")
        return self


class Threshold(_Strict):
    op: Literal[">=", ">", "<=", "<", "=="]
    value: float

    @field_validator("value")
    @classmethod
    def _finite(cls, v: float) -> float:
        if not math.isfinite(v):
            raise ValueError("threshold value must be a finite number")
        return v

    def evaluate(self, observed: float) -> bool:
        return _OPS[self.op](observed, self.value)


_OPS: dict[str, Callable[[float, float], bool]] = {
    ">=": operator.ge,
    ">": operator.gt,
    "<=": operator.le,
    "<": operator.lt,
    "==": operator.eq,
}


class ScoreSpec(_Strict):
    scorer: str = "*"
    metric: str = "*"
    reducer: str | None = None
    threshold: Threshold | None = None


class Observe(_Strict):
    kind: Literal["log-facts"]


class Rule(_Strict):
    id: str = Field(pattern=r"^[A-Za-z0-9._-]+$")
    description: str = ""
    match: Match
    targets: list[str] = Field(min_length=1)
    observe: Observe | None = None
    scores: list[ScoreSpec] = Field(default_factory=list)
    require_complete: bool = True

    @model_validator(mode="after")
    def _has_work(self) -> Rule:
        if not self.scores and self.observe is None:
            raise ValueError(f"rule {self.id!r} needs 'scores' or 'observe'")
        return self


class Mapping(_Strict):
    version: Literal[1]
    catalog: Literal["nist-ai-rmf-1.0"] = "nist-ai-rmf-1.0"
    statement: Literal["derived"] = "derived"
    rules: list[Rule] = Field(min_length=1)
    _sha256: str = PrivateAttr(default="")

    @model_validator(mode="after")
    def _unique_ids(self) -> Mapping:
        ids = [r.id for r in self.rules]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate rule ids: {', '.join(dupes)}")
        return self

    @property
    def sha256(self) -> str:
        """SHA-256 of the mapping file bytes, recorded in the output."""
        return self._sha256

    def all_targets(self) -> list[str]:
        return sorted({t for r in self.rules for t in r.targets})


def default_mapping_text() -> str:
    return resources.files("inspect_oscal.data").joinpath("default_mapping.yaml").read_text("utf-8")


def parse_mapping(text: str, *, origin: str = "mapping") -> Mapping:
    raw = text.encode("utf-8")
    try:
        doc: Any = yaml.safe_load(text)
        mapping = Mapping.model_validate(doc)
    except (yaml.YAMLError, ValidationError) as exc:
        raise MappingError(f"{origin}: {exc}") from exc
    mapping._sha256 = hashlib.sha256(raw).hexdigest()
    return mapping


def load_mapping(path: str | Path | None = None) -> Mapping:
    """Load ``path``, or the packaged default mapping when omitted."""
    if path is None:
        return parse_mapping(default_mapping_text(), origin="default mapping")
    try:
        text = Path(path).read_text("utf-8")
    except OSError as exc:
        raise MappingError(f"{path}: {exc}") from exc
    return parse_mapping(text, origin=str(path))


def check_targets(mapping: Mapping, catalog: Catalog) -> list[str]:
    """Return one error per target id that is absent from the pinned catalog."""
    return [
        f"rule {rule.id!r}: target {t!r} does not exist in the pinned catalog"
        for rule in mapping.rules
        for t in rule.targets
        if not catalog.has_control(t)
    ]


@dataclass(frozen=True)
class LogView:
    """The facts of one log that rules match against."""

    task: str
    task_registry_name: str
    tags: frozenset[str]
    dataset: str
    model: str
    metadata: dict[str, str]


def _glob_any(value: str, patterns: list[str]) -> bool:
    return any(fnmatchcase(value.lower(), p.lower()) for p in patterns)


def cond_matches(cond: Cond, view: LogView) -> bool:
    if cond.task_glob is not None and not _glob_any(view.task, cond.task_glob):
        return False
    if cond.task_registry_glob is not None and not _glob_any(
        view.task_registry_name, cond.task_registry_glob
    ):
        return False
    if cond.tags is not None and not any(t in view.tags for t in cond.tags):
        return False
    if cond.dataset_glob is not None and not _glob_any(view.dataset, cond.dataset_glob):
        return False
    if cond.model_glob is not None and not _glob_any(view.model, cond.model_glob):
        return False
    if cond.metadata is not None:
        for key, expected in cond.metadata.items():
            if key not in view.metadata or view.metadata[key] != str(expected):
                return False
    return True


def rule_matches(rule: Rule, view: LogView) -> bool:
    match = rule.match
    if match.any is not None:
        return any(cond_matches(c, view) for c in match.any)
    if match.all is True:
        return True
    assert isinstance(match.all, list)
    return all(cond_matches(c, view) for c in match.all)


def glob_match(value: str, pattern: str) -> bool:
    return fnmatchcase(value, pattern)


def is_finite(value: float) -> bool:
    return not (math.isnan(value) or math.isinf(value))
