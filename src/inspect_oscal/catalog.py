"""The vendored, hash-pinned NIST AI RMF OSCAL catalog."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any

from .constants import AI_RMF_CATALOG_SHA256, CATALOG_FILENAME


class CatalogError(Exception):
    """The vendored catalog is missing or does not match its pinned hash."""


@dataclass(frozen=True)
class Catalog:
    sha256: str
    control_ids: frozenset[str]
    part_ids: frozenset[str]
    titles: dict[str, str] = field(default_factory=dict)

    def has_control(self, control_id: str) -> bool:
        return control_id in self.control_ids

    def overview_part(self, control_id: str) -> str | None:
        """Id of the outcome-text part (``<id>_ovw``) if the catalog has one."""
        candidate = f"{control_id}_ovw"
        return candidate if candidate in self.part_ids else None


def catalog_bytes() -> bytes:
    return resources.files("inspect_oscal.data").joinpath(CATALOG_FILENAME).read_bytes()


def _walk_controls(controls: list[dict[str, Any]]) -> Any:
    for control in controls:
        yield control
        yield from _walk_controls(control.get("controls", []))


def _walk_parts(parts: list[dict[str, Any]]) -> Any:
    for part in parts:
        if "id" in part:
            yield part["id"]
        yield from _walk_parts(part.get("parts", []))


@lru_cache(maxsize=1)
def load_catalog() -> Catalog:
    """Load the catalog, refusing to proceed if its SHA-256 differs from the pin."""
    raw = catalog_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != AI_RMF_CATALOG_SHA256:
        raise CatalogError(
            f"vendored catalog hash {digest} does not equal pinned {AI_RMF_CATALOG_SHA256}"
        )
    doc = json.loads(raw)["catalog"]
    top: list[dict[str, Any]] = [c for g in doc["groups"] for c in g.get("controls", [])]
    control_ids: set[str] = set()
    part_ids: set[str] = set()
    titles: dict[str, str] = {}
    for control in _walk_controls(top):
        control_ids.add(control["id"])
        titles[control["id"]] = control.get("title", "")
        part_ids.update(_walk_parts(control.get("parts", [])))
    return Catalog(digest, frozenset(control_ids), frozenset(part_ids), titles)


def verify_catalog() -> str:
    """Return the verified SHA-256, or raise :class:`CatalogError`."""
    return load_catalog().sha256
