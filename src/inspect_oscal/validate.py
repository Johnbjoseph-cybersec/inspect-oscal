"""Validation: our own reference-integrity and honesty checks, plus an oscal-cli wrapper.

oscal-cli does not check that control or target ids exist in the catalog, so we do.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .catalog import Catalog, CatalogError, load_catalog
from .constants import (
    AI_RMF_CATALOG_SHA256,
    BUNDLE_FILES,
    CATALOG_FILENAME,
    DEFAULT_OCLI_TIMEOUT,
    HASH_ALGORITHM,
    MANIFEST_FILENAME,
    PARTIAL_EVIDENCE,
)

_FORBIDDEN = re.compile(
    r"\b(non-?compliant|compliant|certified|conforms?|conformant|passed|passes)\b", re.IGNORECASE
)
_BUNDLE_NAMES = frozenset({*BUNDLE_FILES.values(), CATALOG_FILENAME})
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_OSCAL_KIND = {"ar": "ar", "ap": "ap", "ssp": "ssp", "profile": "profile"}


@dataclass
class ValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": self.errors,
            "warnings": self.warnings,
            "checks": self.checks,
        }


def find_oscal_cli(explicit: str | Path | None = None) -> str | None:
    if explicit:
        return str(explicit)
    return os.environ.get("INSPECT_OSCAL_CLI") or shutil.which("oscal-cli")


def _load(path: Path, report: ValidationReport) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError) as exc:
        report.errors.append(f"{path.name}: cannot read ({exc})")
        return None
    if not isinstance(data, dict):
        report.errors.append(f"{path.name}: not a JSON object")
        return None
    return data


def _all_uuids(node: Any, out: list[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "uuid" and isinstance(value, str):
                out.append(value)
            else:
                _all_uuids(value, out)
    elif isinstance(node, list):
        for item in node:
            _all_uuids(item, out)


def _authored_strings(kind: str, root: dict[str, Any]) -> list[str]:
    """Strings the tool writes itself. User data (task, model, dataset names) is not linted."""
    if kind != "ar":
        return []
    out = [str(root.get("metadata", {}).get("remarks", ""))]
    for result in root.get("results", []):
        out.append(str(result.get("description", "")))
        for finding in result.get("findings", []):
            out.append(str(finding.get("description", "")).split(" Metrics:")[0])
            out.extend(str(p.get("value", "")) for p in finding.get("props", []))
    return out


def _control_ids(doc: dict[str, Any], kind: str) -> list[str]:
    root = doc[next(iter(doc))]
    ids: list[str] = []

    def selections(reviewed: dict[str, Any]) -> None:
        for sel in reviewed.get("control-selections", []):
            ids.extend(c["control-id"] for c in sel.get("include-controls", []))

    if kind == "ar":
        for result in root.get("results", []):
            selections(result.get("reviewed-controls", {}))
    elif kind == "ap":
        selections(root.get("reviewed-controls", {}))
    elif kind == "ssp":
        reqs = root.get("control-implementation", {}).get("implemented-requirements", [])
        ids.extend(r["control-id"] for r in reqs)
    elif kind == "profile":
        for imp in root.get("imports", []):
            for inc in imp.get("include-controls", []):
                ids.extend(inc.get("with-ids", []))
    return ids


def _check_ar(root: dict[str, Any], catalog: Catalog, report: ValidationReport) -> None:
    resources = {r["uuid"]: r for r in root.get("back-matter", {}).get("resources", [])}
    meta_props = {p["name"] for p in root.get("metadata", {}).get("props", [])}
    if "mapping-statement" not in meta_props:
        report.errors.append("assessment-results: metadata lacks the mapping-statement property")
    for result in root.get("results", []):
        local = result.get("local-definitions", {})
        actors = {c["uuid"] for c in local.get("components", [])}
        actors |= {
            p["uuid"] for p in local.get("assessment-assets", {}).get("assessment-platforms", [])
        }
        obs_ids = {o["uuid"] for o in result.get("observations", [])}
        for obs in result.get("observations", []):
            oid = obs["uuid"]
            if "mapping-statement" not in {p["name"] for p in obs.get("props", [])}:
                report.errors.append(f"observation {oid}: lacks the mapping-statement property")
            for subj in obs.get("subjects", []):
                if subj["subject-uuid"] not in actors:
                    report.errors.append(f"observation {oid}: subject-uuid does not resolve")
            for origin in obs.get("origins", []):
                for actor in origin.get("actors", []):
                    if actor["actor-uuid"] not in actors:
                        report.errors.append(f"observation {oid}: actor-uuid does not resolve")
            evidence = obs.get("relevant-evidence", [])
            if not evidence:
                report.errors.append(f"observation {oid}: no relevant-evidence")
            for ev in evidence:
                href = ev.get("href", "")
                res = resources.get(href[1:]) if href.startswith("#") else None
                if res is None:
                    report.errors.append(f"observation {oid}: evidence href {href!r} unresolved")
                    continue
                hashes = [h for r in res.get("rlinks", []) for h in r.get("hashes", [])]
                if not any(
                    h.get("algorithm") == HASH_ALGORITHM and _HASH_RE.match(h.get("value", ""))
                    for h in hashes
                ):
                    report.errors.append(f"resource {res['uuid']}: no valid SHA-256 hash")
        for finding in result.get("findings", []):
            fid = finding["uuid"]
            target = finding["target"]
            tid = target["target-id"]
            if tid not in catalog.part_ids:
                report.errors.append(f"finding {fid}: target-id {tid!r} not in the pinned catalog")
            for rel in finding.get("related-observations", []):
                if rel["observation-uuid"] not in obs_ids:
                    report.errors.append(f"finding {fid}: related observation does not resolve")
            if target["status"]["state"] == "satisfied" and PARTIAL_EVIDENCE not in finding.get(
                "description", ""
            ):
                report.errors.append(f"finding {fid}: satisfied without the partial-evidence text")


def check_integrity(
    out_dir: str | Path, report: ValidationReport | None = None
) -> ValidationReport:
    """Reference-integrity, manifest, and honesty checks over a bundle directory."""
    report = report or ValidationReport()
    out = Path(out_dir)
    try:
        catalog = load_catalog()
    except CatalogError as exc:
        report.errors.append(str(exc))
        return report

    manifest_path = out / MANIFEST_FILENAME
    manifest = _load(manifest_path, report) if manifest_path.exists() else None
    if not manifest_path.exists():
        report.errors.append(f"{MANIFEST_FILENAME}: missing")
    elif manifest is not None:
        files = manifest.get("files")
        if not isinstance(files, dict):
            report.errors.append(f"{MANIFEST_FILENAME}: no 'files' object")
            files = {}
        for name, digest in files.items():
            if name not in _BUNDLE_NAMES:
                report.errors.append(f"{MANIFEST_FILENAME}: unexpected path {str(name)[:60]!r}")
                continue
            path = out / name
            if not path.exists():
                report.errors.append(f"{name}: listed in manifest but missing")
            elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                report.errors.append(f"{name}: SHA-256 differs from the manifest (modified)")
        report.checks.append("manifest hashes (detects accidental change; not tamper-proof)")

    bundled = out / CATALOG_FILENAME
    if not bundled.exists():
        report.errors.append(f"{CATALOG_FILENAME}: missing from the bundle")
    elif hashlib.sha256(bundled.read_bytes()).hexdigest() != AI_RMF_CATALOG_SHA256:
        report.errors.append(f"{CATALOG_FILENAME}: does not match the pinned hash")
    else:
        report.checks.append("catalog hash")

    seen: list[str] = []
    for kind, name in BUNDLE_FILES.items():
        path = out / name
        if not path.exists():
            report.errors.append(f"{name}: missing")
            continue
        doc = _load(path, report)
        if doc is None:
            continue
        if len(doc) != 1 or not isinstance(next(iter(doc.values())), dict):
            report.errors.append(f"{name}: not an OSCAL document (expected one root object)")
            continue
        root = doc[next(iter(doc))]
        try:
            for cid in _control_ids(doc, kind):
                if not catalog.has_control(cid):
                    report.errors.append(
                        f"{name}: control-id {cid!r} does not exist in the catalog"
                    )
            _all_uuids(root, seen)
            for text in _authored_strings(kind, root):
                if _FORBIDDEN.search(text):
                    report.errors.append(f"{name}: forbidden wording in {text[:60]!r}")
            if kind == "ar":
                _check_ar(root, catalog, report)
        except (KeyError, TypeError, AttributeError, IndexError, ValueError) as exc:
            report.errors.append(f"{name}: malformed document ({type(exc).__name__}: {exc})")
    for u, n in Counter(seen).items():
        if n > 1:
            report.errors.append(f"uuid {u} is not unique across the bundle")
    report.checks += ["control ids exist", "uuids unique", "references resolve", "wording lint"]
    return report


def run_oscal_cli(
    out_dir: Path, cli: str, report: ValidationReport, timeout: float = DEFAULT_OCLI_TIMEOUT
) -> None:
    out_dir = out_dir.resolve()
    for kind, name in BUNDLE_FILES.items():
        try:
            proc = subprocess.run(
                [cli, _OSCAL_KIND[kind], "validate", str(out_dir / name)],
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            report.errors.append(f"oscal-cli timed out after {timeout:g}s on {name}")
            continue
        except OSError as exc:
            report.errors.append(f"oscal-cli could not be run: {exc}")
            return
        if proc.returncode == 0:
            report.checks.append(f"oscal-cli {kind}: valid")
        else:
            detail = (proc.stdout + proc.stderr).strip().splitlines()
            report.errors.append(f"oscal-cli rejected {name}: " + " | ".join(detail[:6]))


def validate_bundle(
    out_dir: str | Path,
    *,
    use_oscal_cli: bool = False,
    oscal_cli: str | Path | None = None,
    timeout: float = DEFAULT_OCLI_TIMEOUT,
) -> ValidationReport:
    """Run integrity checks and, if requested, oscal-cli over results, plan, SSP and profile."""
    report = check_integrity(out_dir)
    if use_oscal_cli:
        cli = find_oscal_cli(oscal_cli)
        if cli is None:
            report.errors.append("oscal-cli requested but not found (use --oscal-cli or PATH)")
        else:
            run_oscal_cli(Path(out_dir), cli, report, timeout)
    report.warnings.append(
        "catalog is hash-pinned and not re-validated (known upstream constraint errors)"
    )
    return report
