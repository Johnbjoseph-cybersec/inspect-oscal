"""Build and write the five-document OSCAL bundle oscal-cli needs to validate results."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .catalog import catalog_bytes, load_catalog
from .constants import (
    BUNDLE_FILES,
    CATALOG_FILENAME,
    MANIFEST_FILENAME,
    MANIFEST_STATEMENT,
    OSCAL_VERSION,
    TOOL_NAME,
    __version__,
)
from .convert import Json, build_results
from .ids import resolve_now, stable_uuid
from .logread import MAX_LOG_BYTES, LogEvidence, clean_base_url, read_log
from .mapping import Mapping, MappingError, check_targets, load_mapping
from .validate import check_integrity

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
PLACEHOLDER = "Not described by inspect-oscal; to be supplied by the system owner."


class BundleError(Exception):
    """Nothing could be converted, or an option is invalid."""


@dataclass
class Bundle:
    out_dir: Path
    files: list[Path]
    warnings: list[str] = field(default_factory=list)
    results: int = 0


def _meta(title: str, now: str, version: str) -> Json:
    return {"title": title, "last-modified": now, "version": __version__, "oscal-version": version}


def _plan(controls: list[str], now: str, version: str) -> Json:
    return {
        "assessment-plan": {
            "uuid": stable_uuid("assessment-plan", *controls),
            "metadata": _meta("Assessment plan for Inspect eval evidence", now, version),
            "import-ssp": {"href": f"./{BUNDLE_FILES['ssp']}"},
            "reviewed-controls": {
                "control-selections": [{"include-controls": [{"control-id": c} for c in controls]}]
            },
        }
    }


def _ssp(controls: list[str], system_name: str, now: str, version: str) -> Json:
    this_system = stable_uuid("ssp-component", system_name)
    return {
        "system-security-plan": {
            "uuid": stable_uuid("ssp", system_name, *controls),
            "metadata": _meta(f"System security plan placeholder: {system_name}", now, version),
            "import-profile": {"href": f"./{BUNDLE_FILES['profile']}"},
            "system-characteristics": {
                "system-ids": [{"id": stable_uuid("system-id", system_name)}],
                "system-name": system_name,
                "description": "Placeholder system record so the OSCAL chain resolves. "
                "inspect-oscal does not describe the system.",
                "system-information": {
                    "information-types": [
                        {
                            "uuid": stable_uuid("information-type", system_name),
                            "title": "Evaluation data",
                            "description": "Placeholder; impact levels are not assessed by "
                            "inspect-oscal.",
                            "confidentiality-impact": {"base": "fips-199-low"},
                            "integrity-impact": {"base": "fips-199-low"},
                            "availability-impact": {"base": "fips-199-low"},
                        }
                    ]
                },
                "status": {"state": "under-development"},
                "authorization-boundary": {"description": "Not described by inspect-oscal."},
            },
            "system-implementation": {
                "users": [{"uuid": stable_uuid("ssp-user", system_name), "title": "Evaluator"}],
                "components": [
                    {
                        "uuid": this_system,
                        "type": "this-system",
                        "title": system_name,
                        "description": "The AI system under evaluation.",
                        "status": {"state": "operational"},
                    }
                ],
            },
            "control-implementation": {
                "description": "Implementation is not described by inspect-oscal.",
                "implemented-requirements": [
                    {
                        "uuid": stable_uuid("ir", system_name, c),
                        "control-id": c,
                        "by-components": [
                            {
                                "component-uuid": this_system,
                                "uuid": stable_uuid("ir-bc", system_name, c),
                                "description": PLACEHOLDER,
                            }
                        ],
                    }
                    for c in controls
                ],
            },
        }
    }


def _profile(controls: list[str], now: str, version: str) -> Json:
    return {
        "profile": {
            "uuid": stable_uuid("profile", *controls),
            "metadata": _meta("AI RMF subcategories referenced by Inspect evidence", now, version),
            "imports": [
                {
                    "href": f"./{CATALOG_FILENAME}",
                    "include-controls": [{"with-ids": controls}],
                }
            ],
        }
    }


def _dump(doc: Any) -> bytes:
    return (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def convert_logs(
    logs: Sequence[str | Path],
    *,
    out_dir: str | Path,
    mapping: Mapping | None = None,
    system_name: str = "Evaluated AI system",
    samples: bool = True,
    findings: bool = False,
    oscal_version: str = OSCAL_VERSION,
    now: str | None = None,
    evidence_base_url: str | None = None,
    max_log_bytes: int = MAX_LOG_BYTES,
) -> Bundle:
    """Convert Inspect logs into an OSCAL bundle under ``out_dir`` and return what was written.

    Observations are always written. ``findings=True`` adds OSCAL findings whose status records
    only whether a user-declared threshold was met. ``samples=True`` (default) reads samples to
    count abnormal scores; pass False for very large logs.
    """
    if not _VERSION_RE.match(oscal_version):
        raise BundleError(f"invalid OSCAL version {oscal_version!r}")
    if not logs:
        raise BundleError("no logs given")
    catalog = load_catalog()
    mapping = mapping or load_mapping()
    errors = check_targets(mapping, catalog)
    if errors:
        raise MappingError("; ".join(errors))
    stamp = resolve_now(now)
    base = clean_base_url(evidence_base_url) if evidence_base_url else None

    evidences: list[LogEvidence] = []
    for log in logs:
        ev = read_log(log, samples=samples, max_bytes=max_log_bytes)
        if base:
            ev = replace(ev, href=f"{base}/{ev.file_name}")
        evidences.append(ev)

    conv = build_results(
        evidences, mapping, catalog, now=stamp, oscal_version=oscal_version, findings=findings
    )
    if conv.converted == 0:
        raise BundleError("no log matched any mapping rule: " + "; ".join(conv.warnings))

    docs: dict[str, bytes] = {
        BUNDLE_FILES["ar"]: _dump(conv.document),
        BUNDLE_FILES["ap"]: _dump(_plan(conv.controls, stamp, oscal_version)),
        BUNDLE_FILES["ssp"]: _dump(_ssp(conv.controls, system_name, stamp, oscal_version)),
        BUNDLE_FILES["profile"]: _dump(_profile(conv.controls, stamp, oscal_version)),
        CATALOG_FILENAME: catalog_bytes(),
    }
    manifest = {
        "tool": f"{TOOL_NAME} {__version__}",
        "oscal-version": oscal_version,
        "mapping-sha256": mapping.sha256,
        "catalog-sha256": catalog.sha256,
        "statement": MANIFEST_STATEMENT,
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(docs.items())},
    }
    docs[MANIFEST_FILENAME] = _dump(manifest)

    out = Path(out_dir)
    with tempfile.TemporaryDirectory(prefix="inspect-oscal-") as tmp:
        staging = Path(tmp)
        for name, data in docs.items():
            (staging / name).write_bytes(data)
        report = check_integrity(staging)
        if report.errors:
            raise BundleError(
                "generated bundle failed integrity checks: " + "; ".join(report.errors)
            )
        stale = sorted(n for n in docs if (out / n).exists())
        if stale:
            conv.warnings.append(f"{out}: overwriting existing files: {', '.join(stale)}")
        out.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        for name, data in docs.items():
            path = out / name
            path.write_bytes(data)
            written.append(path)
    return Bundle(out, written, conv.warnings, conv.converted)
