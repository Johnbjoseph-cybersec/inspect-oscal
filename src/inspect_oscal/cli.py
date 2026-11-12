"""Command line interface. Exit codes: 0 ok, 1 usage or IO, 2 strict failure, 3 validation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .bundle import BundleError, convert_logs
from .catalog import CatalogError, load_catalog
from .constants import (
    AI_RMF_CATALOG_SHA256,
    CATALOG_SOURCE,
    OSCAL_VERSION,
    __version__,
)
from .logread import LogReadError
from .mapping import MappingError, check_targets, default_mapping_text, load_mapping
from .redact import redact
from .validate import find_oscal_cli, validate_bundle


@click.group()
@click.version_option(__version__, prog_name="inspect-oscal")
def cli() -> None:
    """Convert Inspect eval logs into OSCAL assessment-results evidence (unofficial).

    Output is evidence. The mapping is derived by the user and is not NIST-endorsed. Finding
    statuses (opt-in) record only whether a user-declared threshold was met.
    """


@cli.command()
@click.argument("logs", nargs=-1, required=True)
@click.option("-o", "--out", "out_dir", required=True, type=click.Path(path_type=Path))
@click.option("--mapping", "mapping_file", type=click.Path(exists=True, path_type=Path))
@click.option("--system-name", default="Evaluated AI system", show_default=True)
@click.option(
    "--samples/--no-samples",
    default=True,
    show_default=True,
    help="Read samples to count abnormal scores (counts only). Off skips that check.",
)
@click.option(
    "--findings",
    is_flag=True,
    help="Also write OSCAL findings recording whether your declared thresholds were met "
    "(not a determination about any subcategory). Off by default: observations only.",
)
@click.option("--strict", is_flag=True, help="Exit 2 if any warning was raised.")
@click.option("--oscal-version", default=OSCAL_VERSION, show_default=True)
@click.option("--now", default=None, help="ISO 8601 clock override (else SOURCE_DATE_EPOCH).")
@click.option("--evidence-base-url", default=None, help="Where the logs will be hosted.")
def convert(
    logs: tuple[str, ...],
    out_dir: Path,
    mapping_file: Path | None,
    system_name: str,
    samples: bool,
    findings: bool,
    strict: bool,
    oscal_version: str,
    now: str | None,
    evidence_base_url: str | None,
) -> None:
    """Convert LOGS (.eval or .json, paths or URLs) into an OSCAL bundle in OUT."""
    bundle = convert_logs(
        list(logs),
        out_dir=out_dir,
        mapping=load_mapping(mapping_file),
        system_name=system_name,
        samples=samples,
        findings=findings,
        oscal_version=oscal_version,
        now=now,
        evidence_base_url=evidence_base_url,
    )
    for warning in bundle.warnings:
        click.echo(f"warning: {redact(warning)}", err=True)
    click.echo(f"wrote {len(bundle.files)} files for {bundle.results} log(s) to {bundle.out_dir}")
    if strict and bundle.warnings:
        sys.exit(2)


@cli.command()
@click.argument("out_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--oscal-cli", "oscal_cli", default=None, help="Path to the oscal-cli executable.")
@click.option("--json", "as_json", is_flag=True)
def validate(out_dir: Path, oscal_cli: str | None, as_json: bool) -> None:
    """Validate a bundle: integrity and honesty checks, plus oscal-cli when available."""
    cli_path = find_oscal_cli(oscal_cli)
    report = validate_bundle(out_dir, use_oscal_cli=cli_path is not None, oscal_cli=cli_path)
    if cli_path is None:
        report.warnings.append("oscal-cli not found; schema validation not run")
    if as_json:
        click.echo(json.dumps(report.to_json(), indent=2))
    else:
        for line in report.checks:
            click.echo(f"ok: {line}")
        for line in report.warnings:
            click.echo(f"warning: {redact(line)}")
        for line in report.errors:
            click.echo(f"error: {redact(line)}")
        click.echo("VALID" if report.ok else "INVALID")
    if not report.ok:
        sys.exit(3)


@cli.group()
def mapping() -> None:
    """Work with the mapping file."""


@mapping.command("init")
def mapping_init() -> None:
    """Print the default mapping so you can edit and own it."""
    click.echo(default_mapping_text(), nl=False)


@mapping.command("check")
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def mapping_check(file: Path) -> None:
    """Check FILE parses and every target id exists in the pinned catalog."""
    loaded = load_mapping(file)
    errors = check_targets(loaded, load_catalog())
    for err in errors:
        click.echo(f"error: {redact(err)}", err=True)
    if errors:
        sys.exit(1)
    click.echo(f"ok: {len(loaded.rules)} rules, {len(loaded.all_targets())} targets")


@cli.group()
def catalog() -> None:
    """Inspect the vendored NIST AI RMF catalog."""


@catalog.command("info")
def catalog_info() -> None:
    """Describe the vendored catalog."""
    cat = load_catalog()
    click.echo(f"NIST AI RMF 1.0 OSCAL catalog, {len(cat.control_ids)} controls")
    click.echo(f"sha256: {cat.sha256}")
    click.echo(f"source: {CATALOG_SOURCE}")
    click.echo("licence: public domain / CC0 1.0 (see NIST_LICENSE.md in the package data)")


@catalog.command("verify")
def catalog_verify() -> None:
    """Re-check the vendored catalog against its pinned hash."""
    load_catalog()
    click.echo(f"ok: catalog matches pinned {AI_RMF_CATALOG_SHA256}")


def main() -> None:
    """Console entry point with the documented exit codes."""
    try:
        cli(standalone_mode=False)
    except click.exceptions.Exit as exc:
        sys.exit(exc.exit_code)
    except click.Abort:
        sys.exit(1)
    except click.ClickException as exc:
        click.echo(f"error: {redact(exc.format_message())}", err=True)
        sys.exit(1)
    except (BundleError, MappingError, LogReadError, CatalogError) as exc:
        click.echo(f"error: {redact(str(exc))}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
