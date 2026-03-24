"""Stig sub-commands: XCCDF import and benchmark management."""

from __future__ import annotations

from pathlib import Path

import typer

from stigcode.cli import ISSUES_URL, stig_app


def _not_implemented(issue: int) -> None:
    """Print a standard 'not yet implemented' message and exit 2."""
    typer.echo(f"Not yet implemented. See: {ISSUES_URL}/{issue}", err=True)
    raise typer.Exit(code=2)


@stig_app.command(name="import-xccdf")
def stig_import_xccdf(
    xccdf_file: Path = typer.Argument(
        ..., help="Path to a DISA XCCDF XML file."
    ),
) -> None:
    """Import a STIG from a DISA XCCDF XML file, printing a summary."""
    try:
        from stigcode.ingest.xccdf import parse_xccdf
    except ImportError:
        _not_implemented(9)
        return

    if not xccdf_file.exists():
        typer.echo(f"Error: file not found: {xccdf_file}", err=True)
        raise typer.Exit(code=2)

    benchmark = parse_xccdf(xccdf_file)

    by_cat: dict[int, int] = {}
    for finding in benchmark.findings:
        cat = finding.category
        by_cat[cat] = by_cat.get(cat, 0) + 1

    typer.echo(f"Benchmark: {benchmark.title}")
    typer.echo(
        f"Version {benchmark.version}, Release {benchmark.release} ({benchmark.date})"
    )
    typer.echo(f"Findings: {len(benchmark.findings)}")
    for cat in sorted(by_cat):
        typer.echo(f"  CAT {cat}: {by_cat[cat]}")
