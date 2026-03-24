"""Simple top-level CLI commands: version, import, assess."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer

from stigcode.cli import app, DESCRIPTION, REPO_URL, ISSUES_URL
from stigcode.cli.pipeline import load_pipeline
from stigcode.version import __version__


def _not_implemented(issue: int) -> None:
    """Print a standard 'not yet implemented' message and exit 2."""
    typer.echo(f"Not yet implemented. See: {ISSUES_URL}/{issue}", err=True)
    raise typer.Exit(code=2)


@app.command()
def version() -> None:
    """Print version and exit."""
    typer.echo(f"stigcode {__version__}")
    typer.echo(DESCRIPTION)
    typer.echo(REPO_URL)


@app.command(name="import")
def import_sarif(
    sarif_file: str = typer.Argument(
        ..., help="Path to SARIF file, or '-' to read from stdin."
    ),
) -> None:
    """Import and normalize a SARIF file, printing a findings summary."""
    try:
        from stigcode.ingest.sarif import parse_sarif
    except ImportError:
        _not_implemented(2)
        return  # unreachable; satisfies type checkers

    if sarif_file == "-":
        content = sys.stdin.read()
        result = parse_sarif(content)
    else:
        path = Path(sarif_file)
        if not path.exists():
            typer.echo(f"Error: file not found: {path}", err=True)
            raise typer.Exit(code=2)
        result = parse_sarif(path)

    findings = result.findings
    scanner = getattr(result, "scanner_name", "unknown")

    by_severity: dict[str, int] = {}
    for f in findings:
        sev = getattr(f, "severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    typer.echo(f"Scanner: {scanner}")
    typer.echo(f"Findings: {len(findings)}")
    for sev in ("CAT I", "CAT II", "CAT III"):
        count = by_severity.get(sev, 0)
        if count:
            typer.echo(f"  {sev}: {count}")


@app.command()
def assess(
    sarif_file: str = typer.Argument(
        ..., help="Path to SARIF file, or '-' to read from stdin."
    ),
    xccdf_file: Optional[Path] = typer.Option(
        None, "--xccdf", "-x",
        help="Path to DISA XCCDF XML file.",
    ),
    mapping_file: Optional[Path] = typer.Option(
        None, "--mappings", "-m",
        help="Path to CWE-to-STIG mapping YAML.",
    ),
    classifications_file: Optional[Path] = typer.Option(
        None, "--classifications", "-c",
        help="Path to finding classifications YAML.",
    ),
) -> None:
    """Assess a SARIF scan against a STIG benchmark and print a status summary."""
    from stigcode.mapping.status import CklStatus

    rpt, benchmark, _db, _sarif_result = load_pipeline(
        sarif_file, mapping_file, classifications_file, xccdf_file
    )

    typer.echo(f"Scanner: {rpt.scan_summary['scanner_name'] or 'unknown'}")
    typer.echo(f"SARIF findings: {rpt.scan_summary['total_sarif_findings']}")
    typer.echo(f"STIG findings assessed: {rpt.scan_summary['total_stig_findings']}")
    typer.echo("")
    typer.echo("Status summary:")
    typer.echo(f"  Open:          {rpt.open_count}")
    typer.echo(f"  Not a finding: {rpt.not_a_finding_count}")
    typer.echo(f"  Not reviewed:  {rpt.not_reviewed_count}")

    if rpt.open_count:
        typer.echo("")
        typer.echo("Open findings by category:")
        by_cat: dict[int, int] = {}
        open_dets = [d for d in rpt.determinations if d.status == CklStatus.OPEN]
        cat_by_stig = {f.vuln_id: f.category for f in benchmark.findings}
        for det in open_dets:
            cat = cat_by_stig.get(det.stig_id, 2)
            by_cat[cat] = by_cat.get(cat, 0) + 1
        for cat in sorted(by_cat):
            typer.echo(f"  CAT {cat}: {by_cat[cat]}")
