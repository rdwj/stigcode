"""OSCAL Assessment Results generation command."""

from __future__ import annotations

from pathlib import Path

import typer

from stigcode.cli import app
from stigcode.cli.pipeline import load_pipeline


@app.command()
def oscal(
    sarif_file: str = typer.Argument(
        ..., help="Path to SARIF file, or '-' to read from stdin."
    ),
    output: Path = typer.Option(
        ..., "--output", "-o",
        help="Output JSON file path (required).",
    ),
    xccdf_file: Path | None = typer.Option(
        None, "--xccdf", "-x",
        help="Path to DISA XCCDF XML file for full benchmark metadata.",
    ),
    mapping_file: Path | None = typer.Option(
        None, "--mappings", "-m",
        help="Path to CWE-to-STIG mapping YAML.",
    ),
    classifications_file: Path | None = typer.Option(
        None, "--classifications", "-c",
        help="Path to finding classifications YAML.",
    ),
    stig: str | None = typer.Option(
        None, "--stig", "-s",
        help="STIG profile to use (e.g., 'asd'). Defaults to the default profile.",
    ),
) -> None:
    """Generate NIST OSCAL Assessment Results JSON."""
    from stigcode.data import get_cci_mappings
    from stigcode.output.oscal import write_oscal

    rpt, benchmark, db, _sarif_result = load_pipeline(
        sarif_file, mapping_file, classifications_file, xccdf_file, stig=stig
    )

    try:
        cci_mappings = get_cci_mappings()
    except FileNotFoundError:
        cci_mappings = {}

    write_oscal(rpt, benchmark, db, cci_mappings, output)
    typer.echo(f"OSCAL Assessment Results written to {output}", err=True)
