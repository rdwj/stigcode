"""Output-generating CLI commands: report, coverage, poam."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from stigcode.cli import app
from stigcode.cli.pipeline import load_pipeline


@app.command()
def report(
    sarif_file: str = typer.Argument(
        ..., help="Path to SARIF file, or '-' to read from stdin."
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output file path. Prints to stdout if omitted.",
    ),
    xccdf_file: Optional[Path] = typer.Option(
        None, "--xccdf", "-x",
        help="Path to DISA XCCDF XML file for full benchmark metadata.",
    ),
    mapping_file: Optional[Path] = typer.Option(
        None, "--mappings", "-m",
        help="Path to CWE-to-STIG mapping YAML.",
    ),
    classifications_file: Optional[Path] = typer.Option(
        None, "--classifications", "-c",
        help="Path to finding classifications YAML.",
    ),
    fmt: str = typer.Option(
        "md", "--format", "-f",
        help="Output format. Only 'md' (Markdown) is supported.",
    ),
) -> None:
    """Generate an ATO evidence summary report from SARIF scan results."""
    if fmt != "md":
        typer.echo(
            f"Error: unsupported format '{fmt}'. Only 'md' is supported.", err=True
        )
        raise typer.Exit(code=2)

    from stigcode.output.report import generate_report, write_report

    rpt, benchmark, db, _sarif_result = load_pipeline(
        sarif_file, mapping_file, classifications_file, xccdf_file
    )

    if output is not None:
        write_report(rpt, benchmark, db, output)
        typer.echo(f"Report written to {output}", err=True)
    else:
        typer.echo(generate_report(rpt, benchmark, db))


@app.command()
def coverage(
    sarif_file: str = typer.Argument(
        ..., help="Path to SARIF file, or '-' to read from stdin."
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output file path. Prints to stdout if omitted.",
    ),
    xccdf_file: Optional[Path] = typer.Option(
        None, "--xccdf", "-x",
        help="Path to DISA XCCDF XML file for full benchmark metadata.",
    ),
    mapping_file: Optional[Path] = typer.Option(
        None, "--mappings", "-m",
        help="Path to CWE-to-STIG mapping YAML.",
    ),
    classifications_file: Optional[Path] = typer.Option(
        None, "--classifications", "-c",
        help="Path to finding classifications YAML.",
    ),
    fmt: str = typer.Option(
        "md", "--format", "-f",
        help="Output format: 'md' (Markdown) or 'csv'.",
    ),
) -> None:
    """Generate a NIST 800-53 coverage matrix from imported findings."""
    if fmt not in ("md", "csv"):
        typer.echo(
            f"Error: --format must be 'md' or 'csv', got {fmt!r}", err=True
        )
        raise typer.Exit(code=2)

    from stigcode.data import get_cci_mappings
    from stigcode.output.coverage import (
        build_coverage_matrix,
        matrix_to_csv,
        matrix_to_markdown,
        write_coverage,
    )

    rpt, benchmark, db, _sarif_result = load_pipeline(
        sarif_file, mapping_file, classifications_file, xccdf_file
    )

    try:
        cci_mappings = get_cci_mappings()
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2)

    matrix = build_coverage_matrix(rpt, benchmark, cci_mappings, mapping_db=db)

    if output is not None:
        write_coverage(matrix, output, fmt=fmt)
        typer.echo(f"Coverage matrix written to {output}", err=True)
    else:
        if fmt == "md":
            typer.echo(matrix_to_markdown(matrix))
        else:
            typer.echo(matrix_to_csv(matrix))


@app.command()
def poam(
    sarif_file: str = typer.Argument(
        ..., help="Path to SARIF file, or '-' to read from stdin."
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output file path. Prints to stdout if omitted.",
    ),
    xccdf_file: Optional[Path] = typer.Option(
        None, "--xccdf", "-x",
        help="Path to DISA XCCDF XML file for full benchmark metadata.",
    ),
    mapping_file: Optional[Path] = typer.Option(
        None, "--mappings", "-m",
        help="Path to CWE-to-STIG mapping YAML.",
    ),
    classifications_file: Optional[Path] = typer.Option(
        None, "--classifications", "-c",
        help="Path to finding classifications YAML.",
    ),
    fmt: str = typer.Option(
        "md", "--format", "-f",
        help="Output format: 'md' or 'csv'.",
    ),
) -> None:
    """Generate POA&M candidates from open findings."""
    if fmt not in ("md", "csv"):
        typer.echo(
            f"Error: --format must be 'md' or 'csv', got {fmt!r}", err=True
        )
        raise typer.Exit(code=2)

    from stigcode.data import get_cci_mappings
    from stigcode.output.poam import build_poam, write_poam, poam_to_markdown, poam_to_csv

    rpt, benchmark, db, sarif_result = load_pipeline(
        sarif_file, mapping_file, classifications_file, xccdf_file
    )

    try:
        cci_mappings = get_cci_mappings()
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2)

    poam_report = build_poam(
        report=rpt,
        benchmark=benchmark,
        mapping_db=db,
        cci_mappings=cci_mappings,
        scanner_name=sarif_result.scanner_name,
        scanner_version=sarif_result.scanner_version,
    )

    if output is not None:
        write_poam(poam_report, output, fmt=fmt)
        typer.echo(f"POA&M written to {output}", err=True)
    else:
        if fmt == "md":
            typer.echo(poam_to_markdown(poam_report))
        else:
            typer.echo(poam_to_csv(poam_report))
