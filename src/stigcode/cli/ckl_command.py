"""CKL generation command — secondary output for AppDev STIG checklists."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from stigcode.cli import app
from stigcode.cli.pipeline import load_pipeline


@app.command()
def ckl(
    sarif_file: str = typer.Argument(
        ..., help="Path to SARIF file, or '-' to read from stdin."
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output .ckl file path. Prints to stdout if omitted.",
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
    host_name: str = typer.Option(
        "", "--host-name", help="Target host name for the CKL ASSET block."
    ),
    host_ip: str = typer.Option(
        "", "--host-ip", help="Target host IP for the CKL ASSET block."
    ),
    classification: str = typer.Option(
        "UNCLASSIFIED", "--classification",
        help="Classification marking (e.g. UNCLASSIFIED, CUI).",
    ),
    update_ckl_file: Optional[Path] = typer.Option(
        None, "--update", "-u",
        help="Path to an existing CKL to update incrementally (preserves assessor notes).",
    ),
) -> None:
    """Generate a STIG Viewer checklist (.ckl) from SARIF scan results."""
    from stigcode.output.ckl import generate_ckl, write_ckl, AssetInfo

    rpt, benchmark, db, _sarif_result = load_pipeline(
        sarif_file, mapping_file, classifications_file, xccdf_file
    )

    asset = AssetInfo(host_name=host_name, host_ip=host_ip)

    if update_ckl_file is not None:
        _handle_update(update_ckl_file, rpt, benchmark, output, asset, classification)
    elif output is not None:
        write_ckl(rpt, benchmark, output, asset, classification)
        typer.echo(f"CKL written to {output}", err=True)
    else:
        typer.echo(generate_ckl(rpt, benchmark, asset, classification))


def _handle_update(update_ckl_file, rpt, benchmark, output, asset, classification):
    """Handle the --update flow for incremental CKL updates."""
    if not update_ckl_file.exists():
        typer.echo(
            f"Error: existing CKL not found: {update_ckl_file}", err=True
        )
        raise typer.Exit(code=2)
    if output is None:
        typer.echo(
            "Error: --update requires --output to specify the destination path.",
            err=True,
        )
        raise typer.Exit(code=2)

    from stigcode.output.ckl_update import update_ckl as _update_ckl

    ckl_result = _update_ckl(
        update_ckl_file, rpt, benchmark, output, asset, classification
    )

    typer.echo(f"CKL updated: {output}", err=True)
    typer.echo(
        f"  {ckl_result.updated_count} updated, "
        f"{ckl_result.preserved_count} preserved, "
        f"{len(ckl_result.conflicts)} conflicts "
        f"(of {ckl_result.total_findings} total findings)",
        err=True,
    )
    if ckl_result.conflicts:
        typer.echo("Conflicts requiring manual review:", err=True)
        for c in ckl_result.conflicts:
            typer.echo(
                f"  {c.stig_id}: was {c.existing_status}, "
                f"new scan says {c.new_status} — {c.reason}",
                err=True,
            )
