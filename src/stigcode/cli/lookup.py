"""Lookup sub-commands: cwe and stig reverse lookups."""

from __future__ import annotations

import typer

from stigcode.cli import lookup_app


@lookup_app.command(name="cwe")
def lookup_cwe(
    cwe_id: str = typer.Option(
        ..., "--cwe", help="CWE ID to look up (e.g. '89' or 'CWE-89')."
    ),
) -> None:
    """Look up STIG findings mapped to a CWE ID."""
    from stigcode.data import get_mapping_database

    # Accept "89" or "CWE-89"
    raw = cwe_id.upper().lstrip("CWE-").lstrip("0") or "0"
    raw = cwe_id.replace("CWE-", "").replace("cwe-", "").strip()
    try:
        numeric_id = int(raw)
    except ValueError:
        typer.echo(f"Error: '{cwe_id}' is not a valid CWE ID.", err=True)
        raise typer.Exit(code=2) from None

    try:
        db = get_mapping_database()
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    matches = db.lookup_by_cwe(numeric_id)
    if not matches:
        typer.echo(f"No STIG mappings found for CWE-{numeric_id}.")
        return

    typer.echo(f"CWE-{numeric_id} maps to {len(matches)} STIG finding(s):\n")
    for m in sorted(matches, key=lambda x: x.stig_id):
        typer.echo(f"  {m.stig_id}  ({m.check_id})")
        typer.echo("    Severity:   (see XCCDF for CAT)")
        typer.echo(f"    Confidence: {m.confidence}")
        typer.echo(f"    NIST:       {m.nist_control}")
        if m.notes:
            typer.echo(f"    Notes:      {m.notes}")
        typer.echo("")


@lookup_app.command(name="stig")
def lookup_stig(
    stig_id: str = typer.Option(
        ..., "--stig", help="STIG Vuln ID to look up (e.g. 'V-222387')."
    ),
) -> None:
    """Look up CWE mappings for a STIG finding."""
    from stigcode.data import get_mapping_database

    # Accept "V-222607" or "222607"
    normalized = stig_id if stig_id.startswith("V-") else f"V-{stig_id}"

    try:
        db = get_mapping_database()
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    matches = db.lookup_by_stig(normalized)
    if not matches:
        typer.echo(f"No CWE mappings found for {normalized}.")
        return

    typer.echo(f"{normalized} maps to {len(matches)} CWE(s):\n")
    for m in sorted(matches, key=lambda x: x.cwe_id):
        typer.echo(f"  CWE-{m.cwe_id}")
        typer.echo(f"    Check ID:   {m.check_id}")
        typer.echo(f"    Confidence: {m.confidence}")
        typer.echo(f"    NIST:       {m.nist_control}")
        if m.cci_refs:
            typer.echo(f"    CCI refs:   {', '.join(m.cci_refs)}")
        if m.notes:
            typer.echo(f"    Notes:      {m.notes}")
        typer.echo("")
