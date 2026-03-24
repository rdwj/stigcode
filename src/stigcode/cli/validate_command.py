"""validate-sarif CLI command — check a SARIF file for stigcode compatibility."""

from __future__ import annotations

from pathlib import Path

import typer

from stigcode.cli import REPO_URL, app
from stigcode.ingest.validate import ValidationResult, validate_sarif

_GUIDE_URL = f"{REPO_URL}/blob/main/docs/sarif-integration-guide.md"

# Icons for issue levels in terminal output
_LEVEL_ICONS = {
    "error": "✗",
    "warning": "⚠",
    "info": "ℹ",
}

# Display order for CWE coverage methods
_METHOD_LABELS = {
    "properties.stigIds": "Explicit STIG IDs (properties.stigIds)",
    "properties.cweIds": "CWE IDs in result properties",
    "rule.tags": "Rule tags (external/cwe/cwe-NNN)",
    "rule.relationships": "Rule taxonomy relationships",
    "message.text": "CWE in message text (fallback)",
    "none": "No CWE information",
}

_TIER_DESCRIPTIONS = {
    "enriched": "enriched (direct STIG mapping)",
    "standard": "standard (CWE-based mapping)",
    "minimal": "minimal (rule-ID heuristics only)",
}


@app.command(name="validate")
def validate_sarif_cmd(
    sarif_file: Path = typer.Argument(..., help="Path to a SARIF file to validate."),
    strict: bool = typer.Option(False, "--strict", help="Treat warnings as errors."),
) -> None:
    """Validate a SARIF file for stigcode compatibility.

    Checks structure, CWE coverage, and compliance metadata enrichment.
    Exits 0 if valid, 1 if warnings (or errors in --strict), 2 if invalid.
    """
    if not sarif_file.exists():
        typer.echo(f"Error: file not found: {sarif_file}", err=True)
        raise typer.Exit(code=2)

    result = validate_sarif(sarif_file)

    _print_report(sarif_file, result, strict=strict)

    errors = [i for i in result.issues if i.level == "error"]
    warnings = [i for i in result.issues if i.level == "warning"]

    if errors or (strict and warnings):
        raise typer.Exit(code=2)
    if warnings:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def _print_report(path: Path, result: ValidationResult, *, strict: bool) -> None:
    typer.echo(f"\nValidating: {path.name}\n")

    # Scanner / version header
    scanner = result.scanner_name or "unknown"
    version = result.scanner_version
    scanner_str = f"{scanner} v{version}" if version else scanner
    typer.echo(f"Scanner:      {scanner_str}")
    typer.echo(f"SARIF version: {result.sarif_version or 'unknown'}")
    tier_desc = _TIER_DESCRIPTIONS.get(result.tier, result.tier)
    typer.echo(f"Tier:         {tier_desc}")
    typer.echo("")

    # Results summary
    typer.echo(f"Results: {result.total_results} findings across {result.total_rules} rules")
    typer.echo("")

    # CWE coverage
    if result.cwe_coverage:
        typer.echo("CWE Coverage:")
        for method, count in result.cwe_coverage.items():
            label = _METHOD_LABELS.get(method, method)
            typer.echo(f"  {label}: {count} result{'s' if count != 1 else ''}")
        typer.echo("")

    # Issues (warnings + errors; skip info for cleaner output)
    visible = [i for i in result.issues if i.level in ("error", "warning")]
    info_issues = [i for i in result.issues if i.level == "info"]

    if visible:
        typer.echo("Issues:")
        for issue in visible:
            icon = _LEVEL_ICONS.get(issue.level, "?")
            typer.echo(f"  {icon} {issue.message}")
            if issue.location not in ("<summary>", "<file>", "<root>"):
                typer.echo(f"    at {issue.location}")
        typer.echo("")

    for issue in info_issues:
        icon = _LEVEL_ICONS.get(issue.level, "?")
        typer.echo(f"  {icon} {issue.message}")
    if info_issues:
        typer.echo("")

    # Verdict
    errors = [i for i in result.issues if i.level == "error"]
    warnings = [i for i in result.issues if i.level == "warning"]

    if errors:
        error_count = len(errors)
        typer.echo(f"Verdict: INVALID ({error_count} error{'s' if error_count != 1 else ''})")
    elif strict and warnings:
        typer.echo(f"Verdict: INVALID (--strict: {len(warnings)} warning(s) treated as errors)")
    elif warnings:
        typer.echo(f"Verdict: VALID ({len(warnings)} warning{'s' if len(warnings) != 1 else ''})")
    else:
        typer.echo("Verdict: VALID")
