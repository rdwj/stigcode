"""Shared pipeline loader for commands that process SARIF input."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
import yaml

from stigcode.data import get_data_dir, get_stig_profile


def _resolve_stig_paths(
    mapping_file: Path | None,
    classifications_file: Path | None,
    xccdf_file: Path | None,
    stig: str | None,
) -> tuple[Path, Path, Path | None]:
    """Resolve mapping, classifications, and XCCDF paths.

    Priority:
    1. Explicit CLI flags (--mappings, --classifications, --xccdf)
    2. STIG profile lookup via --stig or the default profile
    """
    try:
        profile = get_stig_profile(stig)
    except KeyError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    resolved_mapping = mapping_file or profile.mapping_file
    resolved_classifications = classifications_file or profile.classifications_file
    resolved_xccdf = xccdf_file or profile.xccdf_file

    return resolved_mapping, resolved_classifications, resolved_xccdf


def load_pipeline(
    sarif_file: str,
    mapping_file: Path | None,
    classifications_file: Path | None,
    xccdf_file: Path | None,
    stig: str | None = None,
):
    """Load all inputs and run status determination.

    Handles stdin, default paths, and the synthetic-benchmark fallback.

    Args:
        sarif_file: Path to a SARIF file, or ``"-"`` for stdin.
        mapping_file: Explicit mapping file override.
        classifications_file: Explicit classifications file override.
        xccdf_file: Explicit XCCDF file override.
        stig: STIG profile key (e.g. ``"asd"``). Uses the default if None.

    Returns:
        Tuple of (StatusReport, StigBenchmark, MappingDatabase, SarifResult)

    Raises:
        typer.Exit(code=2) on any error with a user-facing message printed
        to stderr.
    """
    from stigcode.ingest.sarif import parse_sarif
    from stigcode.ingest.xccdf import StigBenchmark, StigFinding, parse_xccdf
    from stigcode.mapping.engine import load_mapping_database
    from stigcode.mapping.status import determine_status

    # --- Resolve STIG profile paths ---
    mapping_path, cls_path, xccdf_path = _resolve_stig_paths(
        mapping_file, classifications_file, xccdf_file, stig,
    )

    # --- Load SARIF ---
    if sarif_file == "-":
        content = sys.stdin.read()
        sarif_result = parse_sarif(content)
    else:
        path = Path(sarif_file)
        if not path.exists():
            typer.echo(f"Error: SARIF file not found: {path}", err=True)
            raise typer.Exit(code=2)
        sarif_result = parse_sarif(path)

    if sarif_result.errors:
        for err in sarif_result.errors:
            typer.echo(f"Warning: {err}", err=True)

    # --- Load mapping database ---
    if not mapping_path.exists():
        typer.echo(f"Error: mapping file not found: {mapping_path}", err=True)
        typer.echo(
            "Provide --mappings or ensure the bundled mapping data is installed.",
            err=True,
        )
        raise typer.Exit(code=2)
    db = load_mapping_database(mapping_path)

    # --- Load classifications ---
    if not cls_path.exists():
        typer.echo(f"Error: classifications file not found: {cls_path}", err=True)
        raise typer.Exit(code=2)
    raw_cls = yaml.safe_load(cls_path.read_text(encoding="utf-8"))
    classifications: dict = raw_cls.get("classifications", {})

    # --- Load benchmark (real XCCDF or synthetic fallback) ---
    if xccdf_path is not None and xccdf_path.exists():
        benchmark = parse_xccdf(xccdf_path)
    elif xccdf_file is not None:
        # User explicitly passed --xccdf but file doesn't exist
        typer.echo(f"Error: XCCDF file not found: {xccdf_file}", err=True)
        raise typer.Exit(code=2)
    else:
        stig_ids = sorted(db.all_stig_ids())
        synthetic_findings: list[StigFinding] = [
            StigFinding(
                vuln_id=stig_id,
                rule_id=f"{stig_id}_rule",
                check_id="",
                title=stig_id,
                description="",
                severity="medium",
                category=2,
                cci_refs=[],
                fix_text="",
                check_content="",
            )
            for stig_id in stig_ids
        ]
        benchmark = StigBenchmark(
            benchmark_id="synthetic",
            title="Synthetic benchmark from mapping database",
            version="",
            release="",
            date="",
            findings=synthetic_findings,
            profiles={},
        )

    # --- Determine status ---
    report = determine_status(sarif_result.findings, db, benchmark, classifications)

    return report, benchmark, db, sarif_result
