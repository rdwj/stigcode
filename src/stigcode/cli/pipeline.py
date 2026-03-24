"""Shared pipeline loader for commands that process SARIF input."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
import yaml

from stigcode.data import get_data_dir

_DEFAULT_MAPPING = get_data_dir() / "mappings" / "asd_stig_v6r3.yaml"
_DEFAULT_CLASSIFICATIONS = get_data_dir() / "mappings" / "finding_classifications.yaml"


def load_pipeline(
    sarif_file: str,
    mapping_file: Path | None,
    classifications_file: Path | None,
    xccdf_file: Path | None,
):
    """Load all inputs and run status determination.

    Handles stdin, default paths, and the synthetic-benchmark fallback.

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
    mapping_path = mapping_file or _DEFAULT_MAPPING
    if not mapping_path.exists():
        typer.echo(f"Error: mapping file not found: {mapping_path}", err=True)
        typer.echo(
            "Provide --mappings or ensure the bundled mapping data is installed.",
            err=True,
        )
        raise typer.Exit(code=2)
    db = load_mapping_database(mapping_path)

    # --- Load classifications ---
    cls_path = classifications_file or _DEFAULT_CLASSIFICATIONS
    if not cls_path.exists():
        typer.echo(f"Error: classifications file not found: {cls_path}", err=True)
        raise typer.Exit(code=2)
    raw_cls = yaml.safe_load(cls_path.read_text(encoding="utf-8"))
    classifications: dict = raw_cls.get("classifications", {})

    # --- Load benchmark (real XCCDF or synthetic fallback) ---
    if xccdf_file is not None:
        if not xccdf_file.exists():
            typer.echo(f"Error: XCCDF file not found: {xccdf_file}", err=True)
            raise typer.Exit(code=2)
        benchmark = parse_xccdf(xccdf_file)
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
