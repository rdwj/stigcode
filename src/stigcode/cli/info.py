"""Info sub-commands: mapping database inspection."""

from __future__ import annotations

from pathlib import Path

import typer
import yaml

from stigcode.cli import info_app
from stigcode.cli.pipeline import _DEFAULT_CLASSIFICATIONS


@info_app.command(name="mappings")
def info_mappings(
    output: Path | None = typer.Option(
        None, "--output", "-o",
        help="Write full cross-reference matrix to this file.",
    ),
    xccdf_file: Path | None = typer.Option(
        None, "--xccdf", "-x",
        help="Path to DISA XCCDF XML for full finding metadata.",
    ),
    fmt: str = typer.Option(
        "md", "--format", "-f",
        help="Output format for --output: 'md' or 'csv'.",
    ),
) -> None:
    """Show mapping database stats; optionally write the cross-reference matrix."""
    from stigcode.data import get_cci_mappings, get_mapping_database

    if fmt not in ("md", "csv"):
        typer.echo(f"Error: --format must be 'md' or 'csv', got {fmt!r}", err=True)
        raise typer.Exit(code=2) from None

    try:
        db = get_mapping_database()
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    total = len(db.mappings)
    unique_cwes = len(db.all_cwe_ids())
    unique_stigs = len(db.all_stig_ids())

    by_confidence: dict[str, int] = {}
    for m in db.mappings:
        by_confidence[m.confidence] = by_confidence.get(m.confidence, 0) + 1

    typer.echo(f"Mapping database: {db.stig_name} {db.stig_version}  (v{db.version})")
    typer.echo(f"  Total mappings:  {total}")
    typer.echo(f"  Unique CWEs:     {unique_cwes}")
    typer.echo(f"  Unique STIGs:    {unique_stigs}")
    typer.echo("")
    typer.echo("  By confidence:")
    for level in ("direct", "inferred", "partial"):
        count = by_confidence.get(level, 0)
        typer.echo(f"    {level:10s}: {count}")

    if output is None:
        return

    # Build full cross-reference matrix
    from stigcode.ingest.xccdf import StigBenchmark, StigFinding, parse_xccdf
    from stigcode.output.xref import build_xref_matrix, write_xref

    if xccdf_file is not None:
        if not xccdf_file.exists():
            typer.echo(f"Error: XCCDF file not found: {xccdf_file}", err=True)
            raise typer.Exit(code=2) from None
        benchmark = parse_xccdf(xccdf_file)
    else:
        # Synthetic benchmark from mapping db + classifications
        cls_path = _DEFAULT_CLASSIFICATIONS
        if not cls_path.exists():
            typer.echo(
                f"Error: classifications file not found: {cls_path}", err=True
            )
            raise typer.Exit(code=2) from None
        raw_cls = yaml.safe_load(cls_path.read_text(encoding="utf-8"))
        classifications: dict = raw_cls.get("classifications", {})

        stig_ids = sorted(db.all_stig_ids())
        synthetic_findings: list[StigFinding] = []
        for sid in stig_ids:
            cls_data = classifications.get(sid, {})
            title = cls_data.get("title", sid) if isinstance(cls_data, dict) else sid
            synthetic_findings.append(StigFinding(
                vuln_id=sid,
                rule_id=f"{sid}_rule",
                check_id="",
                title=title,
                description="",
                severity="medium",
                category=2,
                cci_refs=[],
                fix_text="",
                check_content="",
            ))
        benchmark = StigBenchmark(
            benchmark_id="synthetic",
            title=f"{db.stig_name} {db.stig_version}",
            version="",
            release="",
            date="",
            findings=synthetic_findings,
            profiles={},
        )

    cls_path = _DEFAULT_CLASSIFICATIONS
    raw_cls = yaml.safe_load(cls_path.read_text(encoding="utf-8"))
    classifications = raw_cls.get("classifications", {})

    try:
        cci_mappings = get_cci_mappings()
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    entries = build_xref_matrix(benchmark, db, cci_mappings, classifications)
    write_xref(entries, output, fmt=fmt, benchmark_title=benchmark.title)
    typer.echo(
        f"\nCross-reference matrix ({len(entries)} entries) written to {output}",
        err=True,
    )
