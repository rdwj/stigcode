"""CLI command: stigcode trend — CA-7 trend analysis across multiple SARIF scans."""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from stigcode.cli import app


@app.command()
def trend(
    sarif_files: list[str] = typer.Argument(
        ...,
        help="SARIF files or a single directory containing *.sarif files.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write output to this file instead of stdout.",
    ),
    since: str | None = typer.Option(
        None,
        "--since",
        help="Only include scans on or after this date (YYYY-MM-DD).",
    ),
    fmt: str = typer.Option(
        "md",
        "--format",
        "-f",
        help="Output format: 'md' (Markdown) or 'csv'.",
    ),
) -> None:
    """Analyze finding trends across multiple SARIF scans (CA-7 evidence)."""
    from stigcode.output.trend import analyze_trend, load_scan_snapshots, trend_to_markdown

    # Resolve paths: directory glob or explicit file list
    resolved: list[Path] = []
    for arg in sarif_files:
        p = Path(arg)
        if p.is_dir():
            resolved.extend(sorted(p.glob("*.sarif")))
        elif p.exists():
            resolved.append(p)
        else:
            typer.echo(f"Error: not found: {p}", err=True)
            raise typer.Exit(code=2) from None

    if not resolved:
        typer.echo("Error: no SARIF files found.", err=True)
        raise typer.Exit(code=2) from None

    # Apply --since date filter
    if since:
        from datetime import datetime, timezone

        try:
            cutoff = datetime.strptime(since, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            typer.echo(
                f"Error: --since value '{since}' must be in YYYY-MM-DD format.", err=True
            )
            raise typer.Exit(code=2) from None

        from stigcode.output.trend import _extract_scan_date

        resolved = [p for p in resolved if _extract_scan_date(p) >= cutoff]
        if not resolved:
            typer.echo(
                f"No SARIF files found on or after {since}.", err=True
            )
            raise typer.Exit(code=2) from None

    if len(resolved) < 2:
        typer.echo(
            f"Note: only {len(resolved)} scan(s) found — trend analysis works best "
            "with two or more scans.",
            err=True,
        )

    snapshots = load_scan_snapshots(resolved)
    report = analyze_trend(snapshots)

    if fmt == "csv":
        content = _render_csv(report)
    else:
        content = trend_to_markdown(report)

    if output:
        output.write_text(content, encoding="utf-8")
        typer.echo(f"Trend report written to {output}")
    else:
        sys.stdout.write(content)


# ---------------------------------------------------------------------------
# CSV renderer (simple, keeps output.trend focused on Markdown)
# ---------------------------------------------------------------------------

def _render_csv(report) -> str:  # type: ignore[no-untyped-def]
    """Render trend report as CSV (per-finding rows)."""
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["status", "rule_id", "cwe_ids", "severity", "file_path",
         "first_seen", "last_seen", "seen_in_scans", "message"]
    )
    all_entries = (
        report.new_findings + report.persistent_findings + report.remediated_findings
    )
    for e in sorted(all_entries, key=lambda x: (x.status, x.severity, x.rule_id)):
        writer.writerow(
            [
                e.status,
                e.rule_id,
                "|".join(f"CWE-{c}" for c in e.cwe_ids),
                e.severity,
                e.file_path,
                e.first_seen.strftime("%Y-%m-%d"),
                e.last_seen.strftime("%Y-%m-%d"),
                "|".join(e.seen_in),
                e.message,
            ]
        )
    return buf.getvalue()
