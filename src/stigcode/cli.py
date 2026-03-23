"""Stigcode CLI — SARIF-to-compliance bridge."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
import yaml

from stigcode.version import __version__

DESCRIPTION = "SARIF-to-compliance bridge"
REPO_URL = "https://github.com/rdwj/stigcode"
ISSUES_URL = f"{REPO_URL}/issues"

# Issue numbers for not-yet-implemented commands
_ISSUE_CKL = 5
_ISSUE_REPORT = 6
_ISSUE_COVERAGE = 7

_DEFAULT_MAPPING = Path(__file__).parent.parent.parent / "data" / "mappings" / "asd_stig_v6r3.yaml"
_DEFAULT_CLASSIFICATIONS = (
    Path(__file__).parent.parent.parent / "data" / "mappings" / "finding_classifications.yaml"
)

app = typer.Typer(help=DESCRIPTION, no_args_is_help=True)
export_app = typer.Typer(help="Generate compliance artifacts from imported findings.", no_args_is_help=True)
lookup_app = typer.Typer(help="Look up STIG/CWE mappings.", no_args_is_help=True)
stig_app = typer.Typer(help="Manage STIG benchmark data.", no_args_is_help=True)

app.add_typer(export_app, name="export")
app.add_typer(lookup_app, name="lookup")
app.add_typer(stig_app, name="stig")


def _not_implemented(issue: int) -> None:
    """Print a standard 'not yet implemented' message and exit 2."""
    typer.echo(f"Not yet implemented. See: {ISSUES_URL}/{issue}", err=True)
    raise typer.Exit(code=2)


# ---------------------------------------------------------------------------
# Shared pipeline loader
# ---------------------------------------------------------------------------

def _load_pipeline(
    sarif_file: str,
    mapping_file: Optional[Path],
    classifications_file: Optional[Path],
    xccdf_file: Optional[Path],
):
    """Load all inputs and run status determination.

    Handles stdin, default paths, and the synthetic-benchmark fallback.

    Returns:
        Tuple of (StatusReport, StigBenchmark, MappingDatabase, SarifResult)

    Raises:
        typer.Exit(code=2) on any error with a user-facing message printed to stderr.
    """
    from stigcode.ingest.sarif import parse_sarif
    from stigcode.ingest.xccdf import parse_xccdf, StigBenchmark, StigFinding
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
        typer.echo("Provide --mappings or ensure the bundled mapping data is installed.", err=True)
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


# ---------------------------------------------------------------------------
# Top-level commands
# ---------------------------------------------------------------------------

@app.command()
def version() -> None:
    """Print version and exit."""
    typer.echo(f"stigcode {__version__}")
    typer.echo(DESCRIPTION)
    typer.echo(REPO_URL)


@app.command(name="import")
def import_sarif(
    sarif_file: str = typer.Argument(..., help="Path to SARIF file, or '-' to read from stdin."),
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

    # result is expected to be a SarifReport or similar with .findings and .scanner_name
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


# ---------------------------------------------------------------------------
# export sub-commands
# ---------------------------------------------------------------------------

@export_app.command(name="ckl")
def export_ckl(
    sarif_file: str = typer.Argument(..., help="Path to SARIF file, or '-' to read from stdin."),
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
        help="Path to CWE-to-STIG mapping YAML. Defaults to the bundled ASD STIG V6 mapping.",
    ),
    classifications_file: Optional[Path] = typer.Option(
        None, "--classifications", "-c",
        help="Path to finding classifications YAML.",
    ),
    host_name: str = typer.Option("", "--host-name", help="Target host name for the CKL ASSET block."),
    host_ip: str = typer.Option("", "--host-ip", help="Target host IP for the CKL ASSET block."),
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

    report, benchmark, db, _sarif_result = _load_pipeline(
        sarif_file, mapping_file, classifications_file, xccdf_file
    )

    asset = AssetInfo(host_name=host_name, host_ip=host_ip)

    if update_ckl_file is not None:
        if not update_ckl_file.exists():
            typer.echo(f"Error: existing CKL not found: {update_ckl_file}", err=True)
            raise typer.Exit(code=2)
        if output is None:
            typer.echo(
                "Error: --update requires --output to specify the destination path.",
                err=True,
            )
            raise typer.Exit(code=2)

        from stigcode.output.ckl_update import update_ckl as _update_ckl

        result = _update_ckl(update_ckl_file, report, benchmark, output, asset, classification)

        typer.echo(f"CKL updated: {output}", err=True)
        typer.echo(
            f"  {result.updated_count} updated, "
            f"{result.preserved_count} preserved, "
            f"{len(result.conflicts)} conflicts "
            f"(of {result.total_findings} total findings)",
            err=True,
        )
        if result.conflicts:
            typer.echo("Conflicts requiring manual review:", err=True)
            for c in result.conflicts:
                typer.echo(
                    f"  {c.stig_id}: was {c.existing_status}, "
                    f"new scan says {c.new_status} — {c.reason}",
                    err=True,
                )
    elif output is not None:
        write_ckl(report, benchmark, output, asset, classification)
        typer.echo(f"CKL written to {output}", err=True)
    else:
        typer.echo(generate_ckl(report, benchmark, asset, classification))


@export_app.command(name="report")
def export_report(
    sarif_file: str = typer.Argument(..., help="Path to SARIF file, or '-' to read from stdin."),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output Markdown file path. Prints to stdout if omitted.",
    ),
    xccdf_file: Optional[Path] = typer.Option(
        None, "--xccdf", "-x",
        help="Path to DISA XCCDF XML file for full benchmark metadata.",
    ),
    mapping_file: Optional[Path] = typer.Option(
        None, "--mappings", "-m",
        help="Path to CWE-to-STIG mapping YAML. Defaults to the bundled ASD STIG V6 mapping.",
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
        typer.echo(f"Error: unsupported format '{fmt}'. Only 'md' is supported.", err=True)
        raise typer.Exit(code=2)

    from stigcode.output.report import generate_report, write_report

    report, benchmark, db, _sarif_result = _load_pipeline(
        sarif_file, mapping_file, classifications_file, xccdf_file
    )

    if output is not None:
        write_report(report, benchmark, db, output)
        typer.echo(f"Report written to {output}", err=True)
    else:
        typer.echo(generate_report(report, benchmark, db))


@export_app.command(name="coverage")
def export_coverage(
    sarif_file: str = typer.Argument(..., help="Path to SARIF file, or '-' to read from stdin."),
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
        help="Path to CWE-to-STIG mapping YAML. Defaults to the bundled ASD STIG V6 mapping.",
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
        typer.echo(f"Error: --format must be 'md' or 'csv', got {fmt!r}", err=True)
        raise typer.Exit(code=2)

    from stigcode.data import get_cci_mappings
    from stigcode.output.coverage import (
        build_coverage_matrix,
        matrix_to_csv,
        matrix_to_markdown,
        write_coverage,
    )

    report, benchmark, _db, _sarif_result = _load_pipeline(
        sarif_file, mapping_file, classifications_file, xccdf_file
    )

    try:
        cci_mappings = get_cci_mappings()
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2)

    matrix = build_coverage_matrix(report, benchmark, cci_mappings)

    if output is not None:
        write_coverage(matrix, output, fmt=fmt)
        typer.echo(f"Coverage matrix written to {output}", err=True)
    else:
        if fmt == "md":
            typer.echo(matrix_to_markdown(matrix))
        else:
            typer.echo(matrix_to_csv(matrix))



# ---------------------------------------------------------------------------
# lookup sub-commands
# ---------------------------------------------------------------------------

@lookup_app.command(name="cwe")
def lookup_cwe(
    cwe_id: str = typer.Option(..., "--cwe", help="CWE ID to look up (e.g. '89' or 'CWE-89')."),
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
        raise typer.Exit(code=2)

    try:
        db = get_mapping_database()
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2)

    matches = db.lookup_by_cwe(numeric_id)
    if not matches:
        typer.echo(f"No STIG mappings found for CWE-{numeric_id}.")
        return

    typer.echo(f"CWE-{numeric_id} maps to {len(matches)} STIG finding(s):\n")
    for m in sorted(matches, key=lambda x: x.stig_id):
        typer.echo(f"  {m.stig_id}  ({m.check_id})")
        typer.echo(f"    Severity:   (see XCCDF for CAT)")
        typer.echo(f"    Confidence: {m.confidence}")
        typer.echo(f"    NIST:       {m.nist_control}")
        if m.notes:
            typer.echo(f"    Notes:      {m.notes}")
        typer.echo("")


@lookup_app.command(name="stig")
def lookup_stig(
    stig_id: str = typer.Option(..., "--stig", help="STIG Vuln ID to look up (e.g. 'V-222387')."),
) -> None:
    """Look up CWE mappings for a STIG finding."""
    from stigcode.data import get_mapping_database

    # Accept "V-222607" or "222607"
    normalized = stig_id if stig_id.startswith("V-") else f"V-{stig_id}"

    try:
        db = get_mapping_database()
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2)

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


# ---------------------------------------------------------------------------
# stig sub-commands
# ---------------------------------------------------------------------------

@stig_app.command(name="mappings")
def stig_mappings(
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Write full cross-reference matrix to this file.",
    ),
    xccdf_file: Optional[Path] = typer.Option(
        None, "--xccdf", "-x",
        help="Path to DISA XCCDF XML for full finding metadata.",
    ),
    fmt: str = typer.Option(
        "md", "--format", "-f",
        help="Output format for --output: 'md' or 'csv'.",
    ),
) -> None:
    """Show mapping database stats; optionally write the cross-reference matrix."""
    import yaml

    from stigcode.data import get_mapping_database, get_cci_mappings

    if fmt not in ("md", "csv"):
        typer.echo(f"Error: --format must be 'md' or 'csv', got {fmt!r}", err=True)
        raise typer.Exit(code=2)

    try:
        db = get_mapping_database()
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2)

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
    from stigcode.ingest.xccdf import parse_xccdf, StigBenchmark, StigFinding
    from stigcode.output.xref import build_xref_matrix, write_xref

    if xccdf_file is not None:
        if not xccdf_file.exists():
            typer.echo(f"Error: XCCDF file not found: {xccdf_file}", err=True)
            raise typer.Exit(code=2)
        benchmark = parse_xccdf(xccdf_file)
    else:
        # Synthetic benchmark from mapping db + classifications
        cls_path = _DEFAULT_CLASSIFICATIONS
        if not cls_path.exists():
            typer.echo(f"Error: classifications file not found: {cls_path}", err=True)
            raise typer.Exit(code=2)
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
        raise typer.Exit(code=2)

    entries = build_xref_matrix(benchmark, db, cci_mappings, classifications)
    write_xref(entries, output, fmt=fmt, benchmark_title=benchmark.title)
    typer.echo(f"\nCross-reference matrix ({len(entries)} entries) written to {output}", err=True)


@stig_app.command(name="import-xccdf")
def stig_import_xccdf(
    xccdf_file: Path = typer.Argument(..., help="Path to a DISA XCCDF XML file."),
) -> None:
    """Import a STIG from a DISA XCCDF XML file, printing a summary."""
    try:
        from stigcode.ingest.xccdf import parse_xccdf
    except ImportError:
        _not_implemented(9)
        return

    if not xccdf_file.exists():
        typer.echo(f"Error: file not found: {xccdf_file}", err=True)
        raise typer.Exit(code=2)

    benchmark = parse_xccdf(xccdf_file)

    by_cat: dict[int, int] = {}
    for finding in benchmark.findings:
        cat = finding.category
        by_cat[cat] = by_cat.get(cat, 0) + 1

    typer.echo(f"Benchmark: {benchmark.title}")
    typer.echo(f"Version {benchmark.version}, Release {benchmark.release} ({benchmark.date})")
    typer.echo(f"Findings: {len(benchmark.findings)}")
    for cat in sorted(by_cat):
        typer.echo(f"  CAT {cat}: {by_cat[cat]}")


@app.command()
def assess(
    sarif_file: str = typer.Argument(..., help="Path to SARIF file, or '-' to read from stdin."),
    xccdf_file: Optional[Path] = typer.Option(
        None, "--xccdf", "-x",
        help="Path to DISA XCCDF XML file. Required for full STIG benchmark coverage.",
    ),
    mapping_file: Optional[Path] = typer.Option(
        None, "--mappings", "-m",
        help="Path to CWE→STIG mapping YAML. Defaults to the bundled ASD STIG V6 mapping.",
    ),
    classifications_file: Optional[Path] = typer.Option(
        None, "--classifications", "-c",
        help="Path to finding classifications YAML. Defaults to the bundled classifications.",
    ),
) -> None:
    """Assess a SARIF scan against a STIG benchmark and print a status summary."""
    from stigcode.mapping.status import CklStatus

    report, benchmark, _db, _sarif_result = _load_pipeline(
        sarif_file, mapping_file, classifications_file, xccdf_file
    )

    typer.echo(f"Scanner: {report.scan_summary['scanner_name'] or 'unknown'}")
    typer.echo(f"SARIF findings: {report.scan_summary['total_sarif_findings']}")
    typer.echo(f"STIG findings assessed: {report.scan_summary['total_stig_findings']}")
    typer.echo("")
    typer.echo("Status summary:")
    typer.echo(f"  Open:          {report.open_count}")
    typer.echo(f"  Not a finding: {report.not_a_finding_count}")
    typer.echo(f"  Not reviewed:  {report.not_reviewed_count}")

    if report.open_count:
        typer.echo("")
        typer.echo("Open findings by category:")
        by_cat: dict[int, int] = {}
        open_dets = [d for d in report.determinations if d.status == CklStatus.OPEN]
        cat_by_stig = {f.vuln_id: f.category for f in benchmark.findings}
        for det in open_dets:
            cat = cat_by_stig.get(det.stig_id, 2)
            by_cat[cat] = by_cat.get(cat, 0) + 1
        for cat in sorted(by_cat):
            typer.echo(f"  CAT {cat}: {by_cat[cat]}")


def main() -> None:
    """Entry point declared in pyproject.toml."""
    app()
