"""Stigcode CLI — SARIF-to-compliance bridge."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer

from stigcode.version import __version__

DESCRIPTION = "SARIF-to-compliance bridge"
REPO_URL = "https://github.com/rdwj/stigcode"
ISSUES_URL = f"{REPO_URL}/issues"

# Issue numbers for not-yet-implemented commands
_ISSUE_CKL = 5
_ISSUE_REPORT = 6
_ISSUE_COVERAGE = 7

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
) -> None:
    """Generate a STIG Viewer checklist (.ckl) from SARIF scan results."""
    import yaml

    from stigcode.ingest.sarif import parse_sarif
    from stigcode.ingest.xccdf import parse_xccdf, StigBenchmark, StigFinding
    from stigcode.mapping.engine import load_mapping_database
    from stigcode.mapping.status import determine_status
    from stigcode.output.ckl import generate_ckl, write_ckl, AssetInfo

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
    _DEFAULT_MAPPING = Path(__file__).parent.parent.parent / "data" / "mappings" / "asd_stig_v6r3.yaml"
    mapping_path = mapping_file or _DEFAULT_MAPPING
    if not mapping_path.exists():
        typer.echo(f"Error: mapping file not found: {mapping_path}", err=True)
        raise typer.Exit(code=2)
    db = load_mapping_database(mapping_path)

    # --- Load classifications ---
    _DEFAULT_CLASSIFICATIONS = Path(__file__).parent.parent.parent / "data" / "mappings" / "finding_classifications.yaml"
    cls_path = classifications_file or _DEFAULT_CLASSIFICATIONS
    if not cls_path.exists():
        typer.echo(f"Error: classifications file not found: {cls_path}", err=True)
        raise typer.Exit(code=2)
    raw_cls = yaml.safe_load(cls_path.read_text(encoding="utf-8"))
    classifications: dict = raw_cls.get("classifications", {})

    # --- Load benchmark ---
    if xccdf_file is not None:
        if not xccdf_file.exists():
            typer.echo(f"Error: XCCDF file not found: {xccdf_file}", err=True)
            raise typer.Exit(code=2)
        benchmark = parse_xccdf(xccdf_file)
    else:
        stig_ids = sorted(db.all_stig_ids())
        synthetic_findings: list[StigFinding] = []
        for stig_id in stig_ids:
            synthetic_findings.append(StigFinding(
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
            ))
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

    # --- Generate CKL ---
    asset = AssetInfo(host_name=host_name, host_ip=host_ip)

    if output is not None:
        write_ckl(report, benchmark, output, asset, classification)
        typer.echo(f"CKL written to {output}", err=True)
    else:
        typer.echo(generate_ckl(report, benchmark, asset, classification))


@export_app.command(name="report")
def export_report() -> None:
    """Generate an ATO evidence report from imported findings."""
    _not_implemented(_ISSUE_REPORT)


@export_app.command(name="coverage")
def export_coverage() -> None:
    """Generate a NIST 800-53 coverage matrix from imported findings."""
    _not_implemented(_ISSUE_COVERAGE)


# ---------------------------------------------------------------------------
# lookup sub-commands
# ---------------------------------------------------------------------------

@lookup_app.command(name="cwe")
def lookup_cwe(
    cwe_id: str = typer.Option(..., "--cwe", help="CWE ID to look up (e.g. '89' or 'CWE-89')."),
) -> None:
    """Look up STIG findings mapped to a CWE ID."""
    _not_implemented(1)


@lookup_app.command(name="stig")
def lookup_stig(
    stig_id: str = typer.Option(..., "--stig", help="STIG Vuln ID to look up (e.g. 'V-222387')."),
) -> None:
    """Look up CWE mappings for a STIG finding."""
    _not_implemented(1)


# ---------------------------------------------------------------------------
# stig sub-commands
# ---------------------------------------------------------------------------

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
    import yaml

    from stigcode.ingest.sarif import parse_sarif
    from stigcode.ingest.xccdf import parse_xccdf, StigBenchmark, StigFinding
    from stigcode.mapping.engine import load_mapping_database, MappingDatabase, StigMapping
    from stigcode.mapping.status import determine_status, CklStatus

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
    _DEFAULT_MAPPING = Path(__file__).parent.parent.parent / "data" / "mappings" / "asd_stig_v6r3.yaml"
    mapping_path = mapping_file or _DEFAULT_MAPPING
    if not mapping_path.exists():
        typer.echo(f"Error: mapping file not found: {mapping_path}", err=True)
        typer.echo("Provide --mappings or ensure the bundled mapping data is installed.", err=True)
        raise typer.Exit(code=2)
    db = load_mapping_database(mapping_path)

    # --- Load classifications ---
    _DEFAULT_CLASSIFICATIONS = Path(__file__).parent.parent.parent / "data" / "mappings" / "finding_classifications.yaml"
    cls_path = classifications_file or _DEFAULT_CLASSIFICATIONS
    if not cls_path.exists():
        typer.echo(f"Error: classifications file not found: {cls_path}", err=True)
        raise typer.Exit(code=2)
    raw_cls = yaml.safe_load(cls_path.read_text(encoding="utf-8"))
    classifications: dict = raw_cls.get("classifications", {})

    # --- Load benchmark ---
    if xccdf_file is not None:
        if not xccdf_file.exists():
            typer.echo(f"Error: XCCDF file not found: {xccdf_file}", err=True)
            raise typer.Exit(code=2)
        benchmark = parse_xccdf(xccdf_file)
    else:
        # Build a synthetic benchmark from the findings the mapping DB knows about
        stig_ids = sorted(db.all_stig_ids())
        synthetic_findings: list[StigFinding] = []
        for stig_id in stig_ids:
            synthetic_findings.append(StigFinding(
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
            ))
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

    # --- Print summary ---
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
        # Map STIG IDs back to categories via the benchmark
        cat_by_stig = {f.vuln_id: f.category for f in benchmark.findings}
        for det in open_dets:
            cat = cat_by_stig.get(det.stig_id, 2)
            by_cat[cat] = by_cat.get(cat, 0) + 1
        for cat in sorted(by_cat):
            typer.echo(f"  CAT {cat}: {by_cat[cat]}")


def main() -> None:
    """Entry point declared in pyproject.toml."""
    app()
