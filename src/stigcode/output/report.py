"""ATO evidence summary report generator.

Produces Markdown reports suitable for Authority to Operate (ATO) packages,
providing evidence for NIST 800-53 SA-11 and SI-10 controls.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from stigcode.data import get_cci_mappings
from stigcode.ingest.xccdf import StigBenchmark, StigFinding
from stigcode.mapping.engine import MappingDatabase
from stigcode.mapping.status import CklStatus, StatusReport
from stigcode.version import __version__


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_finding_index(benchmark: StigBenchmark) -> dict[str, StigFinding]:
    """Return a dict of vuln_id → StigFinding for fast lookup."""
    return {f.vuln_id: f for f in benchmark.findings}


def _control_family(control: str) -> str:
    """Extract the two-letter control family prefix, e.g. 'SI' from 'SI-10'."""
    return control.split("-")[0].upper() if "-" in control else control.upper()[:2]


def _resolve_nist_controls(
    cci_refs: list[str],
    cci_mappings: dict[str, str],
) -> list[str]:
    """Map CCI references to NIST 800-53 control IDs."""
    controls = []
    for cci in cci_refs:
        nist = cci_mappings.get(cci)
        if nist:
            controls.append(nist)
    return controls


def _severity_label(category: int) -> str:
    labels = {1: "CAT I (High)", 2: "CAT II (Medium)", 3: "CAT III (Low)"}
    return labels.get(category, f"CAT {category}")


def _confidence_label(confidence: str) -> str:
    labels = {
        "direct": "Direct",
        "inferred": "Inferred",
        "partial": "Partial",
        "none": "Not Reviewed",
    }
    return labels.get(confidence, confidence.title())


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _section_executive_summary(
    report: StatusReport,
    benchmark: StigBenchmark,
    scan_date: datetime,
) -> str:
    scanner_name = report.scan_summary.get("scanner_name") or "unknown"
    scanner_version = report.scan_summary.get("scanner_version") or ""
    scanner_display = f"{scanner_name} v{scanner_version}" if scanner_version else scanner_name

    total = report.scan_summary.get("total_stig_findings", len(report.determinations))

    lines = [
        "## Executive Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Assessment Date | {scan_date.strftime('%Y-%m-%d')} |",
        f"| Scanner | {scanner_display} |",
        f"| STIG Benchmark | {benchmark.title} |",
        f"| Total STIG Findings | {total} |",
        f"| Open | {report.open_count} |",
        f"| Not a Finding | {report.not_a_finding_count} |",
        f"| Not Reviewed | {report.not_reviewed_count} |",
    ]
    return "\n".join(lines)


def _section_findings_by_severity(
    report: StatusReport,
    finding_index: dict[str, StigFinding],
) -> str:
    # Aggregate counts by category × status
    cats = {1: {"open": 0, "naf": 0, "nr": 0},
            2: {"open": 0, "naf": 0, "nr": 0},
            3: {"open": 0, "naf": 0, "nr": 0}}

    for det in report.determinations:
        sf = finding_index.get(det.stig_id)
        cat = sf.category if sf else 2
        if cat not in cats:
            cats[cat] = {"open": 0, "naf": 0, "nr": 0}
        if det.status == CklStatus.OPEN:
            cats[cat]["open"] += 1
        elif det.status == CklStatus.NOT_A_FINDING:
            cats[cat]["naf"] += 1
        else:
            cats[cat]["nr"] += 1

    lines = [
        "## Findings by Severity",
        "",
        "| Category | Open | Not a Finding | Not Reviewed | Total |",
        "|----------|------|---------------|--------------|-------|",
    ]
    for cat in sorted(cats):
        c = cats[cat]
        total = c["open"] + c["naf"] + c["nr"]
        label = _severity_label(cat)
        lines.append(f"| {label} | {c['open']} | {c['naf']} | {c['nr']} | {total} |")

    return "\n".join(lines)


def _section_open_findings(
    report: StatusReport,
    finding_index: dict[str, StigFinding],
) -> str:
    open_dets = [d for d in report.determinations if d.status == CklStatus.OPEN]

    if not open_dets:
        return "## Open Findings\n\nNo open findings."

    # Group by category
    by_cat: dict[int, list] = {}
    for det in open_dets:
        sf = finding_index.get(det.stig_id)
        cat = sf.category if sf else 2
        by_cat.setdefault(cat, []).append((det, sf))

    lines = ["## Open Findings", ""]

    for cat in sorted(by_cat):
        cat_label = _severity_label(cat)
        lines.append(f"### {cat_label}")
        lines.append("")

        for det, sf in by_cat[cat]:
            title = sf.title if sf else det.stig_id
            fix_text = (sf.fix_text or "").strip() if sf else ""

            # Derive NIST controls from the mapping DB or from the StigFinding CCI refs
            # We'll list what we know from the finding's review_notes / CWE context.
            # For simplicity we note the confidence here; NIST mapping is in its own section.
            confidence_display = _confidence_label(det.confidence.value)
            status_note = f"{det.status.value} ({confidence_display}"
            if det.mapped_cwe_ids:
                cwe_str = ", ".join(f"CWE-{c}" for c in det.mapped_cwe_ids)
                status_note += f" via {cwe_str}"
            status_note += ")"

            lines.append(f"#### {det.stig_id} — {title}")
            lines.append(f"- **Status**: {status_note}")

            if det.evidence:
                evidence_str = ", ".join(det.evidence)
                lines.append(f"- **Evidence**: {evidence_str}")

            if fix_text:
                # Truncate very long fix texts for readability
                if len(fix_text) > 500:
                    fix_text = fix_text[:497] + "..."
                lines.append(f"- **Remediation**: {fix_text}")

            lines.append("")

    return "\n".join(lines)


def _section_nist_control_mapping(
    report: StatusReport,
    benchmark: StigBenchmark,
    mapping_db: MappingDatabase,
    cci_mappings: dict[str, str],
) -> str:
    finding_index = _build_finding_index(benchmark)

    # For each STIG finding, collect its NIST control families
    # Sources: CCI refs on the XCCDF finding (if available), then mapping DB nist_control
    family_covered: dict[str, int] = {}
    family_open: dict[str, int] = {}

    for det in report.determinations:
        sf = finding_index.get(det.stig_id)
        controls: list[str] = []

        if sf and sf.cci_refs:
            controls = _resolve_nist_controls(sf.cci_refs, cci_mappings)

        if not controls:
            # Fall back to mapping DB
            db_mappings = mapping_db.lookup_by_stig(det.stig_id)
            controls = [m.nist_control for m in db_mappings if m.nist_control]

        families = {_control_family(c) for c in controls}
        for fam in families:
            family_covered[fam] = family_covered.get(fam, 0) + 1
            if det.status == CklStatus.OPEN:
                family_open[fam] = family_open.get(fam, 0) + 1

    lines = [
        "## NIST 800-53 Control Mapping",
        "",
        "| Control Family | Covered | Open | Gap |",
        "|---------------|---------|------|-----|",
    ]

    if not family_covered:
        lines.append("| (no mappings) | 0 | 0 | 0 |")
    else:
        for fam in sorted(family_covered):
            covered = family_covered[fam]
            open_count = family_open.get(fam, 0)
            gap = covered - open_count
            lines.append(f"| {fam} | {covered} | {open_count} | {gap} |")

    return "\n".join(lines)


def _section_methodology(db: MappingDatabase) -> str:
    return "\n".join([
        "## Assessment Methodology",
        "",
        f"This report was generated by Stigcode v{__version__} using automated SAST analysis. "
        "Findings were mapped from CWE identifiers to STIG findings using the stigcode "
        f"CWE→STIG mapping database (v{db.version}, {db.stig_name} {db.stig_version}).",
        "",
        "Confidence levels:",
        "- **Direct**: Scanner explicitly reported STIG finding ID",
        "- **Inferred**: Finding mapped via CWE→STIG database",
        "- **Not Reviewed**: Finding requires manual assessment",
    ])


def _section_attestation(
    report: StatusReport,
    benchmark: StigBenchmark,
    db: MappingDatabase,
    scan_date: datetime,
) -> str:
    scanner_name = report.scan_summary.get("scanner_name") or "unknown"
    scanner_version = report.scan_summary.get("scanner_version") or ""

    lines = [
        "## Attestation",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Tool | Stigcode v{__version__} |",
        f"| Scanner | {scanner_name} v{scanner_version}" if scanner_version
        else f"| Scanner | {scanner_name} |",
        f"| Scan Date | {scan_date.strftime('%Y-%m-%d')} |",
        f"| Benchmark | {benchmark.title} |",
        f"| Mapping Database | v{db.version} |",
    ]

    # Fix the scanner line — conditionally added above produces wrong format
    # Rebuild cleanly:
    scanner_display = f"{scanner_name} v{scanner_version}" if scanner_version else scanner_name
    lines = [
        "## Attestation",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Tool | Stigcode v{__version__} |",
        f"| Scanner | {scanner_display} |",
        f"| Scan Date | {scan_date.strftime('%Y-%m-%d')} |",
        f"| Benchmark | {benchmark.title} |",
        f"| Mapping Database | v{db.version} |",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report(
    report: StatusReport,
    benchmark: StigBenchmark,
    mapping_db: MappingDatabase,
    scan_date: datetime | None = None,
) -> str:
    """Generate a Markdown ATO evidence report.

    Args:
        report: Status determinations for all STIG findings.
        benchmark: The STIG benchmark that was assessed.
        mapping_db: The loaded CWE→STIG mapping database (for metadata and NIST lookups).
        scan_date: Date of the scan. Uses current UTC date if not provided.

    Returns:
        A Markdown string suitable for inclusion in an ATO package.
    """
    if scan_date is None:
        scan_date = datetime.utcnow()

    try:
        cci_mappings = get_cci_mappings()
    except FileNotFoundError:
        cci_mappings = {}

    finding_index = _build_finding_index(benchmark)

    sections = [
        "# STIG Compliance Assessment Report",
        "",
        _section_executive_summary(report, benchmark, scan_date),
        "",
        _section_findings_by_severity(report, finding_index),
        "",
        _section_open_findings(report, finding_index),
        "",
        _section_nist_control_mapping(report, benchmark, mapping_db, cci_mappings),
        "",
        _section_methodology(mapping_db),
        "",
        _section_attestation(report, benchmark, mapping_db, scan_date),
    ]

    return "\n".join(sections) + "\n"


def write_report(
    report: StatusReport,
    benchmark: StigBenchmark,
    mapping_db: MappingDatabase,
    output_path: Path,
    scan_date: datetime | None = None,
) -> None:
    """Write a Markdown ATO evidence report to a file.

    Args:
        report: Status determinations for all STIG findings.
        benchmark: The STIG benchmark that was assessed.
        mapping_db: The loaded CWE→STIG mapping database.
        output_path: Destination file path (will be created or overwritten).
        scan_date: Date of the scan. Uses current UTC date if not provided.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    content = generate_report(report, benchmark, mapping_db, scan_date)
    output_path.write_text(content, encoding="utf-8")
