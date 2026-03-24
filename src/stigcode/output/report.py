"""800-53 Control Evidence Report generator.

Produces Markdown reports structured as SA-11 evidence artifacts, suitable
for inclusion in an ATO security package or Security Assessment Report (SAR).
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


def _sa11_assessment_status(report: StatusReport, finding_index: dict[str, StigFinding]) -> str:
    """Derive an SA-11 assessment status from open findings.

    - Satisfied: no open findings and at least one determination exists
    - Other Than Satisfied: any CAT I (high severity) findings are open
    - Partially Satisfied: open findings exist but all are CAT II or III
    """
    if report.open_count == 0 and len(report.determinations) > 0:
        return "Satisfied"

    has_cat1_open = any(
        det.status == CklStatus.OPEN
        and (finding_index.get(det.stig_id) or None) is not None
        and finding_index[det.stig_id].category == 1
        for det in report.determinations
    )

    if has_cat1_open:
        return "Other Than Satisfied"
    if report.open_count > 0:
        return "Partially Satisfied"
    return "Satisfied"


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _section_purpose() -> str:
    return "\n".join([
        "## Purpose",
        "",
        "This report provides evidence for NIST 800-53 security control assessment, "
        "generated from automated static application security testing (SAST). "
        "It is intended as a supporting artifact for the Security Assessment Report (SAR).",
    ])


def _section_applicable_controls(
    report: StatusReport,
    benchmark: StigBenchmark,
    mapping_db: MappingDatabase,
    cci_mappings: dict[str, str],
) -> str:
    finding_index = _build_finding_index(benchmark)
    all_controls: set[str] = set()

    for det in report.determinations:
        sf = finding_index.get(det.stig_id)
        controls: list[str] = []
        if sf and sf.cci_refs:
            controls = _resolve_nist_controls(sf.cci_refs, cci_mappings)
        if not controls:
            db_mappings = mapping_db.lookup_by_stig(det.stig_id)
            controls = [m.nist_control for m in db_mappings if m.nist_control]
        all_controls.update(controls)

    lines = [
        "## Applicable Controls",
        "",
        "This scan provides evidence for the following NIST 800-53 controls:",
    ]

    # SA-11 is always applicable — it covers the act of performing SAST
    known = sorted(all_controls)
    listed = set()

    # Ensure SA-11 appears first
    if "SA-11" not in known:
        lines.append("- **SA-11** Developer Testing and Evaluation")
        listed.add("SA-11")

    for ctrl in known:
        label = ctrl
        if ctrl == "SA-11":
            label = "**SA-11** Developer Testing and Evaluation"
        elif ctrl == "SI-10":
            label = "**SI-10** Information Input Validation"
        elif ctrl == "SI-11":
            label = "**SI-11** Error Handling"
        else:
            label = f"**{ctrl}**"
        lines.append(f"- {label}")
        listed.add(ctrl)

    if not listed:
        lines.append("- **SA-11** Developer Testing and Evaluation")

    return "\n".join(lines)


def _section_executive_summary(
    report: StatusReport,
    benchmark: StigBenchmark,
    scan_date: datetime,
    sa11_status: str,
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
        f"| SA-11 Assessment Status | {sa11_status} |",
        f"| Total STIG Findings | {total} |",
        f"| Open | {report.open_count} |",
        f"| Not a Finding | {report.not_a_finding_count} |",
        f"| Not Reviewed | {report.not_reviewed_count} |",
    ]
    return "\n".join(lines)


def _section_sa11_evidence(
    report: StatusReport,
    benchmark: StigBenchmark,
    mapping_db: MappingDatabase,
    scan_date: datetime,
    sa11_status: str,
) -> str:
    scanner_name = report.scan_summary.get("scanner_name") or "unknown"
    scanner_version = report.scan_summary.get("scanner_version") or ""
    scanner_display = f"{scanner_name} v{scanner_version}" if scanner_version else scanner_name

    total = report.scan_summary.get("total_stig_findings", len(report.determinations))
    naf = report.not_a_finding_count
    stig_label = f"{mapping_db.stig_name} STIG"

    lines = [
        "## Control Evidence",
        "",
        "### SA-11 — Developer Testing and Evaluation",
        "",
        f"**Assessment:** {sa11_status}",
        "",
        f"Automated SAST scanning was performed using {scanner_display} on "
        f"{scan_date.strftime('%Y-%m-%d')}. The scan covers {total} code-level security "
        f"controls from the {stig_label}.",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Rules evaluated | {total} |",
        f"| Findings identified | {report.open_count} |",
        f"| Findings clear (no issues) | {naf} |",
    ]
    return "\n".join(lines)


def _section_findings_by_severity(
    report: StatusReport,
    finding_index: dict[str, StigFinding],
) -> str:
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
        return "## Open Findings Summary\n\nNo open findings."

    by_cat: dict[int, list] = {}
    for det in open_dets:
        sf = finding_index.get(det.stig_id)
        cat = sf.category if sf else 2
        by_cat.setdefault(cat, []).append((det, sf))

    lines = [
        "## Open Findings Summary",
        "",
        "The following findings require POA&M entries if not remediated prior to assessment.",
        "",
    ]

    for cat in sorted(by_cat):
        cat_label = _severity_label(cat)
        lines.append(f"### {cat_label}")
        lines.append("")

        for det, sf in by_cat[cat]:
            title = sf.title if sf else det.stig_id
            fix_text = (sf.fix_text or "").strip() if sf else ""

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

    family_covered: dict[str, int] = {}
    family_open: dict[str, int] = {}

    for det in report.determinations:
        sf = finding_index.get(det.stig_id)
        controls: list[str] = []

        if sf and sf.cci_refs:
            controls = _resolve_nist_controls(sf.cci_refs, cci_mappings)

        if not controls:
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


def _section_scope_and_limitations(mapping_db: MappingDatabase) -> str:
    stig_label = f"{mapping_db.stig_name} STIG"
    return "\n".join([
        "## Assessment Scope and Limitations",
        "",
        "This report covers findings detectable through static analysis only. "
        "The following types of security requirements are NOT addressed by this scan "
        "and require separate evidence:",
        "",
        "- Procedural controls (code review processes, security training, CCB)",
        "- Runtime and configuration controls (session timeouts, TLS settings)",
        "- Operational controls (incident response, backup procedures)",
        "",
        f"Of the findings in the {stig_label}, a subset "
        "are assessable by SAST (covered by this scan); the remainder require "
        "manual or procedural assessment and are not covered.",
    ])


def _section_methodology(db: MappingDatabase) -> str:
    return "\n".join([
        "## Methodology",
        "",
        f"This report was generated by Stigcode v{__version__}. "
        "Stigcode maps SARIF findings to NIST 800-53 controls using a curated "
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
    """Generate a Markdown 800-53 control evidence report.

    Args:
        report: Status determinations for all STIG findings.
        benchmark: The STIG benchmark that was assessed.
        mapping_db: The loaded CWE→STIG mapping database (for metadata and NIST lookups).
        scan_date: Date of the scan. Uses current UTC date if not provided.

    Returns:
        A Markdown string suitable for inclusion in an ATO package as SA-11 evidence.
    """
    if scan_date is None:
        scan_date = datetime.utcnow()

    try:
        cci_mappings = get_cci_mappings()
    except FileNotFoundError:
        cci_mappings = {}

    finding_index = _build_finding_index(benchmark)
    sa11_status = _sa11_assessment_status(report, finding_index)

    sections = [
        "# Security Assessment Evidence: Application Code Analysis",
        "",
        _section_purpose(),
        "",
        _section_applicable_controls(report, benchmark, mapping_db, cci_mappings),
        "",
        _section_executive_summary(report, benchmark, scan_date, sa11_status),
        "",
        _section_sa11_evidence(report, benchmark, mapping_db, scan_date, sa11_status),
        "",
        _section_findings_by_severity(report, finding_index),
        "",
        _section_open_findings(report, finding_index),
        "",
        _section_nist_control_mapping(report, benchmark, mapping_db, cci_mappings),
        "",
        _section_scope_and_limitations(mapping_db),
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
    """Write a Markdown 800-53 control evidence report to a file.

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
