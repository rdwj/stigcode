"""POA&M (Plan of Action and Milestones) candidate report generator.

Produces draft POA&M entries from open STIG findings for ISSO review.
These are *candidates* — an ISSO must review and incorporate them into
the system's authoritative POA&M before submission.

Format follows NIST SP 800-37 and OMB A-130 conventions.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from stigcode.ingest.xccdf import StigBenchmark, StigFinding
from stigcode.mapping.engine import MappingDatabase
from stigcode.mapping.status import CklStatus, FindingDetermination, StatusReport


# CAT → remediation window in days
_CAT_DAYS: dict[int, int] = {1: 30, 2: 90, 3: 180}

_DEFAULT_MILESTONES: list[str] = [
    "Identify root cause and scope of affected code",
    "Implement fix (parameterized queries, input validation, or equivalent)",
    "Verify remediation via rescan",
    "Close finding",
]

_ISSO_PLACEHOLDER = "[ISSO to assign]"
_RESOURCES = "Developer remediation"
_CANDIDATE_DISCLAIMER = (
    "> **Note:** These are *candidate* POA&M entries generated from automated SAST scan "
    "results. An ISSO must review each entry, validate the finding, and incorporate "
    "approved items into the system's authoritative POA&M."
)


@dataclass
class PoamEntry:
    """A single POA&M candidate entry."""

    item_number: int
    weakness_name: str
    weakness_description: str
    security_controls: list[str]
    severity: str                   # "CAT I", "CAT II", "CAT III"
    stig_id: str | None
    affected_components: list[str]
    point_of_contact: str
    resources_required: str
    scheduled_completion: str       # ISO date string
    milestones: list[str]
    status: str
    source: str
    comments: str


@dataclass
class PoamReport:
    """Complete POA&M candidate report."""

    entries: list[PoamEntry]
    generated_date: datetime
    scanner_name: str
    scanner_version: str
    system_name: str = "[ System Name — ISSO to complete ]"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_finding_index(benchmark: StigBenchmark) -> dict[str, StigFinding]:
    return {f.vuln_id: f for f in benchmark.findings}


def _cat_label(category: int) -> str:
    return {1: "CAT I", 2: "CAT II", 3: "CAT III"}.get(category, f"CAT {category}")


def _completion_date(category: int, from_date: datetime) -> str:
    days = _CAT_DAYS.get(category, 90)
    return (from_date + timedelta(days=days)).strftime("%Y-%m-%d")


def _resolve_controls(
    stig_finding: StigFinding | None,
    det: FindingDetermination,
    mapping_db: MappingDatabase,
    cci_mappings: dict[str, str],
) -> list[str]:
    """Resolve NIST 800-53 controls via CCI refs or the mapping DB."""
    controls: list[str] = []

    if stig_finding and stig_finding.cci_refs:
        for cci in stig_finding.cci_refs:
            nist = cci_mappings.get(cci)
            if nist:
                controls.append(nist)

    if not controls:
        db_mappings = mapping_db.lookup_by_stig(det.stig_id)
        controls = [m.nist_control for m in db_mappings if m.nist_control]

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for c in controls:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def _weakness_name(
    stig_finding: StigFinding | None,
    det: FindingDetermination,
) -> str:
    """Derive a human-readable weakness name."""
    if stig_finding and stig_finding.title:
        name = stig_finding.title
    else:
        name = det.stig_id

    if det.mapped_cwe_ids:
        cwe_str = ", ".join(f"CWE-{c}" for c in sorted(det.mapped_cwe_ids))
        return f"{name} ({cwe_str})"
    return name


def _build_entry(
    item_number: int,
    det: FindingDetermination,
    stig_finding: StigFinding | None,
    mapping_db: MappingDatabase,
    cci_mappings: dict[str, str],
    scanner_name: str,
    scanner_version: str,
    from_date: datetime,
) -> PoamEntry:
    category = stig_finding.category if stig_finding else 2
    severity = _cat_label(category)

    weakness_name = _weakness_name(stig_finding, det)
    description = stig_finding.description if stig_finding and stig_finding.description else det.review_notes
    controls = _resolve_controls(stig_finding, det, mapping_db, cci_mappings)
    completion = _completion_date(category, from_date)

    source_parts = [scanner_name or "SAST scanner"]
    if scanner_version:
        source_parts[0] += f" v{scanner_version}"
    source = f"Automated SAST scan ({source_parts[0]})"

    comments = det.review_notes
    if det.confidence:
        comments = f"Confidence: {det.confidence.value}. {comments}"

    fix_text = (stig_finding.fix_text or "").strip() if stig_finding else ""

    return PoamEntry(
        item_number=item_number,
        weakness_name=weakness_name,
        weakness_description=description,
        security_controls=controls,
        severity=severity,
        stig_id=det.stig_id,
        affected_components=list(det.evidence),
        point_of_contact=_ISSO_PLACEHOLDER,
        resources_required=_RESOURCES,
        scheduled_completion=completion,
        milestones=_build_milestones(fix_text),
        status="Open",
        source=source,
        comments=comments,
    )


def _build_milestones(fix_text: str) -> list[str]:
    """Return default milestones, optionally specialised from fix_text."""
    # Use default list — specific remediation is in the fix_text section
    return list(_DEFAULT_MILESTONES)


def _sort_key(entry: PoamEntry) -> tuple[int, str]:
    cat_order = {"CAT I": 1, "CAT II": 2, "CAT III": 3}
    return (cat_order.get(entry.severity, 9), entry.stig_id or "")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_poam(
    report: StatusReport,
    benchmark: StigBenchmark | None,
    mapping_db: MappingDatabase,
    cci_mappings: dict[str, str],
    scanner_name: str = "",
    scanner_version: str = "",
    as_of: datetime | None = None,
) -> PoamReport:
    """Generate POA&M candidates from open findings.

    Args:
        report: Status report produced by determine_status().
        benchmark: Optional parsed STIG benchmark for title and fix text.
        mapping_db: Loaded CWE→STIG mapping database.
        cci_mappings: Dict of CCI-XXXXXX → NIST control string.
        scanner_name: Scanner tool name for source attribution.
        scanner_version: Scanner version string.
        as_of: Reference date for computing scheduled_completion.
            Defaults to today (UTC).

    Returns:
        PoamReport with one PoamEntry per open finding.
    """
    if as_of is None:
        as_of = datetime.utcnow()

    scanner_name = scanner_name or report.scan_summary.get("scanner_name", "")
    scanner_version = scanner_version or report.scan_summary.get("scanner_version", "")

    finding_index = _build_finding_index(benchmark) if benchmark else {}
    open_dets = [d for d in report.determinations if d.status == CklStatus.OPEN]

    entries: list[PoamEntry] = []
    for det in open_dets:
        stig_finding = finding_index.get(det.stig_id)
        entries.append(
            _build_entry(
                item_number=0,  # renumbered after sorting
                det=det,
                stig_finding=stig_finding,
                mapping_db=mapping_db,
                cci_mappings=cci_mappings,
                scanner_name=scanner_name,
                scanner_version=scanner_version,
                from_date=as_of,
            )
        )

    entries.sort(key=_sort_key)
    for i, entry in enumerate(entries, start=1):
        entry.item_number = i

    return PoamReport(
        entries=entries,
        generated_date=as_of,
        scanner_name=scanner_name,
        scanner_version=scanner_version,
    )


def poam_to_markdown(poam: PoamReport) -> str:
    """Render a PoamReport as Markdown."""
    lines: list[str] = []

    lines.append("# POA&M Candidates")
    lines.append("")
    lines.append(_CANDIDATE_DISCLAIMER)
    lines.append("")
    lines.append(f"Generated: {poam.generated_date.strftime('%Y-%m-%d')}")
    scanner_display = poam.scanner_name
    if poam.scanner_version:
        scanner_display += f" v{poam.scanner_version}"
    lines.append(f"Source: SAST scan by {scanner_display}")
    lines.append("")

    # Summary table
    cat_counts: dict[str, int] = {"CAT I": 0, "CAT II": 0, "CAT III": 0}
    for e in poam.entries:
        cat_counts[e.severity] = cat_counts.get(e.severity, 0) + 1

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count | Target Remediation |")
    lines.append("|----------|-------|-------------------|")
    for cat, days in (("CAT I", "30 days"), ("CAT II", "90 days"), ("CAT III", "180 days")):
        lines.append(f"| {cat} | {cat_counts.get(cat, 0)} | {days} |")
    lines.append("")

    if not poam.entries:
        lines.append("*No open findings.*")
        return "\n".join(lines) + "\n"

    lines.append("## POA&M Entries")
    lines.append("")

    for entry in poam.entries:
        lines.append(f"### {entry.item_number}. {entry.weakness_name}")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| Weakness | {entry.weakness_name} |")
        controls_str = ", ".join(entry.security_controls) if entry.security_controls else "—"
        lines.append(f"| Security Controls | {controls_str} |")
        lines.append(f"| STIG Finding | {entry.stig_id or '—'} |")
        lines.append(f"| Severity | {entry.severity} |")
        components_str = (
            ", ".join(entry.affected_components) if entry.affected_components else "—"
        )
        lines.append(f"| Affected Components | {components_str} |")
        lines.append(f"| Point of Contact | {entry.point_of_contact} |")
        lines.append(f"| Resources Required | {entry.resources_required} |")
        lines.append(f"| Scheduled Completion | {entry.scheduled_completion} ({_cat_days_label(entry.severity)}) |")
        lines.append(f"| Status | {entry.status} |")
        lines.append(f"| Source | {entry.source} |")
        lines.append("")

        lines.append("**Milestones:**")
        for i, milestone in enumerate(entry.milestones, start=1):
            lines.append(f"{i}. {milestone}")
        lines.append("")

        if entry.weakness_description:
            lines.append("**Weakness Description:**")
            lines.append(entry.weakness_description)
            lines.append("")

        if entry.comments:
            lines.append("**Assessor Notes:**")
            lines.append(entry.comments)
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def _cat_days_label(severity: str) -> str:
    return {"CAT I": "30 days", "CAT II": "90 days", "CAT III": "180 days"}.get(severity, "")


_CSV_COLUMNS = [
    "Item",
    "Weakness",
    "Description",
    "Controls",
    "STIG_ID",
    "Severity",
    "Affected_Components",
    "POC",
    "Resources",
    "Scheduled_Completion",
    "Milestones",
    "Status",
    "Source",
    "Comments",
]


def poam_to_csv(poam: PoamReport) -> str:
    """Render a PoamReport as CSV."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()

    for entry in poam.entries:
        writer.writerow({
            "Item": entry.item_number,
            "Weakness": entry.weakness_name,
            "Description": entry.weakness_description,
            "Controls": "; ".join(entry.security_controls),
            "STIG_ID": entry.stig_id or "",
            "Severity": entry.severity,
            "Affected_Components": "; ".join(entry.affected_components),
            "POC": entry.point_of_contact,
            "Resources": entry.resources_required,
            "Scheduled_Completion": entry.scheduled_completion,
            "Milestones": " | ".join(entry.milestones),
            "Status": entry.status,
            "Source": entry.source,
            "Comments": entry.comments,
        })

    return buf.getvalue()


def write_poam(poam: PoamReport, output_path: Path, fmt: str = "md") -> None:
    """Write a PoamReport to *output_path* in the requested format.

    Args:
        poam: The report to write.
        output_path: Destination path (created or overwritten).
        fmt: ``"md"`` for Markdown or ``"csv"`` for CSV.

    Raises:
        ValueError: If *fmt* is not ``"md"`` or ``"csv"``.
    """
    if fmt == "md":
        content = poam_to_markdown(poam)
    elif fmt == "csv":
        content = poam_to_csv(poam)
    else:
        raise ValueError(f"Unsupported format '{fmt}'. Use 'md' or 'csv'.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
