"""NIST 800-53 control coverage matrix generator.

Produces Markdown and CSV coverage matrices from a StatusReport,
showing which controls have automated evidence vs. gaps.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from stigcode.ingest.xccdf import StigBenchmark
from stigcode.mapping.engine import MappingDatabase
from stigcode.mapping.status import CklStatus, StatusReport

NIST_FAMILIES: dict[str, str] = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "PII Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}


@dataclass
class ControlCoverage:
    """Coverage status for a single NIST 800-53 control."""

    control_id: str       # e.g., "SI-10"
    control_family: str   # e.g., "SI"
    total_findings: int   # STIG findings mapped to this control
    open_findings: int
    not_a_finding: int
    not_reviewed: int
    evidence_type: str    # "automated", "manual", "mixed", "none"
    stig_ids: list[str] = field(default_factory=list)

    @property
    def coverage_pct(self) -> float:
        """Percentage of findings with automated evidence (open or NAF)."""
        if self.total_findings == 0:
            return 0.0
        automated = self.open_findings + self.not_a_finding
        return 100.0 * automated / self.total_findings


@dataclass
class CoverageMatrix:
    """Complete NIST 800-53 coverage matrix."""

    controls: list[ControlCoverage]

    @property
    def total_controls(self) -> int:
        return len(self.controls)

    @property
    def covered_controls(self) -> int:
        """Controls with at least one automated finding (open or not_a_finding)."""
        return sum(
            1 for c in self.controls
            if (c.open_findings + c.not_a_finding) > 0
        )

    @property
    def gap_controls(self) -> int:
        """Controls with zero automated coverage."""
        return self.total_controls - self.covered_controls

    @property
    def coverage_percentage(self) -> float:
        if self.total_controls == 0:
            return 0.0
        return 100.0 * self.covered_controls / self.total_controls


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def _control_sort_key(control_id: str) -> tuple[str, int, str]:
    """Sort key that groups by family, then numerically by control number."""
    parts = control_id.split("-", 1)
    family = parts[0] if parts else control_id
    if len(parts) == 2:
        # Handle enhancements like "AC-2(1)" — sort by base number first
        remainder = parts[1]
        base = remainder.split("(")[0]
        try:
            return (family, int(base), remainder)
        except ValueError:
            return (family, 0, remainder)
    return (family, 0, "")


def build_coverage_matrix(
    report: StatusReport,
    benchmark: StigBenchmark,
    cci_mappings: dict[str, str],
    mapping_db: Optional[MappingDatabase] = None,
) -> CoverageMatrix:
    """Build a NIST 800-53 coverage matrix from assessment results.

    Args:
        report: Status determinations for all STIG findings.
        benchmark: Parsed STIG benchmark (source of CCI refs per finding).
        cci_mappings: Dict mapping CCI IDs to NIST control IDs,
                      e.g. {"CCI-000054": "AC-2"}.
        mapping_db: Optional CWE→STIG mapping database used as a fallback
                    when a finding has no CCI refs (or none resolve to a known
                    control).  When provided, any STIG ID that still has no
                    resolved NIST control is looked up in the mapping DB and
                    the first ``nist_control`` value found is used.

    Returns:
        CoverageMatrix sorted by control family then control ID.
    """
    # Index determinations by STIG ID for O(1) lookup
    status_by_stig: dict[str, CklStatus] = {
        d.stig_id: d.status for d in report.determinations
    }

    # Pre-build a stig_id → nist_control index from the mapping DB so the
    # fallback lookup is O(1) rather than O(n) per finding.
    db_nist_by_stig: dict[str, str] = {}
    if mapping_db is not None:
        for m in mapping_db.mappings:
            if m.stig_id not in db_nist_by_stig and m.nist_control:
                db_nist_by_stig[m.stig_id] = m.nist_control

    # Accumulate per-control stats
    # control_id → {open, naf, nr, stig_ids}
    acc: dict[str, dict] = {}

    for finding in benchmark.findings:
        stig_id = finding.vuln_id
        status = status_by_stig.get(stig_id)
        if status is None:
            continue

        # Map each CCI ref to a NIST control (highest fidelity path)
        nist_controls: set[str] = set()
        for cci in finding.cci_refs:
            control = cci_mappings.get(cci)
            if control:
                nist_controls.add(control)

        # Fallback: use the mapping DB's nist_control when no CCI resolved
        if not nist_controls and stig_id in db_nist_by_stig:
            nist_controls.add(db_nist_by_stig[stig_id])

        # Still nothing — skip (can't attribute to a NIST control)
        if not nist_controls:
            continue

        for control_id in nist_controls:
            if control_id not in acc:
                acc[control_id] = {
                    "open": 0,
                    "naf": 0,
                    "nr": 0,
                    "stig_ids": [],
                }
            entry = acc[control_id]
            if status == CklStatus.OPEN:
                entry["open"] += 1
            elif status == CklStatus.NOT_A_FINDING:
                entry["naf"] += 1
            else:
                # NOT_REVIEWED and NOT_APPLICABLE both count as unreviewed
                entry["nr"] += 1
            if stig_id not in entry["stig_ids"]:
                entry["stig_ids"].append(stig_id)

    controls: list[ControlCoverage] = []
    for control_id, entry in acc.items():
        family = control_id.split("-")[0]
        automated = entry["open"] + entry["naf"]
        manual = entry["nr"]
        total = automated + manual

        if total == 0:
            evidence_type = "none"
        elif automated > 0 and manual == 0:
            evidence_type = "automated"
        elif automated == 0 and manual > 0:
            evidence_type = "manual"
        else:
            evidence_type = "mixed"

        controls.append(ControlCoverage(
            control_id=control_id,
            control_family=family,
            total_findings=total,
            open_findings=entry["open"],
            not_a_finding=entry["naf"],
            not_reviewed=entry["nr"],
            evidence_type=evidence_type,
            stig_ids=sorted(entry["stig_ids"]),
        ))

    controls.sort(key=lambda c: _control_sort_key(c.control_id))
    return CoverageMatrix(controls=controls)


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def matrix_to_markdown(matrix: CoverageMatrix) -> str:
    """Render coverage matrix as a Markdown document."""
    lines: list[str] = []

    lines.append("# NIST 800-53 Control Coverage Matrix")
    lines.append("")

    # --- Summary table ---
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total Controls | {matrix.total_controls} |")
    covered = matrix.covered_controls
    pct = matrix.coverage_percentage
    lines.append(f"| Automated Coverage | {covered} ({pct:.1f}%) |")
    manual_only = sum(1 for c in matrix.controls if c.evidence_type == "manual")
    lines.append(f"| Manual Only | {manual_only} |")
    lines.append(f"| Zero Coverage | {matrix.gap_controls} |")
    lines.append("")

    # --- Family summary ---
    lines.append("## Coverage by Control Family")
    lines.append("")
    lines.append("| Family | Description | Covered | Total | % |")
    lines.append("|--------|-------------|---------|-------|---|")

    # Group by family
    families: dict[str, list[ControlCoverage]] = {}
    for ctrl in matrix.controls:
        families.setdefault(ctrl.control_family, []).append(ctrl)

    for family in sorted(families):
        ctrls = families[family]
        description = NIST_FAMILIES.get(family, "")
        total = len(ctrls)
        fam_covered = sum(
            1 for c in ctrls if (c.open_findings + c.not_a_finding) > 0
        )
        fam_pct = 100.0 * fam_covered / total if total else 0.0
        lines.append(
            f"| {family} | {description} | {fam_covered} | {total} | {fam_pct:.1f}% |"
        )
    lines.append("")

    # --- Detailed matrix ---
    lines.append("## Detailed Control Matrix")
    lines.append("")
    lines.append("| Control | Findings | Open | Clear | Review | Evidence |")
    lines.append("|---------|----------|------|-------|--------|----------|")

    for ctrl in matrix.controls:
        lines.append(
            f"| {ctrl.control_id} "
            f"| {ctrl.total_findings} "
            f"| {ctrl.open_findings} "
            f"| {ctrl.not_a_finding} "
            f"| {ctrl.not_reviewed} "
            f"| {ctrl.evidence_type} |"
        )
    lines.append("")

    # --- Zero coverage ---
    gap_controls = [c for c in matrix.controls if c.evidence_type == "none"]
    if gap_controls:
        lines.append("## Zero-Coverage Controls")
        lines.append("")
        lines.append("The following controls have no STIG findings mapped:")
        for ctrl in gap_controls:
            description = NIST_FAMILIES.get(ctrl.control_family, "")
            if description:
                lines.append(f"- {ctrl.control_id}: {description}")
            else:
                lines.append(f"- {ctrl.control_id}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CSV renderer
# ---------------------------------------------------------------------------

def matrix_to_csv(matrix: CoverageMatrix) -> str:
    """Render coverage matrix as CSV.

    Columns: Control,Family,Total_Findings,Open,NotAFinding,Not_Reviewed,
             Evidence_Type,Coverage_Pct,STIG_IDs
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Control", "Family", "Total_Findings", "Open",
        "NotAFinding", "Not_Reviewed", "Evidence_Type",
        "Coverage_Pct", "STIG_IDs",
    ])
    for ctrl in matrix.controls:
        writer.writerow([
            ctrl.control_id,
            ctrl.control_family,
            ctrl.total_findings,
            ctrl.open_findings,
            ctrl.not_a_finding,
            ctrl.not_reviewed,
            ctrl.evidence_type,
            f"{ctrl.coverage_pct:.1f}",
            " ".join(ctrl.stig_ids),
        ])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# File writer
# ---------------------------------------------------------------------------

def write_coverage(matrix: CoverageMatrix, output_path: Path, fmt: str = "md") -> None:
    """Write coverage matrix to a file.

    Args:
        matrix: Populated CoverageMatrix.
        output_path: Destination file path.
        fmt: Output format — "md" for Markdown, "csv" for CSV.

    Raises:
        ValueError: If ``fmt`` is not "md" or "csv".
    """
    if fmt == "md":
        content = matrix_to_markdown(matrix)
    elif fmt == "csv":
        content = matrix_to_csv(matrix)
    else:
        raise ValueError(f"Unknown format {fmt!r}. Use 'md' or 'csv'.")

    output_path.write_text(content, encoding="utf-8")
