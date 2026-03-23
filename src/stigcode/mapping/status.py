"""Finding status determination: combines SARIF findings with CWE→STIG mappings.

Produces CKL-ready status determinations for each STIG finding in a benchmark,
following the confidence and evidence chain defined in docs/sarif-contract.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from stigcode.ingest.sarif import NormalizedFinding
from stigcode.ingest.xccdf import StigBenchmark, StigFinding
from stigcode.mapping.engine import MappingDatabase


class CklStatus(Enum):
    OPEN = "Open"
    NOT_A_FINDING = "NotAFinding"
    NOT_REVIEWED = "Not_Reviewed"
    NOT_APPLICABLE = "Not_Applicable"


class DeterminationConfidence(Enum):
    DIRECT = "direct"      # SARIF had explicit STIG IDs
    INFERRED = "inferred"  # Mapped via CWE
    PARTIAL = "partial"    # Incomplete coverage
    NONE = "none"          # No evidence either way


@dataclass
class FindingDetermination:
    """Status determination for a single STIG finding."""

    stig_id: str
    status: CklStatus
    confidence: DeterminationConfidence
    evidence: list[str] = field(default_factory=list)    # file:line references from SARIF
    review_notes: str = ""    # explanation for assessors
    mapped_cwe_ids: list[int] = field(default_factory=list)
    is_sast_assessable: bool = True


@dataclass
class StatusReport:
    """Complete status report for all STIG findings."""

    determinations: list[FindingDetermination]
    scan_summary: dict  # scanner name, version, total findings, etc.

    @property
    def open_count(self) -> int:
        return sum(1 for d in self.determinations if d.status == CklStatus.OPEN)

    @property
    def not_a_finding_count(self) -> int:
        return sum(1 for d in self.determinations if d.status == CklStatus.NOT_A_FINDING)

    @property
    def not_reviewed_count(self) -> int:
        return sum(1 for d in self.determinations if d.status == CklStatus.NOT_REVIEWED)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _format_evidence(f: NormalizedFinding) -> str:
    """Return a file:line reference string for a finding."""
    if f.file_path and f.start_line:
        return f"{f.file_path}:{f.start_line}"
    if f.file_path:
        return f.file_path
    return f.rule_id or "unknown location"


def _direct_match(
    stig_id: str,
    sarif_findings: list[NormalizedFinding],
    scanner_name: str,
) -> FindingDetermination | None:
    """Return an Open/direct determination if any SARIF finding explicitly names this STIG."""
    matches = [f for f in sarif_findings if stig_id in f.stig_ids]
    if not matches:
        return None

    evidence = [_format_evidence(f) for f in matches]
    evidence_str = ", ".join(evidence)
    return FindingDetermination(
        stig_id=stig_id,
        status=CklStatus.OPEN,
        confidence=DeterminationConfidence.DIRECT,
        evidence=evidence,
        review_notes=(
            f"Scanner reported STIG finding directly. Evidence at: {evidence_str}"
        ),
    )


def _inferred_match(
    stig_id: str,
    sarif_findings: list[NormalizedFinding],
    mapping_db: MappingDatabase,
) -> FindingDetermination | None:
    """Return an Open/inferred determination if any SARIF finding maps via CWE to this STIG."""
    # Collect all CWE→STIG mappings for this STIG ID
    stig_mappings = mapping_db.lookup_by_stig(stig_id)
    if not stig_mappings:
        return None

    mapped_cwes = {m.cwe_id for m in stig_mappings}

    # Find SARIF findings whose CWE IDs overlap with this STIG's known CWEs
    matching: list[NormalizedFinding] = []
    matched_cwes: list[int] = []
    for f in sarif_findings:
        overlap = set(f.cwe_ids) & mapped_cwes
        if overlap:
            matching.append(f)
            matched_cwes.extend(overlap)

    if not matching:
        return None

    evidence = [_format_evidence(f) for f in matching]
    evidence_str = ", ".join(evidence)
    cwe_str = ", ".join(f"CWE-{c}" for c in sorted(set(matched_cwes)))

    return FindingDetermination(
        stig_id=stig_id,
        status=CklStatus.OPEN,
        confidence=DeterminationConfidence.INFERRED,
        evidence=evidence,
        review_notes=(
            f"Finding inferred via {cwe_str} mapping (confidence: inferred). "
            f"Evidence at: {evidence_str}. Review recommended."
        ),
        mapped_cwe_ids=sorted(set(matched_cwes)),
    )


def _no_match_determination(
    stig_id: str,
    mapping_db: MappingDatabase,
    scanner_name: str,
    scanner_version: str,
) -> FindingDetermination:
    """Return NotAFinding or Not_Reviewed when no SARIF findings matched this STIG."""
    stig_mappings = mapping_db.lookup_by_stig(stig_id)
    if stig_mappings:
        mapped_cwes = sorted({m.cwe_id for m in stig_mappings})
        cwe_str = ", ".join(f"CWE-{c}" for c in mapped_cwes)
        scanner_info = scanner_name
        if scanner_version:
            scanner_info = f"{scanner_name} v{scanner_version}"
        return FindingDetermination(
            stig_id=stig_id,
            status=CklStatus.NOT_A_FINDING,
            confidence=DeterminationConfidence.INFERRED,
            review_notes=(
                f"Automated scan completed with no findings for CWE(s) {cwe_str}. "
                f"Scanner: {scanner_info}."
            ),
            mapped_cwe_ids=mapped_cwes,
        )

    return FindingDetermination(
        stig_id=stig_id,
        status=CklStatus.NOT_REVIEWED,
        confidence=DeterminationConfidence.NONE,
        review_notes="No CWE mapping available for automated assessment",
    )


def _determine_for_finding(
    stig_finding: StigFinding,
    sarif_findings: list[NormalizedFinding],
    mapping_db: MappingDatabase,
    classifications: dict[str, str],
    scanner_name: str,
    scanner_version: str,
) -> FindingDetermination:
    """Determine the CKL status for a single STIG finding."""
    stig_id = stig_finding.vuln_id
    classification = classifications.get(stig_id, {})
    # Accept either a raw string or the nested dict from the YAML
    if isinstance(classification, dict):
        method = classification.get("assessment_method", "sast")
    else:
        method = str(classification)

    is_sast = method == "sast"

    if not is_sast:
        det = FindingDetermination(
            stig_id=stig_id,
            status=CklStatus.NOT_REVIEWED,
            confidence=DeterminationConfidence.NONE,
            review_notes=(
                "This finding requires manual assessment "
                "(procedural/configuration control)"
            ),
            is_sast_assessable=False,
        )
        return det

    # SAST path — try direct, then inferred, then no-match
    direct = _direct_match(stig_id, sarif_findings, scanner_name)
    if direct is not None:
        direct.is_sast_assessable = True
        return direct

    inferred = _inferred_match(stig_id, sarif_findings, mapping_db)
    if inferred is not None:
        inferred.is_sast_assessable = True
        return inferred

    det = _no_match_determination(stig_id, mapping_db, scanner_name, scanner_version)
    det.is_sast_assessable = True
    return det


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def determine_status(
    sarif_findings: list[NormalizedFinding],
    mapping_db: MappingDatabase,
    benchmark: StigBenchmark,
    classifications: dict[str, str],
) -> StatusReport:
    """Determine CKL status for every STIG finding in the benchmark.

    Args:
        sarif_findings: Normalized findings from one or more SARIF runs.
        mapping_db: Loaded CWE→STIG mapping database.
        benchmark: Parsed STIG benchmark providing the authoritative finding list.
        classifications: Dict mapping V-IDs to "sast" or "procedural".
            Values may be bare strings or nested dicts with an
            ``assessment_method`` key (as produced by the YAML loader).

    Returns:
        StatusReport with a FindingDetermination for every finding in the benchmark.
    """
    # Derive scanner metadata from the first finding that has it
    scanner_name = ""
    scanner_version = ""
    for f in sarif_findings:
        if f.scanner_name:
            scanner_name = f.scanner_name
            scanner_version = f.scanner_version
            break

    determinations: list[FindingDetermination] = []
    for stig_finding in benchmark.findings:
        det = _determine_for_finding(
            stig_finding=stig_finding,
            sarif_findings=sarif_findings,
            mapping_db=mapping_db,
            classifications=classifications,
            scanner_name=scanner_name,
            scanner_version=scanner_version,
        )
        determinations.append(det)

    scan_summary: dict = {
        "scanner_name": scanner_name,
        "scanner_version": scanner_version,
        "total_sarif_findings": len(sarif_findings),
        "benchmark_id": benchmark.benchmark_id,
        "benchmark_title": benchmark.title,
        "total_stig_findings": len(benchmark.findings),
    }

    return StatusReport(determinations=determinations, scan_summary=scan_summary)
