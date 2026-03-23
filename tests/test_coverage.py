"""Tests for the NIST 800-53 coverage matrix generator (output.coverage)."""

from __future__ import annotations

import csv
import io
from pathlib import Path

import pytest

from stigcode.ingest.xccdf import StigBenchmark, StigFinding
from stigcode.mapping.engine import MappingDatabase, StigMapping
from stigcode.mapping.status import CklStatus, FindingDetermination, StatusReport
from stigcode.output.coverage import (
    ControlCoverage,
    CoverageMatrix,
    build_coverage_matrix,
    matrix_to_csv,
    matrix_to_markdown,
    write_coverage,
)

# ---------------------------------------------------------------------------
# Helpers / shared fixtures
# ---------------------------------------------------------------------------

# CCI→NIST mapping used across tests
CCI_MAPPINGS: dict[str, str] = {
    "CCI-000054": "AC-2",
    "CCI-000060": "AC-3",
    "CCI-001310": "SI-10",
    "CCI-001312": "SI-10",
    "CCI-002038": "IA-5",
}


def _finding(
    vuln_id: str,
    cci_refs: list[str] | None = None,
    severity: str = "medium",
) -> StigFinding:
    return StigFinding(
        vuln_id=vuln_id,
        rule_id=f"SV-{vuln_id}_rule",
        check_id=f"APSC-DV-{vuln_id}",
        title=f"Title for {vuln_id}",
        description="",
        severity=severity,
        category={"high": 1, "medium": 2, "low": 3}[severity],
        cci_refs=cci_refs or [],
        fix_text="",
        check_content="",
    )


def _det(
    stig_id: str,
    status: CklStatus,
) -> FindingDetermination:
    return FindingDetermination(
        stig_id=stig_id,
        status=status,
        confidence=None,  # type: ignore[arg-type]
        evidence=[],
    )


def _report(determinations: list[FindingDetermination]) -> StatusReport:
    return StatusReport(
        determinations=determinations,
        scan_summary={},
    )


def _benchmark(findings: list[StigFinding]) -> StigBenchmark:
    return StigBenchmark(
        benchmark_id="TEST",
        title="Test Benchmark",
        version="1",
        release="1",
        date="01 Jan 2025",
        findings=findings,
        profiles={},
    )


# ---------------------------------------------------------------------------
# Standard test benchmark: 5 findings across 3 controls
#
#   V-100001  CCI-000054  → AC-2     OPEN
#   V-100002  CCI-000060  → AC-3     NOT_A_FINDING
#   V-100003  CCI-001310  → SI-10    OPEN
#   V-100004  CCI-001312  → SI-10    NOT_A_FINDING
#   V-100005  CCI-002038  → IA-5     NOT_REVIEWED
# ---------------------------------------------------------------------------

@pytest.fixture()
def standard_benchmark() -> StigBenchmark:
    return _benchmark([
        _finding("V-100001", ["CCI-000054"]),   # AC-2, OPEN
        _finding("V-100002", ["CCI-000060"]),   # AC-3, NAF
        _finding("V-100003", ["CCI-001310"]),   # SI-10, OPEN
        _finding("V-100004", ["CCI-001312"]),   # SI-10, NAF
        _finding("V-100005", ["CCI-002038"]),   # IA-5, NOT_REVIEWED
    ])


@pytest.fixture()
def standard_report() -> StatusReport:
    return _report([
        _det("V-100001", CklStatus.OPEN),
        _det("V-100002", CklStatus.NOT_A_FINDING),
        _det("V-100003", CklStatus.OPEN),
        _det("V-100004", CklStatus.NOT_A_FINDING),
        _det("V-100005", CklStatus.NOT_REVIEWED),
    ])


@pytest.fixture()
def standard_matrix(standard_report, standard_benchmark) -> CoverageMatrix:
    return build_coverage_matrix(standard_report, standard_benchmark, CCI_MAPPINGS)


# ---------------------------------------------------------------------------
# build_coverage_matrix — control count and basic correctness
# ---------------------------------------------------------------------------

def test_control_count(standard_matrix):
    # 3 distinct controls: AC-2, AC-3, SI-10, IA-5
    assert standard_matrix.total_controls == 4, (
        f"Expected 4 controls, got {standard_matrix.total_controls}: "
        f"{[c.control_id for c in standard_matrix.controls]}"
    )


def test_controls_sorted_by_family_then_id(standard_matrix):
    ids = [c.control_id for c in standard_matrix.controls]
    assert ids == sorted(ids, key=lambda x: (x.split("-")[0], x)), (
        f"Controls not sorted correctly: {ids}"
    )


def test_si10_aggregates_two_findings(standard_matrix):
    si10 = next(c for c in standard_matrix.controls if c.control_id == "SI-10")
    assert si10.total_findings == 2, f"SI-10 should have 2 findings, got {si10.total_findings}"
    assert si10.open_findings == 1
    assert si10.not_a_finding == 1
    assert si10.not_reviewed == 0


# ---------------------------------------------------------------------------
# Evidence type classification
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("statuses,expected_type", [
    ([CklStatus.OPEN, CklStatus.NOT_A_FINDING], "automated"),
    ([CklStatus.NOT_REVIEWED, CklStatus.NOT_REVIEWED], "manual"),
    ([CklStatus.OPEN, CklStatus.NOT_REVIEWED], "mixed"),
    ([CklStatus.NOT_A_FINDING, CklStatus.NOT_REVIEWED], "mixed"),
])
def test_evidence_type_classification(statuses, expected_type):
    findings = [
        _finding(f"V-{i}", ["CCI-001310"])
        for i in range(len(statuses))
    ]
    dets = [_det(f"V-{i}", s) for i, s in enumerate(statuses)]
    report = _report(dets)
    benchmark = _benchmark(findings)
    matrix = build_coverage_matrix(report, benchmark, CCI_MAPPINGS)

    si10 = next((c for c in matrix.controls if c.control_id == "SI-10"), None)
    assert si10 is not None, "SI-10 control not found in matrix"
    assert si10.evidence_type == expected_type, (
        f"Expected evidence_type={expected_type!r}, got {si10.evidence_type!r}"
    )


# ---------------------------------------------------------------------------
# CoverageMatrix aggregate properties
# ---------------------------------------------------------------------------

def test_covered_controls(standard_matrix):
    # AC-2 (open), AC-3 (naf), SI-10 (open+naf) → 3 covered; IA-5 (nr) → not covered
    assert standard_matrix.covered_controls == 3, (
        f"Expected 3 covered controls, got {standard_matrix.covered_controls}"
    )


def test_gap_controls(standard_matrix):
    # IA-5 has only NOT_REVIEWED → 1 gap
    assert standard_matrix.gap_controls == 1, (
        f"Expected 1 gap control, got {standard_matrix.gap_controls}"
    )


def test_coverage_percentage(standard_matrix):
    expected = 100.0 * 3 / 4
    assert abs(standard_matrix.coverage_percentage - expected) < 0.01, (
        f"Expected {expected:.1f}%, got {standard_matrix.coverage_percentage:.1f}%"
    )


def test_coverage_percentage_empty():
    matrix = CoverageMatrix(controls=[])
    assert matrix.coverage_percentage == 0.0


# ---------------------------------------------------------------------------
# All-NotAFinding report (100% automated coverage)
# ---------------------------------------------------------------------------

def test_all_not_a_finding_report():
    findings = [
        _finding("V-1", ["CCI-000054"]),
        _finding("V-2", ["CCI-000060"]),
    ]
    dets = [
        _det("V-1", CklStatus.NOT_A_FINDING),
        _det("V-2", CklStatus.NOT_A_FINDING),
    ]
    matrix = build_coverage_matrix(_report(dets), _benchmark(findings), CCI_MAPPINGS)

    assert matrix.covered_controls == matrix.total_controls
    assert matrix.gap_controls == 0
    assert abs(matrix.coverage_percentage - 100.0) < 0.01
    for ctrl in matrix.controls:
        assert ctrl.evidence_type == "automated", (
            f"Expected automated for {ctrl.control_id}, got {ctrl.evidence_type}"
        )


# ---------------------------------------------------------------------------
# All-Not_Reviewed report (0% automated coverage)
# ---------------------------------------------------------------------------

def test_all_not_reviewed_report():
    findings = [
        _finding("V-1", ["CCI-000054"]),
        _finding("V-2", ["CCI-002038"]),
    ]
    dets = [
        _det("V-1", CklStatus.NOT_REVIEWED),
        _det("V-2", CklStatus.NOT_REVIEWED),
    ]
    matrix = build_coverage_matrix(_report(dets), _benchmark(findings), CCI_MAPPINGS)

    assert matrix.covered_controls == 0
    assert matrix.gap_controls == matrix.total_controls
    for ctrl in matrix.controls:
        assert ctrl.evidence_type == "manual", (
            f"Expected manual for {ctrl.control_id}, got {ctrl.evidence_type}"
        )


# ---------------------------------------------------------------------------
# Findings with no CCI refs (should not appear in matrix)
# ---------------------------------------------------------------------------

def test_findings_without_cci_refs_excluded():
    findings = [
        _finding("V-1", []),            # no CCI → excluded
        _finding("V-2", ["CCI-000054"]),
    ]
    dets = [
        _det("V-1", CklStatus.OPEN),
        _det("V-2", CklStatus.OPEN),
    ]
    matrix = build_coverage_matrix(_report(dets), _benchmark(findings), CCI_MAPPINGS)
    # Only AC-2 should appear; V-1 with no CCIs is excluded
    assert matrix.total_controls == 1
    assert matrix.controls[0].control_id == "AC-2"


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------

def test_markdown_contains_summary_header(standard_matrix):
    md = matrix_to_markdown(standard_matrix)
    assert "## Summary" in md, "Markdown should contain '## Summary'"


def test_markdown_contains_detailed_header(standard_matrix):
    md = matrix_to_markdown(standard_matrix)
    assert "## Detailed Control Matrix" in md


def test_markdown_table_headers(standard_matrix):
    md = matrix_to_markdown(standard_matrix)
    assert "| Control |" in md
    assert "| Findings |" in md
    assert "| Open |" in md
    assert "| Clear |" in md
    assert "| Review |" in md
    assert "| Evidence |" in md


def test_markdown_contains_control_ids(standard_matrix):
    md = matrix_to_markdown(standard_matrix)
    for ctrl in standard_matrix.controls:
        assert ctrl.control_id in md, f"{ctrl.control_id} not found in Markdown output"


def test_markdown_zero_coverage_section():
    # A control with evidence_type "none" appears in the zero-coverage section.
    # Inject a ControlCoverage with evidence_type="none" directly.
    ctrl_none = ControlCoverage(
        control_id="ZZ-99",
        control_family="ZZ",
        total_findings=0,
        open_findings=0,
        not_a_finding=0,
        not_reviewed=0,
        evidence_type="none",
    )
    ctrl_automated = ControlCoverage(
        control_id="AC-2",
        control_family="AC",
        total_findings=1,
        open_findings=1,
        not_a_finding=0,
        not_reviewed=0,
        evidence_type="automated",
    )
    matrix = CoverageMatrix(controls=[ctrl_automated, ctrl_none])
    md = matrix_to_markdown(matrix)
    assert "Zero-Coverage Controls" in md, (
        f"Expected 'Zero-Coverage Controls' section in Markdown output"
    )
    assert "ZZ-99" in md, "Expected ZZ-99 to appear in zero-coverage list"


def test_markdown_family_summary(standard_matrix):
    md = matrix_to_markdown(standard_matrix)
    assert "## Coverage by Control Family" in md
    assert "| AC |" in md or "AC" in md


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------

def test_csv_columns(standard_matrix):
    csv_text = matrix_to_csv(standard_matrix)
    reader = csv.DictReader(io.StringIO(csv_text))
    expected_cols = {
        "Control", "Family", "Total_Findings", "Open",
        "NotAFinding", "Not_Reviewed", "Evidence_Type",
        "Coverage_Pct", "STIG_IDs",
    }
    assert set(reader.fieldnames or []) == expected_cols, (
        f"CSV columns mismatch. Got: {reader.fieldnames}"
    )


def test_csv_row_count(standard_matrix):
    csv_text = matrix_to_csv(standard_matrix)
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(rows) == standard_matrix.total_controls, (
        f"Expected {standard_matrix.total_controls} data rows, got {len(rows)}"
    )


def test_csv_values_for_si10(standard_matrix):
    csv_text = matrix_to_csv(standard_matrix)
    rows = {r["Control"]: r for r in csv.DictReader(io.StringIO(csv_text))}
    si10 = rows.get("SI-10")
    assert si10 is not None, "SI-10 row not found in CSV"
    assert si10["Family"] == "SI"
    assert si10["Total_Findings"] == "2"
    assert si10["Open"] == "1"
    assert si10["NotAFinding"] == "1"
    assert si10["Not_Reviewed"] == "0"
    assert si10["Evidence_Type"] == "automated"


# ---------------------------------------------------------------------------
# write_coverage — file writing
# ---------------------------------------------------------------------------

def test_write_coverage_markdown(tmp_path, standard_matrix):
    out = tmp_path / "coverage.md"
    write_coverage(standard_matrix, out, fmt="md")
    assert out.exists()
    content = out.read_text()
    assert "# NIST 800-53 Control Coverage Matrix" in content


def test_write_coverage_csv(tmp_path, standard_matrix):
    out = tmp_path / "coverage.csv"
    write_coverage(standard_matrix, out, fmt="csv")
    assert out.exists()
    content = out.read_text()
    assert "Control,Family" in content


def test_write_coverage_invalid_format(tmp_path, standard_matrix):
    out = tmp_path / "coverage.xyz"
    with pytest.raises(ValueError, match="Unknown format"):
        write_coverage(standard_matrix, out, fmt="xyz")


# ---------------------------------------------------------------------------
# ControlCoverage.coverage_pct
# ---------------------------------------------------------------------------

def test_control_coverage_pct_no_findings():
    ctrl = ControlCoverage(
        control_id="AC-2",
        control_family="AC",
        total_findings=0,
        open_findings=0,
        not_a_finding=0,
        not_reviewed=0,
        evidence_type="none",
    )
    assert ctrl.coverage_pct == 0.0


def test_control_coverage_pct_half():
    ctrl = ControlCoverage(
        control_id="SI-10",
        control_family="SI",
        total_findings=4,
        open_findings=1,
        not_a_finding=1,
        not_reviewed=2,
        evidence_type="mixed",
    )
    assert abs(ctrl.coverage_pct - 50.0) < 0.01
