"""Tests for the 800-53 control evidence report generator (output.report)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from stigcode.ingest.xccdf import StigBenchmark, StigFinding
from stigcode.mapping.engine import MappingDatabase, StigMapping
from stigcode.mapping.status import (
    CklStatus,
    DeterminationConfidence,
    FindingDetermination,
    StatusReport,
    determine_status,
)
from stigcode.output.report import generate_report, write_report

# ---------------------------------------------------------------------------
# Shared fixture helpers (mirrors test_status.py conventions)
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"
XCCDF_FILE = Path(__file__).parent.parent / "data" / "stigs" / "application_security_and_development.xml"
SARIF_CWE_TAGS = FIXTURES_DIR / "sarif" / "cwe_in_tags.sarif"


def _make_stig_finding(
    vuln_id: str,
    severity: str = "medium",
    cci_refs: list[str] | None = None,
    fix_text: str = "",
    title: str = "",
) -> StigFinding:
    cat = {"high": 1, "medium": 2, "low": 3}[severity]
    return StigFinding(
        vuln_id=vuln_id,
        rule_id=f"SV-{vuln_id}_rule",
        check_id=f"APSC-DV-{vuln_id}",
        title=title or f"Title for {vuln_id}",
        description="",
        severity=severity,
        category=cat,
        cci_refs=cci_refs or [],
        fix_text=fix_text,
        check_content="",
    )


def _make_determination(
    stig_id: str,
    status: CklStatus,
    confidence: DeterminationConfidence = DeterminationConfidence.INFERRED,
    evidence: list[str] | None = None,
    mapped_cwe_ids: list[int] | None = None,
) -> FindingDetermination:
    return FindingDetermination(
        stig_id=stig_id,
        status=status,
        confidence=confidence,
        evidence=evidence or [],
        mapped_cwe_ids=mapped_cwe_ids or [],
    )


@pytest.fixture()
def benchmark() -> StigBenchmark:
    return StigBenchmark(
        benchmark_id="ASD_STIG_V6R3",
        title="Application Security and Development STIG",
        version="6",
        release="3",
        date="01 Jan 2025",
        findings=[
            _make_stig_finding("V-100001", severity="high", fix_text="Apply input validation."),
            _make_stig_finding("V-100002", severity="medium", fix_text="Encode all output."),
            _make_stig_finding("V-100003", severity="medium"),
            _make_stig_finding("V-100004", severity="low"),
        ],
        profiles={},
    )


@pytest.fixture()
def mapping_db() -> MappingDatabase:
    return MappingDatabase(
        mappings=[
            StigMapping(
                cwe_id=89, stig_id="V-100001", check_id="APSC-DV-000001",
                confidence="direct", nist_control="SI-10",
            ),
            StigMapping(
                cwe_id=79, stig_id="V-100002", check_id="APSC-DV-000002",
                confidence="inferred", nist_control="SI-10",
            ),
            StigMapping(
                cwe_id=22, stig_id="V-100003", check_id="APSC-DV-000003",
                confidence="inferred", nist_control="AC-3",
            ),
        ],
        version="1.0.0",
        stig_name="Test STIG",
        stig_version="V1",
    )


@pytest.fixture()
def status_report(benchmark, mapping_db) -> StatusReport:
    """Report with 1 open CAT I, 1 open CAT II, 1 not-a-finding, 1 not-reviewed."""
    determinations = [
        _make_determination(
            "V-100001", CklStatus.OPEN, DeterminationConfidence.INFERRED,
            evidence=["src/app.py:42", "src/db.py:88"],
            mapped_cwe_ids=[89],
        ),
        _make_determination(
            "V-100002", CklStatus.OPEN, DeterminationConfidence.DIRECT,
            evidence=["src/views.py:10"],
        ),
        _make_determination("V-100003", CklStatus.NOT_A_FINDING),
        _make_determination("V-100004", CklStatus.NOT_REVIEWED, DeterminationConfidence.NONE),
    ]
    return StatusReport(
        determinations=determinations,
        scan_summary={
            "scanner_name": "Semgrep",
            "scanner_version": "1.50",
            "total_sarif_findings": 3,
            "benchmark_id": "ASD_STIG_V6R3",
            "benchmark_title": "Application Security and Development STIG",
            "total_stig_findings": 4,
        },
    )


@pytest.fixture()
def scan_date() -> datetime:
    return datetime(2024, 3, 23)


@pytest.fixture()
def report_md(status_report, benchmark, mapping_db, scan_date) -> str:
    return generate_report(status_report, benchmark, mapping_db, scan_date)


# ---------------------------------------------------------------------------
# Title and top-level structure
# ---------------------------------------------------------------------------

def test_report_title(report_md):
    assert "# Security Assessment Evidence" in report_md, (
        f"Expected 'Security Assessment Evidence' title. Got:\n{report_md[:500]}"
    )


def test_report_contains_purpose(report_md):
    assert "## Purpose" in report_md


def test_report_contains_applicable_controls(report_md):
    assert "## Applicable Controls" in report_md, "Missing Applicable Controls section"


def test_report_mentions_sa11(report_md):
    assert "SA-11" in report_md, "SA-11 must appear in report"


def test_report_contains_executive_summary(report_md):
    assert "## Executive Summary" in report_md, "Missing Executive Summary section"


def test_report_contains_control_evidence(report_md):
    assert "## Control Evidence" in report_md


def test_report_contains_findings_by_severity(report_md):
    assert "## Findings by Severity" in report_md


def test_report_contains_open_findings_summary(report_md):
    assert "## Open Findings Summary" in report_md


def test_report_contains_nist_control_mapping(report_md):
    assert "## NIST 800-53 Control Mapping" in report_md


def test_report_contains_scope_and_limitations(report_md):
    assert "## Assessment Scope and Limitations" in report_md, (
        "Missing Scope and Limitations section"
    )


def test_report_contains_methodology(report_md):
    assert "## Methodology" in report_md


def test_report_contains_attestation(report_md):
    assert "## Attestation" in report_md


# ---------------------------------------------------------------------------
# SA-11 assessment status logic
# ---------------------------------------------------------------------------

def test_sa11_status_other_than_satisfied_when_cat1_open(report_md):
    # Fixture has a CAT I open finding (V-100001)
    assert "Other Than Satisfied" in report_md, (
        f"Expected 'Other Than Satisfied' due to open CAT I. Got:\n{report_md[:1000]}"
    )


def test_sa11_status_satisfied_when_no_open(benchmark, mapping_db, scan_date):
    determinations = [
        _make_determination("V-100001", CklStatus.NOT_A_FINDING),
        _make_determination("V-100002", CklStatus.NOT_A_FINDING),
    ]
    report = StatusReport(
        determinations=determinations,
        scan_summary={"scanner_name": "Semgrep", "scanner_version": "1.50", "total_stig_findings": 2},
    )
    md = generate_report(report, benchmark, mapping_db, scan_date)
    assert "Satisfied" in md
    assert "Other Than Satisfied" not in md
    assert "Partially Satisfied" not in md


def test_sa11_status_partially_satisfied_when_only_cat2_open(benchmark, mapping_db, scan_date):
    determinations = [
        _make_determination("V-100001", CklStatus.NOT_A_FINDING),  # CAT I, closed
        _make_determination("V-100002", CklStatus.OPEN),            # CAT II, open
    ]
    report = StatusReport(
        determinations=determinations,
        scan_summary={"scanner_name": "Semgrep", "scanner_version": "1.50", "total_stig_findings": 2},
    )
    md = generate_report(report, benchmark, mapping_db, scan_date)
    assert "Partially Satisfied" in md, f"Expected 'Partially Satisfied':\n{md[:1000]}"


# ---------------------------------------------------------------------------
# Count accuracy
# ---------------------------------------------------------------------------

def test_executive_summary_open_count(report_md, status_report):
    assert f"| Open | {status_report.open_count} |" in report_md, (
        f"Expected open count {status_report.open_count} in summary table. Got:\n{report_md}"
    )


def test_executive_summary_naf_count(report_md, status_report):
    assert f"| Not a Finding | {status_report.not_a_finding_count} |" in report_md


def test_executive_summary_not_reviewed_count(report_md, status_report):
    assert f"| Not Reviewed | {status_report.not_reviewed_count} |" in report_md


# ---------------------------------------------------------------------------
# Open findings ordering (CAT I before CAT II)
# ---------------------------------------------------------------------------

def test_open_findings_cat_i_before_cat_ii(report_md):
    pos_cat1 = report_md.find("CAT I")
    pos_cat2 = report_md.find("CAT II")
    assert pos_cat1 < pos_cat2, (
        f"CAT I section (pos {pos_cat1}) should appear before CAT II section (pos {pos_cat2})"
    )


def test_open_finding_stig_id_present(report_md):
    assert "V-100001" in report_md
    assert "V-100002" in report_md


# ---------------------------------------------------------------------------
# POA&M framing
# ---------------------------------------------------------------------------

def test_open_findings_framed_as_poam(report_md):
    assert "POA&M" in report_md, "Open findings should reference POA&M"


# ---------------------------------------------------------------------------
# Evidence locations
# ---------------------------------------------------------------------------

def test_evidence_locations_in_open_findings(report_md):
    assert "src/app.py:42" in report_md, f"Evidence location missing:\n{report_md}"
    assert "src/db.py:88" in report_md


# ---------------------------------------------------------------------------
# Attestation section content
# ---------------------------------------------------------------------------

def test_attestation_includes_scanner_name(report_md):
    assert "Semgrep" in report_md, "Scanner name missing from report"


def test_attestation_includes_stigcode_version(report_md):
    from stigcode.version import __version__
    assert __version__ in report_md, f"Stigcode version {__version__!r} missing from report"


# ---------------------------------------------------------------------------
# Methodology section
# ---------------------------------------------------------------------------

def test_methodology_mentions_direct_confidence(report_md):
    assert "Direct" in report_md


def test_methodology_mentions_inferred_confidence(report_md):
    assert "Inferred" in report_md


def test_methodology_mentions_not_reviewed(report_md):
    assert "Not Reviewed" in report_md


# ---------------------------------------------------------------------------
# Scope and limitations content
# ---------------------------------------------------------------------------

def test_scope_mentions_static_analysis(report_md):
    assert "static analysis" in report_md.lower(), (
        "Scope section should mention static analysis limitations"
    )


# ---------------------------------------------------------------------------
# Zero open findings
# ---------------------------------------------------------------------------

@pytest.fixture()
def no_open_report(benchmark, mapping_db) -> StatusReport:
    determinations = [
        _make_determination("V-100001", CklStatus.NOT_A_FINDING),
        _make_determination("V-100002", CklStatus.NOT_A_FINDING),
        _make_determination("V-100003", CklStatus.NOT_REVIEWED, DeterminationConfidence.NONE),
        _make_determination("V-100004", CklStatus.NOT_REVIEWED, DeterminationConfidence.NONE),
    ]
    return StatusReport(
        determinations=determinations,
        scan_summary={
            "scanner_name": "Semgrep",
            "scanner_version": "1.50",
            "total_sarif_findings": 0,
            "benchmark_id": "ASD_STIG_V6R3",
            "benchmark_title": "Application Security and Development STIG",
            "total_stig_findings": 4,
        },
    )


def test_no_open_findings_message(no_open_report, benchmark, mapping_db, scan_date):
    md = generate_report(no_open_report, benchmark, mapping_db, scan_date)
    assert "No open findings" in md, f"Expected 'No open findings' message:\n{md}"


# ---------------------------------------------------------------------------
# Custom scan date
# ---------------------------------------------------------------------------

def test_custom_scan_date_used(status_report, benchmark, mapping_db):
    custom_date = datetime(2023, 6, 15)
    md = generate_report(status_report, benchmark, mapping_db, scan_date=custom_date)
    assert "2023-06-15" in md, f"Custom scan date not found in report:\n{md}"


def test_default_scan_date_is_present(status_report, benchmark, mapping_db):
    """Without a scan_date argument, the report should still include a date."""
    md = generate_report(status_report, benchmark, mapping_db)
    assert "Assessment Date" in md


# ---------------------------------------------------------------------------
# write_report helper
# ---------------------------------------------------------------------------

def test_write_report_creates_file(tmp_path, status_report, benchmark, mapping_db, scan_date):
    out = tmp_path / "report.md"
    write_report(status_report, benchmark, mapping_db, out, scan_date)
    assert out.exists(), "write_report did not create the output file"
    content = out.read_text(encoding="utf-8")
    assert "## Executive Summary" in content


def test_write_report_creates_parent_dirs(tmp_path, status_report, benchmark, mapping_db, scan_date):
    out = tmp_path / "nested" / "dir" / "report.md"
    write_report(status_report, benchmark, mapping_db, out, scan_date)
    assert out.exists()


# ---------------------------------------------------------------------------
# Integration test: real pipeline data
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not XCCDF_FILE.exists() or not SARIF_CWE_TAGS.exists(),
    reason="Real XCCDF / SARIF fixtures not present",
)
def test_integration_real_pipeline():
    """Run the full pipeline with real fixture data and verify the report is well-formed."""
    from stigcode.ingest.sarif import parse_sarif
    from stigcode.ingest.xccdf import parse_xccdf
    from stigcode.mapping.engine import load_mapping_database

    mapping_path = FIXTURES_DIR / "mappings" / "test_mappings.yaml"
    db = load_mapping_database(mapping_path)
    benchmark = parse_xccdf(XCCDF_FILE)
    sarif_result = parse_sarif(SARIF_CWE_TAGS)

    classifications = {f.vuln_id: "sast" for f in benchmark.findings}
    report = determine_status(sarif_result.findings, db, benchmark, classifications)

    md = generate_report(report, benchmark, db, scan_date=datetime(2024, 1, 1))

    assert len(md) > 100, f"Report unexpectedly short ({len(md)} chars)"
    for heading in [
        "# Security Assessment Evidence",
        "## Applicable Controls",
        "SA-11",
        "## Executive Summary",
        "## Findings by Severity",
        "## Open Findings Summary",
        "## NIST 800-53 Control Mapping",
        "## Assessment Scope and Limitations",
        "## Methodology",
        "## Attestation",
    ]:
        assert heading in md, f"Missing section: {heading!r}"
