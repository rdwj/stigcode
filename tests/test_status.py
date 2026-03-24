"""Tests for the finding status determination module (mapping.status)."""

from __future__ import annotations

import pytest

from stigcode.ingest.sarif import NormalizedFinding
from stigcode.ingest.xccdf import StigBenchmark, StigFinding
from stigcode.mapping.engine import MappingDatabase, StigMapping
from stigcode.mapping.status import (
    CklStatus,
    DeterminationConfidence,
    determine_status,
)

# ---------------------------------------------------------------------------
# Shared fixture data
# ---------------------------------------------------------------------------

# STIG benchmark with 5 findings:
#   V-100001 — SAST, CWE-89 maps to it via the DB
#   V-100002 — SAST, CWE-79 maps to it via the DB
#   V-100003 — SAST, will receive a direct STIG match from SARIF
#   V-100004 — SAST, no CWE mapping in DB
#   V-100005 — procedural

def _make_finding(vuln_id: str, severity: str = "medium") -> StigFinding:
    return StigFinding(
        vuln_id=vuln_id,
        rule_id=f"SV-{vuln_id}_rule",
        check_id=f"APSC-DV-{vuln_id}",
        title=f"Title for {vuln_id}",
        description="",
        severity=severity,
        category={"high": 1, "medium": 2, "low": 3}[severity],
        cci_refs=[],
        fix_text="",
        check_content="",
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
            _make_finding("V-100001"),   # SAST, CWE-89 mapped
            _make_finding("V-100002"),   # SAST, CWE-79 mapped
            _make_finding("V-100003"),   # SAST, direct STIG match in SARIF
            _make_finding("V-100004"),   # SAST, no CWE mapping
            _make_finding("V-100005"),   # procedural
        ],
        profiles={},
    )


@pytest.fixture()
def mapping_db() -> MappingDatabase:
    return MappingDatabase(
        mappings=[
            StigMapping(cwe_id=89,  stig_id="V-100001", check_id="APSC-DV-000001",
                        confidence="direct",   nist_control="SI-10"),
            StigMapping(cwe_id=79,  stig_id="V-100002", check_id="APSC-DV-000002",
                        confidence="inferred", nist_control="SI-10"),
            StigMapping(cwe_id=79,  stig_id="V-100003", check_id="APSC-DV-000003",
                        confidence="direct",   nist_control="SI-10"),
            # V-100004 intentionally has no mapping
        ],
        version="1.0.0",
        stig_name="Test STIG",
        stig_version="V1",
    )


@pytest.fixture()
def classifications() -> dict[str, str]:
    return {
        "V-100001": "sast",
        "V-100002": "sast",
        "V-100003": "sast",
        "V-100004": "sast",
        "V-100005": "procedural",
    }


def _sarif(
    rule_id: str = "RULE-001",
    cwe_ids: list[int] | None = None,
    stig_ids: list[str] | None = None,
    file_path: str = "src/app.py",
    start_line: int = 42,
    scanner_name: str = "TestScanner",
    scanner_version: str = "1.0",
) -> NormalizedFinding:
    return NormalizedFinding(
        rule_id=rule_id,
        message="test finding",
        file_path=file_path,
        start_line=start_line,
        cwe_ids=cwe_ids or [],
        stig_ids=stig_ids or [],
        scanner_name=scanner_name,
        scanner_version=scanner_version,
    )


# ---------------------------------------------------------------------------
# Direct STIG match
# ---------------------------------------------------------------------------

def test_direct_stig_match_is_open(benchmark, mapping_db, classifications):
    sarif = [_sarif(stig_ids=["V-100003"])]
    report = determine_status(sarif, mapping_db, benchmark, classifications)

    det = next(d for d in report.determinations if d.stig_id == "V-100003")
    assert det.status == CklStatus.OPEN, f"Expected OPEN, got {det.status}"
    assert det.confidence == DeterminationConfidence.DIRECT


# ---------------------------------------------------------------------------
# CWE-inferred match
# ---------------------------------------------------------------------------

def test_cwe_inferred_match_is_open(benchmark, mapping_db, classifications):
    sarif = [_sarif(cwe_ids=[89], file_path="src/db.py", start_line=10)]
    report = determine_status(sarif, mapping_db, benchmark, classifications)

    det = next(d for d in report.determinations if d.stig_id == "V-100001")
    assert det.status == CklStatus.OPEN, f"Expected OPEN, got {det.status}"
    assert det.confidence == DeterminationConfidence.INFERRED


# ---------------------------------------------------------------------------
# No SARIF match, but CWE mappings exist → NotAFinding
# ---------------------------------------------------------------------------

def test_no_match_with_mappings_is_not_a_finding(benchmark, mapping_db, classifications):
    # Empty SARIF — no findings at all
    report = determine_status([], mapping_db, benchmark, classifications)

    det = next(d for d in report.determinations if d.stig_id == "V-100001")
    assert det.status == CklStatus.NOT_A_FINDING, (
        f"Expected NOT_A_FINDING for SAST finding with mappings, got {det.status}"
    )


# ---------------------------------------------------------------------------
# No SARIF match, no CWE mappings → Not_Reviewed
# ---------------------------------------------------------------------------

def test_no_match_no_mappings_is_not_reviewed(benchmark, mapping_db, classifications):
    report = determine_status([], mapping_db, benchmark, classifications)

    det = next(d for d in report.determinations if d.stig_id == "V-100004")
    assert det.status == CklStatus.NOT_REVIEWED, (
        f"Expected NOT_REVIEWED for SAST finding with no mappings, got {det.status}"
    )
    assert det.confidence == DeterminationConfidence.NONE


# ---------------------------------------------------------------------------
# Procedural finding → always Not_Reviewed
# ---------------------------------------------------------------------------

def test_procedural_finding_is_not_reviewed(benchmark, mapping_db, classifications):
    # Even with a SARIF finding that mentions V-100005, it stays Not_Reviewed
    sarif = [_sarif(stig_ids=["V-100005"])]
    report = determine_status(sarif, mapping_db, benchmark, classifications)

    det = next(d for d in report.determinations if d.stig_id == "V-100005")
    assert det.status == CklStatus.NOT_REVIEWED, (
        f"Expected NOT_REVIEWED for procedural finding, got {det.status}"
    )
    assert det.is_sast_assessable is False
    assert "procedural" in det.review_notes.lower()


# ---------------------------------------------------------------------------
# Evidence references
# ---------------------------------------------------------------------------

def test_evidence_includes_file_and_line(benchmark, mapping_db, classifications):
    sarif = [_sarif(stig_ids=["V-100003"], file_path="src/auth.py", start_line=99)]
    report = determine_status(sarif, mapping_db, benchmark, classifications)

    det = next(d for d in report.determinations if d.stig_id == "V-100003")
    assert any("src/auth.py:99" in ev for ev in det.evidence), (
        f"Expected 'src/auth.py:99' in evidence, got: {det.evidence}"
    )


# ---------------------------------------------------------------------------
# Review notes quality
# ---------------------------------------------------------------------------

def test_review_notes_explain_determination_for_inferred(
    benchmark, mapping_db, classifications
):
    sarif = [_sarif(cwe_ids=[89])]
    report = determine_status(sarif, mapping_db, benchmark, classifications)

    det = next(d for d in report.determinations if d.stig_id == "V-100001")
    assert "CWE-89" in det.review_notes, (
        f"Expected CWE chain in review notes, got: {det.review_notes!r}"
    )
    assert "inferred" in det.review_notes.lower()


# ---------------------------------------------------------------------------
# StatusReport aggregate properties
# ---------------------------------------------------------------------------

def test_open_count_property(benchmark, mapping_db, classifications):
    sarif = [_sarif(stig_ids=["V-100003"])]
    report = determine_status(sarif, mapping_db, benchmark, classifications)

    assert report.open_count >= 1


def test_not_reviewed_count_property(benchmark, mapping_db, classifications):
    report = determine_status([], mapping_db, benchmark, classifications)
    # V-100004 (no mapping) + V-100005 (procedural)
    assert report.not_reviewed_count >= 2


def test_not_a_finding_count_property(benchmark, mapping_db, classifications):
    report = determine_status([], mapping_db, benchmark, classifications)
    # V-100001, V-100002, V-100003 all have CWE mappings → NotAFinding when no SARIF
    assert report.not_a_finding_count >= 3


# ---------------------------------------------------------------------------
# Multiple SARIF findings mapping to the same STIG
# ---------------------------------------------------------------------------

def test_multiple_sarif_findings_same_stig(benchmark, mapping_db, classifications):
    sarif = [
        _sarif(stig_ids=["V-100003"], file_path="src/a.py", start_line=1),
        _sarif(stig_ids=["V-100003"], file_path="src/b.py", start_line=2),
    ]
    report = determine_status(sarif, mapping_db, benchmark, classifications)

    det = next(d for d in report.determinations if d.stig_id == "V-100003")
    assert det.status == CklStatus.OPEN
    # All locations should appear in evidence
    assert len(det.evidence) == 2, (
        f"Expected 2 evidence entries, got {len(det.evidence)}: {det.evidence}"
    )


# ---------------------------------------------------------------------------
# Empty SARIF findings
# ---------------------------------------------------------------------------

def test_empty_sarif_findings(benchmark, mapping_db, classifications):
    report = determine_status([], mapping_db, benchmark, classifications)

    stig_statuses = {d.stig_id: d.status for d in report.determinations}

    # SAST findings with mappings → NotAFinding
    assert stig_statuses["V-100001"] == CklStatus.NOT_A_FINDING
    assert stig_statuses["V-100002"] == CklStatus.NOT_A_FINDING
    assert stig_statuses["V-100003"] == CklStatus.NOT_A_FINDING
    # SAST finding without mapping → Not_Reviewed
    assert stig_statuses["V-100004"] == CklStatus.NOT_REVIEWED
    # Procedural → Not_Reviewed
    assert stig_statuses["V-100005"] == CklStatus.NOT_REVIEWED


# ---------------------------------------------------------------------------
# Scan summary
# ---------------------------------------------------------------------------

def test_scan_summary_populated(benchmark, mapping_db, classifications):
    sarif = [_sarif(scanner_name="MyScanner", scanner_version="2.0")]
    report = determine_status(sarif, mapping_db, benchmark, classifications)

    assert report.scan_summary["scanner_name"] == "MyScanner"
    assert report.scan_summary["scanner_version"] == "2.0"
    assert report.scan_summary["total_sarif_findings"] == 1
    assert report.scan_summary["total_stig_findings"] == len(benchmark.findings)


# ---------------------------------------------------------------------------
# YAML-dict classifications (assessment_method nested under a dict)
# ---------------------------------------------------------------------------

def test_yaml_dict_classifications(benchmark, mapping_db):
    """Classifications loaded from YAML produce nested dicts; ensure they work."""
    yaml_style = {
        "V-100001": {"assessment_method": "sast",       "title": "...", "rationale": "..."},
        "V-100002": {"assessment_method": "sast",       "title": "...", "rationale": "..."},
        "V-100003": {"assessment_method": "sast",       "title": "...", "rationale": "..."},
        "V-100004": {"assessment_method": "sast",       "title": "...", "rationale": "..."},
        "V-100005": {"assessment_method": "procedural", "title": "...", "rationale": "..."},
    }
    report = determine_status([], mapping_db, benchmark, yaml_style)
    stig_statuses = {d.stig_id: d.status for d in report.determinations}
    assert stig_statuses["V-100005"] == CklStatus.NOT_REVIEWED
    assert stig_statuses["V-100001"] == CklStatus.NOT_A_FINDING
