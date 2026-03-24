"""Tests for the POA&M candidate report generator (output.poam)."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from stigcode.ingest.sarif import parse_sarif
from stigcode.ingest.xccdf import StigBenchmark, StigFinding
from stigcode.mapping.engine import MappingDatabase, StigMapping
from stigcode.mapping.status import (
    CklStatus,
    DeterminationConfidence,
    FindingDetermination,
    StatusReport,
    determine_status,
)
from stigcode.output.poam import (
    PoamReport,
    build_poam,
    poam_to_csv,
    poam_to_markdown,
    write_poam,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

_AS_OF = datetime(2025, 3, 23)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SARIF_CWE_TAGS = FIXTURES_DIR / "sarif" / "cwe_in_tags.sarif"
XCCDF_FILE = Path(__file__).parent.parent / "data" / "stigs" / "application_security_and_development.xml"


def _stig_finding(
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
        description=f"Description for {vuln_id}",
        severity=severity,
        category=cat,
        cci_refs=cci_refs or [],
        fix_text=fix_text,
        check_content="",
    )


def _determination(
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
            _stig_finding("V-100001", severity="high", fix_text="Apply input validation."),
            _stig_finding("V-100002", severity="medium", fix_text="Encode all output."),
            _stig_finding("V-100003", severity="medium"),
            _stig_finding("V-100004", severity="low"),
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
def status_report() -> StatusReport:
    """Report with 1 open CAT I, 1 open CAT II, 1 not-a-finding, 1 not-reviewed."""
    return StatusReport(
        determinations=[
            _determination(
                "V-100001", CklStatus.OPEN, DeterminationConfidence.INFERRED,
                evidence=["src/app.py:42", "src/db.py:88"],
                mapped_cwe_ids=[89],
            ),
            _determination(
                "V-100002", CklStatus.OPEN, DeterminationConfidence.DIRECT,
                evidence=["src/views.py:10"],
            ),
            _determination("V-100003", CklStatus.NOT_A_FINDING),
            _determination("V-100004", CklStatus.NOT_REVIEWED, DeterminationConfidence.NONE),
        ],
        scan_summary={
            "scanner_name": "Semgrep",
            "scanner_version": "1.50",
            "total_sarif_findings": 3,
            "benchmark_id": "ASD_STIG_V6R3",
            "benchmark_title": "Application Security and Development STIG",
            "total_stig_findings": 4,
        },
    )


# ---------------------------------------------------------------------------
# build_poam — filtering and structure
# ---------------------------------------------------------------------------

def test_only_open_findings_included(status_report, benchmark, mapping_db):
    """NotAFinding and Not_Reviewed determinations must not produce POA&M entries."""
    poam = build_poam(status_report, benchmark, mapping_db, {}, as_of=_AS_OF)
    assert len(poam.entries) == 2
    for entry in poam.entries:
        assert entry.status == "Open"


def test_entry_numbering_is_sequential(status_report, benchmark, mapping_db):
    poam = build_poam(status_report, benchmark, mapping_db, {}, as_of=_AS_OF)
    numbers = [e.item_number for e in poam.entries]
    assert numbers == list(range(1, len(numbers) + 1))


def test_cat_i_before_cat_ii(status_report, benchmark, mapping_db):
    poam = build_poam(status_report, benchmark, mapping_db, {}, as_of=_AS_OF)
    severities = [e.severity for e in poam.entries]
    assert severities.index("CAT I") < severities.index("CAT II")


@pytest.mark.parametrize("severity,cat_str,expected_days", [
    ("high", "CAT I", 30),
    ("medium", "CAT II", 90),
    ("low", "CAT III", 180),
])
def test_scheduled_completion_by_severity(severity, cat_str, expected_days, mapping_db):
    report = StatusReport(
        determinations=[_determination("V-999001", CklStatus.OPEN)],
        scan_summary={},
    )
    bench = StigBenchmark(
        benchmark_id="X", title="X", version="1", release="1", date="",
        findings=[_stig_finding("V-999001", severity=severity)],
        profiles={},
    )
    poam = build_poam(report, bench, mapping_db, {}, as_of=_AS_OF)
    assert len(poam.entries) == 1
    expected = (_AS_OF + timedelta(days=expected_days)).strftime("%Y-%m-%d")
    assert poam.entries[0].scheduled_completion == expected, (
        f"Expected {expected} for {cat_str}, got {poam.entries[0].scheduled_completion}"
    )


def test_milestones_populated(status_report, benchmark, mapping_db):
    poam = build_poam(status_report, benchmark, mapping_db, {}, as_of=_AS_OF)
    for entry in poam.entries:
        assert len(entry.milestones) > 0, f"Entry {entry.item_number} has no milestones"


def test_security_controls_from_cci(benchmark, mapping_db):
    """CCI refs on the STIG finding should be resolved to NIST controls."""
    report = StatusReport(
        determinations=[_determination("V-100001", CklStatus.OPEN)],
        scan_summary={},
    )
    cci_mappings = {"CCI-000054": "AC-2", "CCI-000055": "AC-3"}
    bench = StigBenchmark(
        benchmark_id="X", title="X", version="1", release="1", date="",
        findings=[_stig_finding("V-100001", severity="high", cci_refs=["CCI-000054"])],
        profiles={},
    )
    poam = build_poam(report, bench, mapping_db, cci_mappings, as_of=_AS_OF)
    assert poam.entries[0].security_controls == ["AC-2"], (
        f"Expected ['AC-2'] from CCI, got {poam.entries[0].security_controls}"
    )


def test_security_controls_fallback_to_mapping_db(status_report, benchmark, mapping_db):
    """When no CCI refs map, controls come from the mapping DB."""
    poam = build_poam(status_report, benchmark, mapping_db, {}, as_of=_AS_OF)
    cat1 = next(e for e in poam.entries if e.severity == "CAT I")
    assert "SI-10" in cat1.security_controls, (
        f"Expected SI-10 from mapping_db, got {cat1.security_controls}"
    )


def test_affected_components_from_evidence(status_report, benchmark, mapping_db):
    poam = build_poam(status_report, benchmark, mapping_db, {}, as_of=_AS_OF)
    cat1 = next(e for e in poam.entries if e.stig_id == "V-100001")
    assert "src/app.py:42" in cat1.affected_components
    assert "src/db.py:88" in cat1.affected_components


def test_zero_open_findings_produces_empty_valid_report(benchmark, mapping_db):
    report = StatusReport(
        determinations=[
            _determination("V-100001", CklStatus.NOT_A_FINDING),
            _determination("V-100002", CklStatus.NOT_REVIEWED),
        ],
        scan_summary={"scanner_name": "TestScanner", "scanner_version": "0.1"},
    )
    poam = build_poam(report, benchmark, mapping_db, {}, as_of=_AS_OF)
    assert poam.entries == []
    assert isinstance(poam, PoamReport)


def test_scanner_metadata_propagated(status_report, benchmark, mapping_db):
    poam = build_poam(
        status_report, benchmark, mapping_db, {},
        scanner_name="MyScanner", scanner_version="2.0",
        as_of=_AS_OF,
    )
    assert poam.scanner_name == "MyScanner"
    assert poam.scanner_version == "2.0"
    for entry in poam.entries:
        assert "MyScanner" in entry.source
        assert "2.0" in entry.source


def test_scanner_metadata_from_scan_summary(benchmark, mapping_db):
    """scanner_name/version fall back to scan_summary when not explicitly passed."""
    report = StatusReport(
        determinations=[_determination("V-100001", CklStatus.OPEN)],
        scan_summary={"scanner_name": "CodeQL", "scanner_version": "3.5"},
    )
    poam = build_poam(report, benchmark, mapping_db, {}, as_of=_AS_OF)
    assert poam.scanner_name == "CodeQL"


# ---------------------------------------------------------------------------
# poam_to_markdown
# ---------------------------------------------------------------------------

def test_markdown_contains_header(status_report, benchmark, mapping_db):
    poam = build_poam(status_report, benchmark, mapping_db, {}, as_of=_AS_OF)
    md = poam_to_markdown(poam)
    assert "# POA&M Candidates" in md


def test_markdown_contains_summary_table(status_report, benchmark, mapping_db):
    poam = build_poam(status_report, benchmark, mapping_db, {}, as_of=_AS_OF)
    md = poam_to_markdown(poam)
    assert "## Summary" in md
    assert "CAT I" in md
    assert "CAT II" in md
    assert "CAT III" in md


def test_markdown_contains_entries_section(status_report, benchmark, mapping_db):
    poam = build_poam(status_report, benchmark, mapping_db, {}, as_of=_AS_OF)
    md = poam_to_markdown(poam)
    assert "## POA&M Entries" in md


def test_markdown_isso_review_note(status_report, benchmark, mapping_db):
    poam = build_poam(status_report, benchmark, mapping_db, {}, as_of=_AS_OF)
    md = poam_to_markdown(poam)
    assert "ISSO" in md
    assert "candidate" in md.lower()


def test_markdown_empty_report():
    poam = PoamReport(
        entries=[],
        generated_date=_AS_OF,
        scanner_name="Scanner",
        scanner_version="1.0",
    )
    md = poam_to_markdown(poam)
    assert "# POA&M Candidates" in md
    assert "No open findings" in md


# ---------------------------------------------------------------------------
# poam_to_csv
# ---------------------------------------------------------------------------

def test_csv_has_correct_columns(status_report, benchmark, mapping_db):
    poam = build_poam(status_report, benchmark, mapping_db, {}, as_of=_AS_OF)
    csv_text = poam_to_csv(poam)
    reader = csv.DictReader(io.StringIO(csv_text))
    expected = {
        "Item", "Weakness", "Description", "Controls", "STIG_ID",
        "Severity", "Affected_Components", "POC", "Resources",
        "Scheduled_Completion", "Milestones", "Status", "Source", "Comments",
    }
    assert set(reader.fieldnames or []) == expected, (
        f"CSV columns mismatch: {set(reader.fieldnames or [])}"
    )


def test_csv_row_count_matches_entries(status_report, benchmark, mapping_db):
    poam = build_poam(status_report, benchmark, mapping_db, {}, as_of=_AS_OF)
    csv_text = poam_to_csv(poam)
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(rows) == len(poam.entries)


def test_csv_empty_report_has_only_header():
    poam = PoamReport(
        entries=[], generated_date=_AS_OF, scanner_name="S", scanner_version="1",
    )
    csv_text = poam_to_csv(poam)
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert rows == []


# ---------------------------------------------------------------------------
# write_poam
# ---------------------------------------------------------------------------

def test_write_poam_md(tmp_path, status_report, benchmark, mapping_db):
    poam = build_poam(status_report, benchmark, mapping_db, {}, as_of=_AS_OF)
    out = tmp_path / "poam.md"
    write_poam(poam, out, fmt="md")
    assert out.exists()
    assert "# POA&M Candidates" in out.read_text(encoding="utf-8")


def test_write_poam_csv(tmp_path, status_report, benchmark, mapping_db):
    poam = build_poam(status_report, benchmark, mapping_db, {}, as_of=_AS_OF)
    out = tmp_path / "poam.csv"
    write_poam(poam, out, fmt="csv")
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "Item" in content


def test_write_poam_bad_format(tmp_path, status_report, benchmark, mapping_db):
    poam = build_poam(status_report, benchmark, mapping_db, {}, as_of=_AS_OF)
    with pytest.raises(ValueError, match="Unsupported format"):
        write_poam(poam, tmp_path / "out.txt", fmt="pdf")


# ---------------------------------------------------------------------------
# Integration: real SARIF → pipeline → POA&M
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not SARIF_CWE_TAGS.exists() or not XCCDF_FILE.exists(),
    reason="Integration fixture files not present",
)
def test_integration_sarif_to_poam(mapping_db):
    """Full pipeline: parse SARIF, determine status, generate POA&M."""
    from stigcode.ingest.xccdf import parse_xccdf

    sarif_result = parse_sarif(SARIF_CWE_TAGS)
    assert sarif_result.errors == [], f"SARIF parse errors: {sarif_result.errors}"

    benchmark = parse_xccdf(XCCDF_FILE)
    classifications = {f.vuln_id: "sast" for f in benchmark.findings}

    report = determine_status(
        sarif_findings=sarif_result.findings,
        mapping_db=mapping_db,
        benchmark=benchmark,
        classifications=classifications,
    )

    poam = build_poam(report, benchmark, mapping_db, {}, as_of=_AS_OF)

    # The integration test validates structural correctness, not a specific count
    assert isinstance(poam, PoamReport)
    assert poam.entries == [e for e in poam.entries if e.status == "Open"]

    md = poam_to_markdown(poam)
    assert "# POA&M Candidates" in md

    csv_text = poam_to_csv(poam)
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(rows) == len(poam.entries)
