"""Tests for incremental CKL update (ckl_update module)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from stigcode.ingest.xccdf import StigBenchmark, StigFinding
from stigcode.mapping.status import (
    CklStatus,
    DeterminationConfidence,
    FindingDetermination,
    StatusReport,
)
from stigcode.output.ckl_update import (
    UpdateResult,
    parse_existing_ckl,
    update_ckl,
)

FIXTURE_CKL = Path(__file__).parent / "fixtures" / "ckl" / "existing_assessment.ckl"


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _finding(
    vuln_id: str,
    severity: str = "medium",
    cci_refs: list[str] | None = None,
) -> StigFinding:
    cat = {"high": 1, "medium": 2, "low": 3}[severity]
    return StigFinding(
        vuln_id=vuln_id,
        rule_id=f"SV-{vuln_id}r1_rule",
        check_id=f"APSC-DV-{vuln_id.replace('V-', '')}",
        title=f"Title for {vuln_id}",
        description=f"Discussion for {vuln_id}",
        severity=severity,
        category=cat,
        cci_refs=cci_refs if cci_refs is not None else ["CCI-000001"],
        fix_text=f"Fix {vuln_id}",
        check_content=f"Check {vuln_id}",
        group_title=f"SRG-APP-{vuln_id.replace('V-', '')}",
    )


def _det(
    stig_id: str,
    status: CklStatus,
    confidence: DeterminationConfidence = DeterminationConfidence.INFERRED,
    evidence: list[str] | None = None,
    review_notes: str = "",
) -> FindingDetermination:
    return FindingDetermination(
        stig_id=stig_id,
        status=status,
        confidence=confidence,
        evidence=evidence or [],
        review_notes=review_notes,
    )


@pytest.fixture()
def four_finding_benchmark() -> StigBenchmark:
    """Benchmark matching the four VULNs in existing_assessment.ckl."""
    return StigBenchmark(
        benchmark_id="ASD_STIG_V6R3",
        title="Application Security and Development STIG",
        version="6",
        release="3",
        date="01 Jan 2025",
        findings=[
            _finding("V-222606", "high"),
            _finding("V-222607", "medium"),
            _finding("V-222609", "medium"),
            _finding("V-222542", "low"),
        ],
        profiles={},
    )


@pytest.fixture()
def base_report() -> StatusReport:
    """A scan that keeps V-222606 Open, re-confirms V-222607 clean,
    stays silent on V-222609, and finds V-222542 Open."""
    return StatusReport(
        determinations=[
            _det("V-222606", CklStatus.OPEN, DeterminationConfidence.DIRECT,
                 evidence=["db.py:42"], review_notes="SQL injection at db.py:42"),
            _det("V-222607", CklStatus.NOT_A_FINDING, DeterminationConfidence.INFERRED,
                 review_notes="No findings for CWE-20. Scanner: TestScanner v2.0."),
            _det("V-222609", CklStatus.NOT_REVIEWED, DeterminationConfidence.NONE,
                 review_notes="No CWE mapping available for automated assessment"),
            _det("V-222542", CklStatus.OPEN, DeterminationConfidence.INFERRED,
                 evidence=["api.py:10"], review_notes="TLS misconfiguration at api.py:10"),
        ],
        scan_summary={
            "scanner_name": "TestScanner",
            "scanner_version": "2.0",
            "total_sarif_findings": 2,
            "total_stig_findings": 4,
        },
    )


def _get_vuln_field(root: ET.Element, vuln_num: str, field: str) -> str:
    for vuln in root.findall(".//VULN"):
        for sd in vuln.findall("STIG_DATA"):
            if sd.findtext("VULN_ATTRIBUTE") == "Vuln_Num" and sd.findtext("ATTRIBUTE_DATA") == vuln_num:
                return vuln.findtext(field) or ""
    return ""


# ---------------------------------------------------------------------------
# parse_existing_ckl
# ---------------------------------------------------------------------------

class TestParseExistingCkl:
    def test_extracts_all_four_findings(self):
        findings = parse_existing_ckl(FIXTURE_CKL)
        assert set(findings.keys()) == {"V-222606", "V-222607", "V-222609", "V-222542"}

    def test_extracts_correct_statuses(self):
        findings = parse_existing_ckl(FIXTURE_CKL)
        assert findings["V-222606"]["status"] == "Open"
        assert findings["V-222607"]["status"] == "NotAFinding"
        assert findings["V-222609"]["status"] == "Not_Applicable"
        assert findings["V-222542"]["status"] == "Not_Reviewed"

    def test_extracts_assessor_comments(self):
        findings = parse_existing_ckl(FIXTURE_CKL)
        assert findings["V-222606"]["comments"] == "Assessor: Verified, ticket JIRA-123"

    def test_extracts_stigcode_comments(self):
        findings = parse_existing_ckl(FIXTURE_CKL)
        assert findings["V-222607"]["comments"].startswith("Stigcode assessment")

    def test_extracts_not_applicable_comments(self):
        findings = parse_existing_ckl(FIXTURE_CKL)
        assert "does not accept file paths" in findings["V-222609"]["comments"]

    def test_empty_comments_for_not_reviewed(self):
        findings = parse_existing_ckl(FIXTURE_CKL)
        assert findings["V-222542"]["comments"] == ""

    def test_extracts_finding_details(self):
        findings = parse_existing_ckl(FIXTURE_CKL)
        assert "SQL injection" in findings["V-222606"]["finding_details"]


# ---------------------------------------------------------------------------
# update_ckl — preservation rules
# ---------------------------------------------------------------------------

class TestPreservesAssessorComments:
    def test_assessor_comments_survive_update(
        self, tmp_path, four_finding_benchmark, base_report
    ):
        out = tmp_path / "out.ckl"
        update_ckl(FIXTURE_CKL, base_report, four_finding_benchmark, out)

        root = ET.fromstring(out.read_text())
        comments = _get_vuln_field(root, "V-222606", "COMMENTS")

        # Original assessor text must be intact.
        assert "Assessor: Verified, ticket JIRA-123" in comments

    def test_assessor_finding_details_survive(
        self, tmp_path, four_finding_benchmark, base_report
    ):
        out = tmp_path / "out.ckl"
        update_ckl(FIXTURE_CKL, base_report, four_finding_benchmark, out)

        root = ET.fromstring(out.read_text())
        details = _get_vuln_field(root, "V-222606", "FINDING_DETAILS")
        assert "Manual review confirmed SQL injection at db.py:42" in details


class TestPreservesNotApplicable:
    def test_not_applicable_never_overridden(
        self, tmp_path, four_finding_benchmark
    ):
        # Report says V-222609 is Open — must still stay Not_Applicable.
        report = StatusReport(
            determinations=[
                _det("V-222606", CklStatus.OPEN),
                _det("V-222607", CklStatus.NOT_A_FINDING),
                _det("V-222609", CklStatus.OPEN,
                     review_notes="Scanner found path traversal"),
                _det("V-222542", CklStatus.NOT_REVIEWED),
            ],
            scan_summary={},
        )
        out = tmp_path / "out.ckl"
        update_ckl(FIXTURE_CKL, report, four_finding_benchmark, out)

        root = ET.fromstring(out.read_text())
        status = _get_vuln_field(root, "V-222609", "STATUS")
        assert status == "Not_Applicable", (
            f"Expected Not_Applicable to be preserved, got {status!r}"
        )

    def test_not_applicable_comments_preserved(
        self, tmp_path, four_finding_benchmark, base_report
    ):
        out = tmp_path / "out.ckl"
        update_ckl(FIXTURE_CKL, base_report, four_finding_benchmark, out)

        root = ET.fromstring(out.read_text())
        comments = _get_vuln_field(root, "V-222609", "COMMENTS")
        assert "does not accept file paths" in comments


class TestUpdatesStigcodeComments:
    def test_stigcode_comments_replaced(
        self, tmp_path, four_finding_benchmark, base_report
    ):
        out = tmp_path / "out.ckl"
        update_ckl(FIXTURE_CKL, base_report, four_finding_benchmark, out)

        root = ET.fromstring(out.read_text())
        comments = _get_vuln_field(root, "V-222607", "COMMENTS")

        # Old assessment text should be gone; new one present.
        assert "Stigcode assessment" in comments
        # The old "TestScanner v1.0" content should not remain verbatim.
        assert "v1.0" not in comments


# ---------------------------------------------------------------------------
# Status transitions
# ---------------------------------------------------------------------------

class TestUpdatesNotReviewedToStatus:
    def test_not_reviewed_becomes_open(
        self, tmp_path, four_finding_benchmark, base_report
    ):
        out = tmp_path / "out.ckl"
        update_ckl(FIXTURE_CKL, base_report, four_finding_benchmark, out)

        root = ET.fromstring(out.read_text())
        status = _get_vuln_field(root, "V-222542", "STATUS")
        assert status == "Open", (
            f"Expected V-222542 to become Open, got {status!r}"
        )

    def test_not_reviewed_gets_new_evidence(
        self, tmp_path, four_finding_benchmark, base_report
    ):
        out = tmp_path / "out.ckl"
        update_ckl(FIXTURE_CKL, base_report, four_finding_benchmark, out)

        root = ET.fromstring(out.read_text())
        details = _get_vuln_field(root, "V-222542", "FINDING_DETAILS")
        assert "api.py:10" in details


class TestConflictWhenNotAFindingBecomesOpen:
    def _report_with_v222607_open(self) -> StatusReport:
        return StatusReport(
            determinations=[
                _det("V-222606", CklStatus.OPEN),
                # V-222607 had assessor-confirmed NotAFinding; new scan says Open.
                _det("V-222607", CklStatus.OPEN,
                     evidence=["app.py:5"], review_notes="XSS found at app.py:5"),
                _det("V-222609", CklStatus.NOT_REVIEWED),
                _det("V-222542", CklStatus.NOT_REVIEWED),
            ],
            scan_summary={},
        )

    def test_conflict_reported(self, tmp_path, four_finding_benchmark):
        # First we need a CKL where V-222607 has assessor-entered NotAFinding.
        # The fixture has stigcode comments for V-222607, so we craft our own.
        assessor_ckl = tmp_path / "assessor.ckl"
        _write_minimal_ckl(assessor_ckl, {
            "V-222607": {
                "status": "NotAFinding",
                "comments": "Assessor: Manually verified, no XSS possible",
                "finding_details": "Reviewed source 2026-01-10",
            }
        })

        report = self._report_with_v222607_open()
        out = tmp_path / "out.ckl"
        result = update_ckl(assessor_ckl, report, four_finding_benchmark, out)

        assert len(result.conflicts) == 1, (
            f"Expected 1 conflict, got {result.conflicts}"
        )
        assert result.conflicts[0].stig_id == "V-222607"
        assert result.conflicts[0].existing_status == "NotAFinding"
        assert result.conflicts[0].new_status == "Open"

    def test_assessor_status_preserved_despite_conflict(
        self, tmp_path, four_finding_benchmark
    ):
        assessor_ckl = tmp_path / "assessor.ckl"
        _write_minimal_ckl(assessor_ckl, {
            "V-222607": {
                "status": "NotAFinding",
                "comments": "Assessor: Manually verified, no XSS possible",
                "finding_details": "",
            }
        })

        report = self._report_with_v222607_open()
        out = tmp_path / "out.ckl"
        update_ckl(assessor_ckl, report, four_finding_benchmark, out)

        root = ET.fromstring(out.read_text())
        status = _get_vuln_field(root, "V-222607", "STATUS")
        assert status == "NotAFinding", (
            "Assessor's NotAFinding should be preserved even when there's a conflict"
        )


# ---------------------------------------------------------------------------
# UpdateResult counts
# ---------------------------------------------------------------------------

class TestUpdateResultCounts:
    def test_counts_are_consistent(
        self, tmp_path, four_finding_benchmark, base_report
    ):
        out = tmp_path / "out.ckl"
        result = update_ckl(FIXTURE_CKL, base_report, four_finding_benchmark, out)

        assert result.total_findings == 4
        assert result.updated_count + result.preserved_count == result.total_findings - len(result.conflicts)

    def test_not_applicable_counted_as_preserved(
        self, tmp_path, four_finding_benchmark, base_report
    ):
        out = tmp_path / "out.ckl"
        result = update_ckl(FIXTURE_CKL, base_report, four_finding_benchmark, out)
        # V-222609 (Not_Applicable) must be in preserved_count.
        assert result.preserved_count >= 1


# ---------------------------------------------------------------------------
# Timestamp
# ---------------------------------------------------------------------------

class TestTimestampAdded:
    def test_timestamp_present_in_updated_comments(
        self, tmp_path, four_finding_benchmark, base_report
    ):
        out = tmp_path / "out.ckl"
        update_ckl(FIXTURE_CKL, base_report, four_finding_benchmark, out)

        root = ET.fromstring(out.read_text())
        # V-222542 was Not_Reviewed → Open; its comments should carry timestamp.
        comments = _get_vuln_field(root, "V-222542", "COMMENTS")
        assert "Updated by stigcode on" in comments


# ---------------------------------------------------------------------------
# Minimal CKL writer for constructing targeted test fixtures
# ---------------------------------------------------------------------------

def _write_minimal_ckl(path: Path, vulns: dict[str, dict]) -> None:
    """Write a minimal CKL containing only the specified VULNs.

    vulns is a dict mapping vuln_num → {status, comments, finding_details}.
    Missing findings from the benchmark will return empty dicts from
    parse_existing_ckl, which is fine — they'll be treated as new.
    """
    root = ET.Element("CHECKLIST")
    asset = ET.SubElement(root, "ASSET")
    for tag in ("ROLE", "ASSET_TYPE", "MARKING", "HOST_NAME", "HOST_IP",
                "HOST_MAC", "HOST_FQDN", "TARGET_COMMENT", "TECH_AREA",
                "TARGET_KEY", "WEB_OR_DATABASE", "WEB_DB_SITE", "WEB_DB_INSTANCE"):
        ET.SubElement(asset, tag)

    stigs = ET.SubElement(root, "STIGS")
    istig = ET.SubElement(stigs, "iSTIG")
    info = ET.SubElement(istig, "STIG_INFO")
    for name in ("version", "classification", "customname", "stigid", "description",
                 "filename", "releaseinfo", "title", "uuid", "notice", "source"):
        si = ET.SubElement(info, "SI_DATA")
        sid_name = ET.SubElement(si, "SID_NAME")
        sid_name.text = name
        ET.SubElement(si, "SID_DATA")

    for vuln_num, data in vulns.items():
        vuln = ET.SubElement(istig, "VULN")
        sd = ET.SubElement(vuln, "STIG_DATA")
        va = ET.SubElement(sd, "VULN_ATTRIBUTE")
        va.text = "Vuln_Num"
        ad = ET.SubElement(sd, "ATTRIBUTE_DATA")
        ad.text = vuln_num

        for field_tag in ("STATUS", "FINDING_DETAILS", "COMMENTS",
                          "SEVERITY_OVERRIDE", "SEVERITY_JUSTIFICATION"):
            el = ET.SubElement(vuln, field_tag)
            el.text = data.get(field_tag.lower().replace("_", "_"), "") or data.get(
                {"STATUS": "status", "FINDING_DETAILS": "finding_details",
                 "COMMENTS": "comments", "SEVERITY_OVERRIDE": "severity_override",
                 "SEVERITY_JUSTIFICATION": "severity_justification"}[field_tag], ""
            )

    tree = ET.ElementTree(root)
    ET.indent(tree, space="\t")
    path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode"),
        encoding="utf-8",
    )
