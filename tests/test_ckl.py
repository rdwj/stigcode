"""Tests for the CKL (STIG Viewer Checklist) XML generator."""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from stigcode.ingest.xccdf import StigBenchmark, StigFinding
from stigcode.mapping.status import (
    CklStatus,
    DeterminationConfidence,
    FindingDetermination,
    StatusReport,
)
from stigcode.output.ckl import AssetInfo, generate_ckl

# ---------------------------------------------------------------------------
# Expected attribute order (must match ckl.py _VULN_ATTRIBUTES exactly)
# ---------------------------------------------------------------------------

EXPECTED_ATTR_ORDER = [
    "Vuln_Num", "Severity", "Group_Title", "Rule_ID", "Rule_Ver",
    "Rule_Title", "Vuln_Discuss", "IA_Controls", "Check_Content",
    "Fix_Text", "False_Positives", "False_Negatives", "Documentable",
    "Mitigations", "Potential_Impact", "Third_Party_Tools",
    "Mitigation_Control", "Responsibility", "Security_Override_Guidance",
    "Check_Content_Ref", "Weight", "Class", "STIGRef", "TargetKey",
    "STIG_UUID",
]


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _finding(
    vuln_id: str,
    severity: str = "medium",
    cci_refs: list[str] | None = None,
    group_title: str = "",
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
        group_title=group_title or f"SRG-APP-{vuln_id.replace('V-', '')}",
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
def five_finding_benchmark() -> StigBenchmark:
    """Benchmark with 5 findings covering all 4 statuses."""
    return StigBenchmark(
        benchmark_id="ASD_V6R3",
        title="Application Security and Development STIG",
        version="6",
        release="3",
        date="01 Jan 2025",
        findings=[
            _finding("V-100001", "high", ["CCI-001234", "CCI-005678"]),
            _finding("V-100002", "medium"),
            _finding("V-100003", "low"),
            _finding("V-100004", "medium"),
            _finding("V-100005", "high"),
        ],
        profiles={},
    )


@pytest.fixture()
def five_finding_report() -> StatusReport:
    """StatusReport covering all 4 CKL statuses."""
    return StatusReport(
        determinations=[
            _det("V-100001", CklStatus.OPEN, DeterminationConfidence.DIRECT,
                 evidence=["src/app.py:42", "src/db.py:10"],
                 review_notes="SQL injection found"),
            _det("V-100002", CklStatus.NOT_A_FINDING, DeterminationConfidence.INFERRED,
                 review_notes="No findings for CWE-79"),
            _det("V-100003", CklStatus.NOT_REVIEWED, DeterminationConfidence.NONE,
                 review_notes="No CWE mapping available"),
            _det("V-100004", CklStatus.NOT_APPLICABLE, DeterminationConfidence.DIRECT,
                 review_notes="Not applicable to this system"),
            _det("V-100005", CklStatus.OPEN, DeterminationConfidence.INFERRED,
                 evidence=["src/auth.py:5"],
                 review_notes="Authentication bypass via CWE-287"),
        ],
        scan_summary={
            "scanner_name": "TestScanner",
            "scanner_version": "1.0",
            "total_sarif_findings": 3,
            "total_stig_findings": 5,
        },
    )


def _parse_ckl(benchmark, report, asset=None, classification="UNCLASSIFIED"):
    """Generate and parse CKL XML, returning the root Element."""
    xml_str = generate_ckl(report, benchmark, asset, classification)
    return ET.fromstring(xml_str)


# ---------------------------------------------------------------------------
# Basic XML validity
# ---------------------------------------------------------------------------

class TestXmlValidity:
    def test_output_is_valid_xml(self, five_finding_benchmark, five_finding_report):
        xml_str = generate_ckl(five_finding_report, five_finding_benchmark)
        root = ET.fromstring(xml_str)
        assert root.tag == "CHECKLIST"

    def test_has_xml_declaration(self, five_finding_benchmark, five_finding_report):
        xml_str = generate_ckl(five_finding_report, five_finding_benchmark)
        assert xml_str.startswith('<?xml version="1.0" encoding="UTF-8"?>')


# ---------------------------------------------------------------------------
# ASSET block
# ---------------------------------------------------------------------------

class TestAssetBlock:
    def test_all_asset_children_present(self, five_finding_benchmark, five_finding_report):
        root = _parse_ckl(five_finding_benchmark, five_finding_report)
        asset = root.find("ASSET")
        assert asset is not None

        expected_children = [
            "ROLE", "ASSET_TYPE", "MARKING", "HOST_NAME", "HOST_IP",
            "HOST_MAC", "HOST_FQDN", "TARGET_COMMENT", "TECH_AREA",
            "TARGET_KEY", "WEB_OR_DATABASE", "WEB_DB_SITE", "WEB_DB_INSTANCE",
        ]
        actual_children = [child.tag for child in asset]
        assert actual_children == expected_children

    def test_default_asset_values(self, five_finding_benchmark, five_finding_report):
        root = _parse_ckl(five_finding_benchmark, five_finding_report)
        asset = root.find("ASSET")
        assert asset.findtext("ROLE") == "None"
        assert asset.findtext("ASSET_TYPE") == "Computing"
        assert asset.findtext("MARKING") == "CUI"
        assert asset.findtext("WEB_OR_DATABASE") == "false"

    def test_custom_asset_info(self, five_finding_benchmark, five_finding_report):
        custom = AssetInfo(
            host_name="webserver01",
            host_ip="10.0.1.50",
            host_fqdn="webserver01.example.mil",
            marking="SECRET",
        )
        root = _parse_ckl(five_finding_benchmark, five_finding_report, asset=custom)
        asset = root.find("ASSET")
        assert asset.findtext("HOST_NAME") == "webserver01"
        assert asset.findtext("HOST_IP") == "10.0.1.50"
        assert asset.findtext("HOST_FQDN") == "webserver01.example.mil"
        assert asset.findtext("MARKING") == "SECRET"


# ---------------------------------------------------------------------------
# STIG_INFO block
# ---------------------------------------------------------------------------

class TestStigInfo:
    def test_stig_info_fields(self, five_finding_benchmark, five_finding_report):
        root = _parse_ckl(five_finding_benchmark, five_finding_report)
        info = root.find(".//STIG_INFO")
        assert info is not None

        si_data = {}
        for si in info.findall("SI_DATA"):
            name = si.findtext("SID_NAME")
            data = si.findtext("SID_DATA") or ""
            si_data[name] = data

        assert si_data["version"] == "6"
        assert si_data["title"] == "Application Security and Development STIG"
        assert si_data["classification"] == "UNCLASSIFIED"
        assert si_data["source"] == "STIG.DOD.MIL"
        assert si_data["stigid"] == "ASD_V6R3"
        assert si_data["releaseinfo"] == "Release: 3"

    def test_classification_parameter(self, five_finding_benchmark, five_finding_report):
        root = _parse_ckl(
            five_finding_benchmark, five_finding_report,
            classification="SECRET",
        )
        info = root.find(".//STIG_INFO")
        si_data = {
            si.findtext("SID_NAME"): si.findtext("SID_DATA") or ""
            for si in info.findall("SI_DATA")
        }
        assert si_data["classification"] == "SECRET"


# ---------------------------------------------------------------------------
# VULN elements
# ---------------------------------------------------------------------------

class TestVulnElements:
    def test_vuln_count_matches_benchmark(self, five_finding_benchmark, five_finding_report):
        root = _parse_ckl(five_finding_benchmark, five_finding_report)
        vulns = root.findall(".//VULN")
        assert len(vulns) == 5

    def test_stig_data_attribute_order(self, five_finding_benchmark, five_finding_report):
        root = _parse_ckl(five_finding_benchmark, five_finding_report)
        vuln = root.findall(".//VULN")[0]

        stig_data = vuln.findall("STIG_DATA")
        attr_names = [
            sd.findtext("VULN_ATTRIBUTE") for sd in stig_data
        ]

        # First 25 must be the fixed attributes; after that come CCI_REFs
        fixed_attrs = attr_names[:25]
        assert fixed_attrs == EXPECTED_ATTR_ORDER, (
            f"STIG_DATA order mismatch.\nExpected: {EXPECTED_ATTR_ORDER}\nGot: {fixed_attrs}"
        )

    def test_all_26_plus_cci_stig_data_present(self, five_finding_benchmark, five_finding_report):
        """Each VULN has 25 fixed attributes + at least 1 CCI_REF = 26+ STIG_DATA."""
        root = _parse_ckl(five_finding_benchmark, five_finding_report)
        for vuln in root.findall(".//VULN"):
            stig_data = vuln.findall("STIG_DATA")
            assert len(stig_data) >= 26, (
                f"Expected at least 26 STIG_DATA, got {len(stig_data)}"
            )

    def test_cci_ref_entries_match_finding(self, five_finding_benchmark, five_finding_report):
        """V-100001 has 2 CCI refs; verify both appear."""
        root = _parse_ckl(five_finding_benchmark, five_finding_report)
        vuln = root.findall(".//VULN")[0]  # V-100001

        cci_refs = [
            sd.findtext("ATTRIBUTE_DATA")
            for sd in vuln.findall("STIG_DATA")
            if sd.findtext("VULN_ATTRIBUTE") == "CCI_REF"
        ]
        assert cci_refs == ["CCI-001234", "CCI-005678"]

    def test_stig_ref_format(self, five_finding_benchmark, five_finding_report):
        root = _parse_ckl(five_finding_benchmark, five_finding_report)
        vuln = root.findall(".//VULN")[0]
        stig_ref = _get_vuln_attr(vuln, "STIGRef")
        assert stig_ref == "Application Security and Development STIG :: Version 6, Release: 3"


# ---------------------------------------------------------------------------
# STATUS mapping
# ---------------------------------------------------------------------------

class TestStatusMapping:
    def test_open_status(self, five_finding_benchmark, five_finding_report):
        root = _parse_ckl(five_finding_benchmark, five_finding_report)
        vuln = _find_vuln_by_id(root, "V-100001")
        assert vuln.findtext("STATUS") == "Open"

    def test_not_a_finding_status(self, five_finding_benchmark, five_finding_report):
        root = _parse_ckl(five_finding_benchmark, five_finding_report)
        vuln = _find_vuln_by_id(root, "V-100002")
        assert vuln.findtext("STATUS") == "NotAFinding"

    def test_not_reviewed_status(self, five_finding_benchmark, five_finding_report):
        root = _parse_ckl(five_finding_benchmark, five_finding_report)
        vuln = _find_vuln_by_id(root, "V-100003")
        assert vuln.findtext("STATUS") == "Not_Reviewed"

    def test_not_applicable_status(self, five_finding_benchmark, five_finding_report):
        root = _parse_ckl(five_finding_benchmark, five_finding_report)
        vuln = _find_vuln_by_id(root, "V-100004")
        assert vuln.findtext("STATUS") == "Not_Applicable"


# ---------------------------------------------------------------------------
# FINDING_DETAILS and COMMENTS
# ---------------------------------------------------------------------------

class TestFindingDetails:
    def test_open_finding_has_nonempty_details(self, five_finding_benchmark, five_finding_report):
        root = _parse_ckl(five_finding_benchmark, five_finding_report)
        vuln = _find_vuln_by_id(root, "V-100001")
        details = vuln.findtext("FINDING_DETAILS") or ""
        assert len(details) > 0
        assert "src/app.py:42" in details

    def test_comments_contain_confidence(self, five_finding_benchmark, five_finding_report):
        root = _parse_ckl(five_finding_benchmark, five_finding_report)
        vuln = _find_vuln_by_id(root, "V-100001")
        comments = vuln.findtext("COMMENTS") or ""
        assert "Stigcode assessment" in comments
        assert "Confidence: direct" in comments

    def test_inferred_confidence_in_comments(self, five_finding_benchmark, five_finding_report):
        root = _parse_ckl(five_finding_benchmark, five_finding_report)
        vuln = _find_vuln_by_id(root, "V-100002")
        comments = vuln.findtext("COMMENTS") or ""
        assert "Confidence: inferred" in comments


# ---------------------------------------------------------------------------
# SEVERITY_OVERRIDE is always empty
# ---------------------------------------------------------------------------

class TestSeverityOverride:
    def test_severity_override_empty(self, five_finding_benchmark, five_finding_report):
        root = _parse_ckl(five_finding_benchmark, five_finding_report)
        for vuln in root.findall(".//VULN"):
            override = vuln.findtext("SEVERITY_OVERRIDE")
            justification = vuln.findtext("SEVERITY_JUSTIFICATION")
            # These should be present but empty (None text = empty element)
            assert override is None or override == ""
            assert justification is None or justification == ""


# ---------------------------------------------------------------------------
# Fixture structure comparison
# ---------------------------------------------------------------------------

class TestFixtureStructure:
    def test_generated_ckl_matches_reference_structure(
        self, five_finding_benchmark, five_finding_report
    ):
        """Verify generated CKL has the same element nesting as reference CKL."""
        root = _parse_ckl(five_finding_benchmark, five_finding_report)

        # Top-level structure
        assert root.tag == "CHECKLIST"
        assert root.find("ASSET") is not None
        stigs = root.find("STIGS")
        assert stigs is not None
        istig = stigs.find("iSTIG")
        assert istig is not None
        assert istig.find("STIG_INFO") is not None

        # VULN structure
        vuln = istig.findall("VULN")[0]
        expected_direct_children = {"STIG_DATA", "STATUS", "FINDING_DETAILS",
                                    "COMMENTS", "SEVERITY_OVERRIDE",
                                    "SEVERITY_JUSTIFICATION"}
        actual_children = {child.tag for child in vuln}
        assert actual_children == expected_direct_children


# ---------------------------------------------------------------------------
# Edge case: empty benchmark
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_benchmark(self):
        benchmark = StigBenchmark(
            benchmark_id="EMPTY", title="Empty", version="1",
            release="0", date="", findings=[], profiles={},
        )
        report = StatusReport(determinations=[], scan_summary={})
        xml_str = generate_ckl(report, benchmark)
        root = ET.fromstring(xml_str)
        vulns = root.findall(".//VULN")
        assert len(vulns) == 0

    def test_finding_without_determination(self):
        """If a benchmark finding has no matching determination, it should be Not_Reviewed."""
        benchmark = StigBenchmark(
            benchmark_id="TEST", title="Test", version="1",
            release="0", date="", findings=[_finding("V-999999")], profiles={},
        )
        report = StatusReport(determinations=[], scan_summary={})
        root = ET.fromstring(generate_ckl(report, benchmark))
        vuln = root.findall(".//VULN")[0]
        assert vuln.findtext("STATUS") == "Not_Reviewed"

    def test_finding_with_no_cci_refs(self):
        """A finding with empty CCI refs should have only the 25 fixed STIG_DATA."""
        f = _finding("V-888888", cci_refs=[])
        benchmark = StigBenchmark(
            benchmark_id="TEST", title="Test", version="1",
            release="0", date="", findings=[f], profiles={},
        )
        det = _det("V-888888", CklStatus.NOT_REVIEWED)
        report = StatusReport(determinations=[det], scan_summary={})
        root = ET.fromstring(generate_ckl(report, benchmark))
        vuln = root.findall(".//VULN")[0]
        stig_data = vuln.findall("STIG_DATA")
        assert len(stig_data) == 25  # no CCI_REF entries

    def test_multi_cci_finding(self):
        """Multiple CCI refs produce multiple CCI_REF STIG_DATA entries."""
        f = _finding("V-777777", cci_refs=["CCI-000001", "CCI-000002", "CCI-000003"])
        benchmark = StigBenchmark(
            benchmark_id="TEST", title="Test", version="1",
            release="0", date="", findings=[f], profiles={},
        )
        det = _det("V-777777", CklStatus.OPEN, evidence=["file.py:1"])
        report = StatusReport(determinations=[det], scan_summary={})
        root = ET.fromstring(generate_ckl(report, benchmark))
        vuln = root.findall(".//VULN")[0]
        cci_refs = [
            sd.findtext("ATTRIBUTE_DATA")
            for sd in vuln.findall("STIG_DATA")
            if sd.findtext("VULN_ATTRIBUTE") == "CCI_REF"
        ]
        assert cci_refs == ["CCI-000001", "CCI-000002", "CCI-000003"]


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def _find_vuln_by_id(root: ET.Element, vuln_id: str) -> ET.Element:
    """Find a VULN element by its Vuln_Num value."""
    for vuln in root.findall(".//VULN"):
        if _get_vuln_attr(vuln, "Vuln_Num") == vuln_id:
            return vuln
    raise AssertionError(f"VULN with Vuln_Num={vuln_id} not found")


def _get_vuln_attr(vuln: ET.Element, attr_name: str) -> str:
    """Get the ATTRIBUTE_DATA value for a given VULN_ATTRIBUTE name."""
    for sd in vuln.findall("STIG_DATA"):
        if sd.findtext("VULN_ATTRIBUTE") == attr_name:
            return sd.findtext("ATTRIBUTE_DATA") or ""
    return ""
