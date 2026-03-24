"""Tests for the OSCAL Assessment Results generator (output.oscal)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
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
from stigcode.output.oscal import (
    OSCAL_VERSION,
    generate_oscal_ar,
    oscal_to_json,
    write_oscal,
)
from stigcode.version import __version__

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

SCAN_DATE = datetime(2025, 3, 23, 12, 0, 0, tzinfo=timezone.utc)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SARIF_CWE_TAGS = FIXTURES_DIR / "sarif" / "cwe_in_tags.sarif"
XCCDF_FILE = (
    Path(__file__).parent.parent / "data" / "stigs"
    / "application_security_and_development.xml"
)


def _stig_finding(
    vuln_id: str,
    severity: str = "medium",
    cci_refs: list[str] | None = None,
) -> StigFinding:
    cat = {"high": 1, "medium": 2, "low": 3}[severity]
    return StigFinding(
        vuln_id=vuln_id,
        rule_id=f"SV-{vuln_id}_rule",
        check_id=f"APSC-DV-{vuln_id}",
        title=f"Title for {vuln_id}",
        description=f"Description for {vuln_id}",
        severity=severity,
        category=cat,
        cci_refs=cci_refs or [],
        fix_text="",
        check_content="",
    )


def _determination(
    stig_id: str,
    status: CklStatus,
    confidence: DeterminationConfidence = DeterminationConfidence.INFERRED,
    evidence: list[str] | None = None,
    mapped_cwe_ids: list[int] | None = None,
    is_sast_assessable: bool = True,
) -> FindingDetermination:
    return FindingDetermination(
        stig_id=stig_id,
        status=status,
        confidence=confidence,
        evidence=evidence or [],
        mapped_cwe_ids=mapped_cwe_ids or [],
        is_sast_assessable=is_sast_assessable,
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
            _stig_finding("V-100001", severity="high", cci_refs=["CCI-001310"]),
            _stig_finding("V-100002", severity="medium"),
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
def cci_mappings() -> dict[str, str]:
    return {"CCI-001310": "SI-10"}


@pytest.fixture()
def status_report() -> StatusReport:
    """1 open CAT I, 1 open CAT II, 1 not-a-finding, 1 not-reviewed."""
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
                mapped_cwe_ids=[79],
            ),
            _determination("V-100003", CklStatus.NOT_A_FINDING),
            _determination(
                "V-100004", CklStatus.NOT_REVIEWED,
                DeterminationConfidence.NONE,
                is_sast_assessable=False,
            ),
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


@pytest.fixture()
def oscal_ar(status_report, benchmark, mapping_db, cci_mappings) -> dict:
    return generate_oscal_ar(
        status_report, benchmark, mapping_db, cci_mappings,
        scan_date=SCAN_DATE,
    )


# ---------------------------------------------------------------------------
# Structure and metadata
# ---------------------------------------------------------------------------

def test_oscal_ar_has_required_structure(oscal_ar):
    """Top-level keys: assessment-results with uuid, metadata, import-ap, results."""
    ar = oscal_ar["assessment-results"]
    assert "uuid" in ar
    assert "metadata" in ar
    assert "import-ap" in ar
    assert "results" in ar
    assert len(ar["results"]) >= 1


def test_metadata_has_oscal_version(oscal_ar):
    meta = oscal_ar["assessment-results"]["metadata"]
    assert meta["oscal-version"] == OSCAL_VERSION


def test_metadata_has_stigcode_version(oscal_ar):
    meta = oscal_ar["assessment-results"]["metadata"]
    assert meta["version"] == __version__
    # Also check tool prop
    tool_props = [p for p in meta.get("props", []) if p["name"] == "tool"]
    assert len(tool_props) == 1
    assert __version__ in tool_props[0]["value"]


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------

def test_observations_match_open_findings(oscal_ar, status_report):
    """One observation per Open finding."""
    result = oscal_ar["assessment-results"]["results"][0]
    observations = result.get("observations", [])
    open_count = sum(
        1 for d in status_report.determinations if d.status == CklStatus.OPEN
    )
    assert len(observations) == open_count, (
        f"Expected {open_count} observations for open findings, got {len(observations)}"
    )


# ---------------------------------------------------------------------------
# Findings — grouped by control
# ---------------------------------------------------------------------------

def test_findings_grouped_by_control(oscal_ar, status_report, mapping_db):
    """Findings are per-control, not per-STIG-finding.

    V-100001 and V-100002 both map to SI-10, so they should produce
    a single finding entry for si-10, not two.
    """
    result = oscal_ar["assessment-results"]["results"][0]
    findings = result.get("findings", [])
    target_ids = [f["target"]["target-id"] for f in findings]
    # si-10 should appear exactly once despite two STIGs mapping to it
    assert target_ids.count("si-10_smt") == 1


def test_satisfied_control(benchmark, mapping_db, cci_mappings):
    """Control with all NotAFinding determinations gets state 'satisfied'."""
    report = StatusReport(
        determinations=[
            _determination("V-100003", CklStatus.NOT_A_FINDING),
        ],
        scan_summary={},
    )
    # Only include the finding that maps to AC-3
    bench = StigBenchmark(
        benchmark_id="X", title="X", version="1", release="1", date="",
        findings=[_stig_finding("V-100003")],
        profiles={},
    )
    ar = generate_oscal_ar(report, bench, mapping_db, cci_mappings, scan_date=SCAN_DATE)
    result = ar["assessment-results"]["results"][0]
    findings = result.get("findings", [])
    ac3 = [f for f in findings if f["target"]["target-id"] == "ac-3_smt"]
    assert len(ac3) == 1, f"Expected ac-3 finding, got targets: {[f['target']['target-id'] for f in findings]}"
    assert ac3[0]["target"]["status"]["state"] == "satisfied"


def test_not_satisfied_control(oscal_ar):
    """Control with Open findings gets state 'not-satisfied'."""
    result = oscal_ar["assessment-results"]["results"][0]
    findings = result.get("findings", [])
    si10 = [f for f in findings if f["target"]["target-id"] == "si-10_smt"]
    assert len(si10) == 1
    assert si10[0]["target"]["status"]["state"] == "not-satisfied"


def test_not_reviewed_control(mapping_db, cci_mappings):
    """Procedural control (Not_Reviewed, no SAST coverage) gets state 'other'."""
    report = StatusReport(
        determinations=[
            _determination(
                "V-100004", CklStatus.NOT_REVIEWED,
                DeterminationConfidence.NONE, is_sast_assessable=False,
            ),
        ],
        scan_summary={},
    )
    db = MappingDatabase(
        mappings=[
            StigMapping(
                cwe_id=0, stig_id="V-100004", check_id="APSC-DV-000004",
                confidence="partial", nist_control="CM-6",
            ),
        ],
        version="1.0.0", stig_name="T", stig_version="V1",
    )
    bench = StigBenchmark(
        benchmark_id="X", title="X", version="1", release="1", date="",
        findings=[_stig_finding("V-100004", severity="low")],
        profiles={},
    )
    ar = generate_oscal_ar(report, bench, db, cci_mappings, scan_date=SCAN_DATE)
    result = ar["assessment-results"]["results"][0]
    findings = result.get("findings", [])
    cm6 = [f for f in findings if f["target"]["target-id"] == "cm-6_smt"]
    assert len(cm6) == 1, f"Expected cm-6, got: {[f['target']['target-id'] for f in findings]}"
    assert cm6[0]["target"]["status"]["state"] == "other"
    assert "remarks" in cm6[0]["target"]["status"]


# ---------------------------------------------------------------------------
# reviewed-controls
# ---------------------------------------------------------------------------

def test_reviewed_controls_list(oscal_ar):
    """control-selections contains all assessed controls."""
    result = oscal_ar["assessment-results"]["results"][0]
    selections = result["reviewed-controls"]["control-selections"]
    assert len(selections) == 1
    ids = {c["control-id"] for c in selections[0]["include-controls"]}
    # Our fixture has SI-10 and AC-3 mapped
    assert "si-10" in ids
    assert "ac-3" in ids


# ---------------------------------------------------------------------------
# UUID determinism
# ---------------------------------------------------------------------------

def test_uuids_are_deterministic(status_report, benchmark, mapping_db, cci_mappings):
    """Same input produces the same UUIDs across two calls."""
    ar1 = generate_oscal_ar(
        status_report, benchmark, mapping_db, cci_mappings, scan_date=SCAN_DATE,
    )
    ar2 = generate_oscal_ar(
        status_report, benchmark, mapping_db, cci_mappings, scan_date=SCAN_DATE,
    )
    assert ar1 == ar2


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def test_oscal_to_json_valid(oscal_ar):
    """Output is valid JSON that round-trips."""
    text = oscal_to_json(oscal_ar)
    parsed = json.loads(text)
    assert parsed == oscal_ar


def test_oscal_to_json_compact(oscal_ar):
    compact = oscal_to_json(oscal_ar, pretty=False)
    assert "\n" not in compact
    assert json.loads(compact) == oscal_ar


# ---------------------------------------------------------------------------
# Control ID normalisation
# ---------------------------------------------------------------------------

def test_control_ids_lowercase(oscal_ar):
    """NIST control IDs must be lowercase with hyphens in OSCAL output."""
    result = oscal_ar["assessment-results"]["results"][0]
    for sel in result["reviewed-controls"]["control-selections"]:
        for ctrl in sel["include-controls"]:
            cid = ctrl["control-id"]
            assert cid == cid.lower(), f"Control ID not lowercase: {cid}"
            assert "_" not in cid, f"Control ID has underscore: {cid}"

    for finding in result.get("findings", []):
        tid = finding["target"]["target-id"]
        # target-id format is "si-10_smt" — the control part before _smt
        ctrl_part = tid.replace("_smt", "")
        assert ctrl_part == ctrl_part.lower(), f"Target control not lowercase: {tid}"


# ---------------------------------------------------------------------------
# write_oscal
# ---------------------------------------------------------------------------

def test_write_oscal_creates_file(
    tmp_path, status_report, benchmark, mapping_db, cci_mappings
):
    out = tmp_path / "ar.json"
    write_oscal(status_report, benchmark, mapping_db, cci_mappings, out, scan_date=SCAN_DATE)
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "assessment-results" in data


# ---------------------------------------------------------------------------
# Integration: real data pipeline
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not SARIF_CWE_TAGS.exists() or not XCCDF_FILE.exists(),
    reason="Integration fixture files not present",
)
def test_integration_sarif_to_oscal():
    """Full pipeline: parse SARIF, determine status, generate OSCAL AR."""
    from stigcode.ingest.xccdf import parse_xccdf
    from stigcode.mapping.engine import load_mapping_database
    from stigcode.data import get_data_dir

    sarif_result = parse_sarif(SARIF_CWE_TAGS)
    assert sarif_result.errors == [], f"SARIF parse errors: {sarif_result.errors}"

    benchmark = parse_xccdf(XCCDF_FILE)
    classifications = {f.vuln_id: "sast" for f in benchmark.findings}

    mapping_path = get_data_dir() / "mappings" / "asd_stig_v6r3.yaml"
    db = load_mapping_database(mapping_path)

    report = determine_status(
        sarif_findings=sarif_result.findings,
        mapping_db=db,
        benchmark=benchmark,
        classifications=classifications,
    )

    ar = generate_oscal_ar(report, benchmark, db, {}, scan_date=SCAN_DATE)

    # Structural validation
    assert "assessment-results" in ar
    result = ar["assessment-results"]["results"][0]
    assert "reviewed-controls" in result
    assert "findings" in result

    # Round-trip JSON
    text = oscal_to_json(ar)
    assert json.loads(text) == ar

    # All control IDs lowercase
    for sel in result["reviewed-controls"]["control-selections"]:
        for ctrl in sel["include-controls"]:
            assert ctrl["control-id"] == ctrl["control-id"].lower()
