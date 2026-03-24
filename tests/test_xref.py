"""Tests for the STIG cross-reference matrix generator (output.xref)."""

from __future__ import annotations

import csv
import io
from pathlib import Path

import pytest

from stigcode.ingest.xccdf import StigBenchmark, StigFinding
from stigcode.mapping.engine import MappingDatabase, StigMapping
from stigcode.output.xref import (
    build_xref_matrix,
    write_xref,
    xref_to_csv,
    xref_to_markdown,
)

# ---------------------------------------------------------------------------
# Paths to real data assets
# ---------------------------------------------------------------------------

_REPO = Path(__file__).parent.parent
_XCCDF = _REPO / "data" / "stigs" / "application_security_and_development.xml"
_MAPPINGS = _REPO / "data" / "mappings" / "asd_stig_v6r3.yaml"
_CLASSIFICATIONS = _REPO / "data" / "mappings" / "finding_classifications.yaml"
_CCI = _REPO / "data" / "cci" / "cci_to_nist.yaml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(
    vuln_id: str,
    check_id: str = "APSC-DV-000000",
    severity: str = "medium",
    cci_refs: list[str] | None = None,
    title: str = "",
) -> StigFinding:
    cat = {"high": 1, "medium": 2, "low": 3}.get(severity, 2)
    return StigFinding(
        vuln_id=vuln_id,
        rule_id=f"SV-{vuln_id}_rule",
        check_id=check_id,
        title=title or f"Title for {vuln_id}",
        description="",
        severity=severity,
        category=cat,
        cci_refs=cci_refs or [],
        fix_text="",
        check_content="",
    )


def _mapping(cwe_id: int, stig_id: str, check_id: str = "APSC-DV-000000",
             confidence: str = "direct", nist_control: str = "SI-10",
             cci_refs: list[str] | None = None) -> StigMapping:
    return StigMapping(
        cwe_id=cwe_id,
        stig_id=stig_id,
        check_id=check_id,
        confidence=confidence,
        nist_control=nist_control,
        cci_refs=cci_refs or [],
    )


def _db(mappings: list[StigMapping]) -> MappingDatabase:
    return MappingDatabase(
        mappings=mappings,
        version="1.0.0",
        stig_name="Test STIG",
        stig_version="V1R1",
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
# Unit tests with small synthetic data
# ---------------------------------------------------------------------------

class TestBuildXrefMatrixUnit:
    def setup_method(self):
        self.findings = [
            _finding("V-100001", cci_refs=["CCI-001310"]),  # sast
            _finding("V-100002"),                            # procedural
            _finding("V-100003", cci_refs=["CCI-001312"]),  # sast, multi-CWE
        ]
        self.mappings = [
            _mapping(89, "V-100001", confidence="direct", nist_control="SI-10",
                     cci_refs=["CCI-001310"]),
            _mapping(564, "V-100003", confidence="inferred", nist_control="SI-10"),
            _mapping(89, "V-100003", confidence="direct", nist_control="SI-10"),
        ]
        self.db = _db(self.mappings)
        self.benchmark = _benchmark(self.findings)
        self.classifications = {
            "V-100001": {"assessment_method": "sast"},
            "V-100002": {"assessment_method": "procedural"},
            "V-100003": {"assessment_method": "sast"},
        }
        self.cci_mappings = {"CCI-001310": "SI-10", "CCI-001312": "SI-10"}

    def test_returns_all_findings(self):
        entries = build_xref_matrix(
            self.benchmark, self.db, self.cci_mappings, self.classifications
        )
        assert len(entries) == 3, (
            f"Expected 3 entries, got {len(entries)}: {[e.stig_id for e in entries]}"
        )

    def test_sast_findings_have_cwe_ids(self):
        entries = build_xref_matrix(
            self.benchmark, self.db, self.cci_mappings, self.classifications
        )
        sast = {e.stig_id: e for e in entries if e.assessment_method == "sast"}
        assert 89 in sast["V-100001"].cwe_ids, (
            f"Expected CWE-89 in V-100001.cwe_ids, got {sast['V-100001'].cwe_ids}"
        )

    def test_procedural_findings_have_empty_cwe_ids(self):
        entries = build_xref_matrix(
            self.benchmark, self.db, self.cci_mappings, self.classifications
        )
        proc = [e for e in entries if e.assessment_method == "procedural"]
        assert len(proc) == 1
        assert proc[0].cwe_ids == [], (
            f"Expected empty cwe_ids for procedural finding, got {proc[0].cwe_ids}"
        )

    def test_procedural_assessment_method_field(self):
        entries = build_xref_matrix(
            self.benchmark, self.db, self.cci_mappings, self.classifications
        )
        proc = [e for e in entries if e.stig_id == "V-100002"]
        assert proc[0].assessment_method == "procedural"

    def test_sast_findings_appear_before_procedural(self):
        entries = build_xref_matrix(
            self.benchmark, self.db, self.cci_mappings, self.classifications
        )
        methods = [e.assessment_method for e in entries]
        # All sast entries must come before any procedural entry
        last_sast = max((i for i, m in enumerate(methods) if m == "sast"), default=-1)
        first_proc = min((i for i, m in enumerate(methods) if m == "procedural"), default=len(methods))
        assert last_sast < first_proc, (
            f"SAST entries must precede procedural entries; got order: {methods}"
        )

    def test_multi_cwe_aggregated(self):
        entries = build_xref_matrix(
            self.benchmark, self.db, self.cci_mappings, self.classifications
        )
        entry = next(e for e in entries if e.stig_id == "V-100003")
        assert len(entry.cwe_ids) == 2, (
            f"Expected 2 CWEs for V-100003, got {entry.cwe_ids}"
        )

    def test_confidence_from_mapping(self):
        entries = build_xref_matrix(
            self.benchmark, self.db, self.cci_mappings, self.classifications
        )
        entry = next(e for e in entries if e.stig_id == "V-100001")
        assert entry.confidence == "direct", (
            f"Expected confidence=direct, got {entry.confidence}"
        )


class TestXrefToMarkdown:
    def _build(self):
        findings = [_finding("V-100001"), _finding("V-200001")]
        mappings = [_mapping(89, "V-100001")]
        db = _db(mappings)
        benchmark = _benchmark(findings)
        classifications = {
            "V-100001": {"assessment_method": "sast"},
            "V-200001": {"assessment_method": "procedural"},
        }
        return build_xref_matrix(benchmark, db, {}, classifications)

    def test_contains_sast_section(self):
        entries = self._build()
        md = xref_to_markdown(entries)
        assert "SAST-Assessable Findings" in md, "Missing SAST section header"

    def test_contains_procedural_section(self):
        entries = self._build()
        md = xref_to_markdown(entries)
        assert "Procedural Findings" in md, "Missing Procedural section header"

    def test_benchmark_title_in_header(self):
        entries = self._build()
        md = xref_to_markdown(entries, benchmark_title="My STIG V1R1")
        assert "My STIG V1R1" in md

    def test_both_v_ids_present(self):
        entries = self._build()
        md = xref_to_markdown(entries)
        assert "V-100001" in md
        assert "V-200001" in md


class TestXrefToCsv:
    def _build(self):
        findings = [_finding("V-100001"), _finding("V-200001")]
        mappings = [_mapping(89, "V-100001")]
        db = _db(mappings)
        benchmark = _benchmark(findings)
        classifications = {
            "V-100001": {"assessment_method": "sast"},
            "V-200001": {"assessment_method": "procedural"},
        }
        return build_xref_matrix(benchmark, db, {}, classifications)

    def test_correct_column_count(self):
        entries = self._build()
        text = xref_to_csv(entries)
        reader = csv.reader(io.StringIO(text))
        header = next(reader)
        assert len(header) == 11, (
            f"Expected 11 CSV columns, got {len(header)}: {header}"
        )

    def test_row_count_matches_entries(self):
        entries = self._build()
        text = xref_to_csv(entries)
        rows = list(csv.DictReader(io.StringIO(text)))
        assert len(rows) == len(entries), (
            f"CSV row count {len(rows)} != entries count {len(entries)}"
        )

    def test_required_columns_present(self):
        entries = self._build()
        text = xref_to_csv(entries)
        reader = csv.DictReader(io.StringIO(text))
        expected = {
            "STIG_ID", "Check_ID", "Title", "Severity", "CAT",
            "CWE_IDs", "NIST_Controls", "CCI_Refs",
            "Confidence", "Assessment_Method", "Notes",
        }
        assert set(reader.fieldnames or []) == expected, (
            f"CSV column mismatch. Got: {reader.fieldnames}"
        )


class TestWriteXref:
    def _entries(self):
        findings = [_finding("V-100001")]
        mappings = [_mapping(89, "V-100001")]
        db = _db(mappings)
        benchmark = _benchmark(findings)
        return build_xref_matrix(benchmark, db, {}, {"V-100001": {"assessment_method": "sast"}})

    def test_write_markdown(self, tmp_path):
        out = tmp_path / "xref.md"
        entries = self._entries()
        write_xref(entries, out, fmt="md")
        assert out.exists()
        assert "# STIG Cross-Reference Matrix" in out.read_text()

    def test_write_csv(self, tmp_path):
        out = tmp_path / "xref.csv"
        entries = self._entries()
        write_xref(entries, out, fmt="csv")
        assert out.exists()
        assert "STIG_ID" in out.read_text()

    def test_invalid_format_raises(self, tmp_path):
        out = tmp_path / "xref.xyz"
        with pytest.raises(ValueError, match="Unknown format"):
            write_xref([], out, fmt="xyz")


# ---------------------------------------------------------------------------
# Integration tests against real data files
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _XCCDF.exists(), reason="XCCDF fixture not present")
class TestXrefIntegration:
    @pytest.fixture(scope="class")
    def entries(self):
        import yaml

        from stigcode.ingest.xccdf import parse_xccdf
        from stigcode.mapping.engine import load_mapping_database

        benchmark = parse_xccdf(_XCCDF)
        db = load_mapping_database(_MAPPINGS)

        raw_cci = yaml.safe_load(_CCI.read_text())
        cci_mappings = {str(k): str(v) for k, v in raw_cci.items()}

        raw_cls = yaml.safe_load(_CLASSIFICATIONS.read_text())
        classifications = raw_cls.get("classifications", {})

        return build_xref_matrix(benchmark, db, cci_mappings, classifications)

    def test_total_entry_count(self, entries):
        assert len(entries) == 286, (
            f"Expected 286 total entries (all STIG findings), got {len(entries)}"
        )

    def test_sast_findings_have_cwe_ids(self, entries):
        sast = [e for e in entries if e.assessment_method == "sast"]
        for e in sast:
            assert e.cwe_ids, (
                f"SAST finding {e.stig_id} has no CWE IDs assigned"
            )

    def test_procedural_findings_empty_cwe_ids(self, entries):
        procedural = [e for e in entries if e.assessment_method == "procedural"]
        for e in procedural:
            assert e.cwe_ids == [], (
                f"Procedural finding {e.stig_id} unexpectedly has CWE IDs: {e.cwe_ids}"
            )

    def test_v222607_has_cwe89(self, entries):
        entry = next((e for e in entries if e.stig_id == "V-222607"), None)
        assert entry is not None, "V-222607 not found in xref entries"
        assert 89 in entry.cwe_ids, (
            f"Expected CWE-89 in V-222607 cwe_ids, got: {entry.cwe_ids}"
        )

    def test_confidence_matches_mapping_db(self, entries):
        from stigcode.mapping.engine import load_mapping_database
        db = load_mapping_database(_MAPPINGS)

        sast_entries = {e.stig_id: e for e in entries if e.assessment_method == "sast"}
        for stig_id, entry in sast_entries.items():
            db_matches = db.lookup_by_stig(stig_id)
            if db_matches:
                db_confidences = {m.confidence for m in db_matches}
                assert entry.confidence in db_confidences, (
                    f"{stig_id}: xref confidence={entry.confidence!r} not in "
                    f"mapping db confidences {db_confidences}"
                )

    def test_markdown_contains_both_sections(self, entries):
        md = xref_to_markdown(entries, benchmark_title="Test")
        assert "SAST-Assessable Findings" in md
        assert "Procedural Findings" in md

    def test_csv_has_286_rows(self, entries):
        text = xref_to_csv(entries)
        rows = list(csv.DictReader(io.StringIO(text)))
        assert len(rows) == 286, (
            f"CSV should have 286 data rows, got {len(rows)}"
        )
