"""Tests for SARIF ingestion and normalization (src/stigcode/ingest/sarif.py)."""

import json
from pathlib import Path

from stigcode.ingest.sarif import NormalizedFinding, SarifIngestionResult, parse_sarif

SARIF_DIR = Path(__file__).parent / "fixtures" / "sarif"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load(name: str) -> Path:
    return SARIF_DIR / name


def _one(result: SarifIngestionResult) -> NormalizedFinding:
    """Assert exactly one finding and return it."""
    assert len(result.findings) == 1, (
        f"Expected 1 finding, got {len(result.findings)}: {result.findings}"
    )
    return result.findings[0]


# ---------------------------------------------------------------------------
# Fixture-based tests
# ---------------------------------------------------------------------------

class TestCweInTags:
    """cwe_in_tags.sarif — CodeQL-style external/cwe/cwe-NNN rule tag."""

    def test_extracts_cwe_89(self):
        result = parse_sarif(_load("cwe_in_tags.sarif"))
        f = _one(result)
        assert 89 in f.cwe_ids, f"Expected CWE-89 in cwe_ids, got {f.cwe_ids}"

    def test_severity_cat_i(self):
        result = parse_sarif(_load("cwe_in_tags.sarif"))
        f = _one(result)
        assert f.severity == "CAT I", f"Expected CAT I for error level, got {f.severity}"

    def test_confidence_inferred(self):
        result = parse_sarif(_load("cwe_in_tags.sarif"))
        f = _one(result)
        assert f.confidence == "inferred", f"Got {f.confidence}"

    def test_scanner_attribution(self):
        result = parse_sarif(_load("cwe_in_tags.sarif"))
        assert result.scanner_name == "TestScanner-Tags"

    def test_no_errors(self):
        result = parse_sarif(_load("cwe_in_tags.sarif"))
        assert result.errors == [], f"Unexpected errors: {result.errors}"


class TestCweInProperties:
    """cwe_in_properties.sarif — CWE and stig_ids in result.properties."""

    def test_extracts_cwe_22(self):
        result = parse_sarif(_load("cwe_in_properties.sarif"))
        f = _one(result)
        assert 22 in f.cwe_ids, f"Expected CWE-22 in cwe_ids, got {f.cwe_ids}"

    def test_extracts_stig_id(self):
        result = parse_sarif(_load("cwe_in_properties.sarif"))
        f = _one(result)
        assert "V-222609" in f.stig_ids, f"Expected V-222609 in stig_ids, got {f.stig_ids}"

    def test_severity_cat_ii(self):
        result = parse_sarif(_load("cwe_in_properties.sarif"))
        f = _one(result)
        assert f.severity == "CAT II", f"Expected CAT II for warning level, got {f.severity}"

    def test_no_errors(self):
        result = parse_sarif(_load("cwe_in_properties.sarif"))
        assert result.errors == [], f"Unexpected errors: {result.errors}"


class TestCweInRelationships:
    """cwe_in_relationships.sarif — CWE via SARIF taxonomy relationships."""

    def test_extracts_cwe_79(self):
        result = parse_sarif(_load("cwe_in_relationships.sarif"))
        f = _one(result)
        assert 79 in f.cwe_ids, f"Expected CWE-79 in cwe_ids, got {f.cwe_ids}"

    def test_confidence_inferred(self):
        result = parse_sarif(_load("cwe_in_relationships.sarif"))
        f = _one(result)
        assert f.confidence == "inferred", f"Got {f.confidence}"

    def test_no_errors(self):
        result = parse_sarif(_load("cwe_in_relationships.sarif"))
        assert result.errors == [], f"Unexpected errors: {result.errors}"


class TestCweInMessage:
    """cwe_in_message.sarif — CWE extracted via message text regex fallback."""

    def test_extracts_cwe_120_and_20(self):
        result = parse_sarif(_load("cwe_in_message.sarif"))
        f = _one(result)
        assert 120 in f.cwe_ids, f"Expected CWE-120, got {f.cwe_ids}"
        assert 20 in f.cwe_ids, f"Expected CWE-20, got {f.cwe_ids}"

    def test_confidence_low(self):
        result = parse_sarif(_load("cwe_in_message.sarif"))
        f = _one(result)
        assert f.confidence == "low", f"Expected 'low' confidence for message-only CWE, got {f.confidence}"

    def test_no_errors(self):
        result = parse_sarif(_load("cwe_in_message.sarif"))
        assert result.errors == [], f"Unexpected errors: {result.errors}"


class TestMultiRun:
    """multi_run.sarif — two runs, correct scanner attribution per finding."""

    def test_two_findings(self):
        result = parse_sarif(_load("multi_run.sarif"))
        assert len(result.findings) == 2, (
            f"Expected 2 findings, got {len(result.findings)}"
        )

    def test_runs_processed_count(self):
        result = parse_sarif(_load("multi_run.sarif"))
        assert result.runs_processed == 2

    def test_scanner_a_attribution(self):
        result = parse_sarif(_load("multi_run.sarif"))
        finding_a = next(f for f in result.findings if f.scanner_name == "Scanner-A")
        assert finding_a.scanner_version == "2.0.0", (
            f"Expected version 2.0.0, got {finding_a.scanner_version}"
        )

    def test_scanner_b_attribution(self):
        result = parse_sarif(_load("multi_run.sarif"))
        finding_b = next(f for f in result.findings if f.scanner_name == "Scanner-B")
        assert finding_b.scanner_version == "3.1.0", (
            f"Expected version 3.1.0, got {finding_b.scanner_version}"
        )

    def test_top_level_scanner_is_first_run(self):
        result = parse_sarif(_load("multi_run.sarif"))
        assert result.scanner_name == "Scanner-A"

    def test_no_errors(self):
        result = parse_sarif(_load("multi_run.sarif"))
        assert result.errors == [], f"Unexpected errors: {result.errors}"


class TestEmptyRun:
    """empty_run.sarif — empty results list, should produce zero findings."""

    def test_zero_findings(self):
        result = parse_sarif(_load("empty_run.sarif"))
        assert len(result.findings) == 0, (
            f"Expected 0 findings, got {len(result.findings)}"
        )

    def test_no_errors(self):
        result = parse_sarif(_load("empty_run.sarif"))
        assert result.errors == [], f"Unexpected errors: {result.errors}"

    def test_runs_processed(self):
        result = parse_sarif(_load("empty_run.sarif"))
        assert result.runs_processed == 1


class TestSimpleExample:
    """simple_example.sarif — basic ESLint-style SARIF with no compliance metadata."""

    def test_one_finding(self):
        result = parse_sarif(_load("simple_example.sarif"))
        f = _one(result)
        assert f.rule_id == "no-unused-vars"

    def test_file_path_preserved(self):
        result = parse_sarif(_load("simple_example.sarif"))
        f = _one(result)
        assert "simple-example.js" in f.file_path

    def test_no_errors(self):
        result = parse_sarif(_load("simple_example.sarif"))
        assert result.errors == [], f"Unexpected errors: {result.errors}"


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Robustness and error handling."""

    def test_invalid_json_returns_error(self):
        result = parse_sarif("this is not json {{{")
        assert result.findings == []
        assert len(result.errors) == 1
        assert "Failed to load SARIF" in result.errors[0]

    def test_missing_runs_key(self):
        sarif = json.dumps({"version": "2.1.0"})
        result = parse_sarif(sarif)
        assert result.findings == []
        assert any("runs" in e for e in result.errors), (
            f"Expected error about missing 'runs', got: {result.errors}"
        )

    def test_wrong_version_still_parses(self):
        sarif = json.dumps({
            "version": "2.0.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "old-scanner", "version": "1.0"}},
                    "results": [
                        {
                            "ruleId": "test-rule",
                            "level": "warning",
                            "message": {"text": "A warning"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/foo.py"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        })
        result = parse_sarif(sarif)
        # Should have a warning about the version
        assert any("2.0.0" in e for e in result.errors), (
            f"Expected version warning in errors, got: {result.errors}"
        )
        # But still parsed the finding
        assert len(result.findings) == 1, (
            f"Expected 1 finding despite version mismatch, got {len(result.findings)}"
        )

    def test_finding_with_no_location(self):
        sarif = json.dumps({
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "scanner", "version": "1.0"}},
                    "results": [
                        {
                            "ruleId": "missing-loc",
                            "level": "warning",
                            "message": {"text": "No location provided"},
                        }
                    ],
                }
            ],
        })
        result = parse_sarif(sarif)
        assert len(result.findings) == 1, (
            f"Expected 1 finding even without location, got {len(result.findings)}"
        )
        f = result.findings[0]
        assert f.file_path == "", f"Expected empty file_path, got '{f.file_path}'"
        assert f.start_line == 0

    def test_level_none_skipped(self):
        sarif = json.dumps({
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "scanner", "version": "1.0"}},
                    "results": [
                        {
                            "ruleId": "info-only",
                            "level": "none",
                            "message": {"text": "Informational only"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/foo.py"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        })
        result = parse_sarif(sarif)
        assert result.findings == [], "level=none results should not produce findings"

    def test_parse_from_path(self, tmp_path):
        sarif_data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "file-scanner", "version": "0.1"}},
                    "results": [
                        {
                            "ruleId": "file-rule",
                            "level": "error",
                            "message": {"text": "Error from file"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "main.py"},
                                        "region": {"startLine": 5},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        p = tmp_path / "test.sarif"
        p.write_text(json.dumps(sarif_data))
        result = parse_sarif(p)
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "file-rule"

    def test_severity_cat_iii_for_note(self):
        sarif = json.dumps({
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "s", "version": "1"}},
                    "results": [
                        {
                            "ruleId": "note-rule",
                            "level": "note",
                            "message": {"text": "Just a note"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "a.py"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        })
        result = parse_sarif(sarif)
        assert result.findings[0].severity == "CAT III"

    def test_stigcategory_overrides_level(self):
        sarif = json.dumps({
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "s", "version": "1"}},
                    "results": [
                        {
                            "ruleId": "override-rule",
                            "level": "note",
                            "message": {"text": "Override severity"},
                            "properties": {"stigCategory": "I"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "a.py"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        })
        result = parse_sarif(sarif)
        assert result.findings[0].severity == "CAT I", (
            f"stigCategory I should override note→CAT III, got {result.findings[0].severity}"
        )
