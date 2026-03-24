"""Tests for SARIF validation (src/stigcode/ingest/validate.py)."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
from typer.testing import CliRunner

from stigcode.cli import app
from stigcode.ingest.validate import validate_sarif

runner = CliRunner()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures" / "sarif"


def _write_sarif(tmp_path: Path, data: dict, name: str = "test.sarif") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _minimal_sarif(*, version: str = "2.1.0", results: list | None = None) -> dict:
    """Return the simplest valid SARIF with one rule and optional results."""
    return {
        "version": version,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "TestScanner",
                        "version": "1.0.0",
                        "rules": [
                            {
                                "id": "rule-1",
                                "shortDescription": {"text": "A rule"},
                            }
                        ],
                    }
                },
                "results": results if results is not None else [],
            }
        ],
    }


def _result_with_location(rule_id: str = "rule-1", level: str = "warning") -> dict:
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": "A finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": 10},
                }
            }
        ],
    }


# ---------------------------------------------------------------------------
# Structural validation
# ---------------------------------------------------------------------------

def test_valid_sarif_passes(tmp_path: Path) -> None:
    path = _write_sarif(tmp_path, _minimal_sarif())
    result = validate_sarif(path)
    assert result.is_valid is True
    assert not any(i.level == "error" for i in result.issues)


def test_invalid_json_fails(tmp_path: Path) -> None:
    p = tmp_path / "bad.sarif"
    p.write_text("not json {{{", encoding="utf-8")
    result = validate_sarif(p)
    assert result.is_valid is False
    errors = [i for i in result.issues if i.level == "error"]
    assert any("Not valid JSON" in i.message for i in errors)


def test_missing_version_fails(tmp_path: Path) -> None:
    data = {"runs": [{"tool": {"driver": {"name": "X", "rules": []}}, "results": []}]}
    path = _write_sarif(tmp_path, data)
    result = validate_sarif(path)
    assert result.is_valid is False
    assert any("version" in i.message.lower() for i in result.issues if i.level == "error")


def test_missing_runs_fails(tmp_path: Path) -> None:
    path = _write_sarif(tmp_path, {"version": "2.1.0"})
    result = validate_sarif(path)
    assert result.is_valid is False
    assert any("runs" in i.message for i in result.issues if i.level == "error")


def test_wrong_version_errors(tmp_path: Path) -> None:
    path = _write_sarif(tmp_path, _minimal_sarif(version="1.0.0"))
    result = validate_sarif(path)
    assert result.is_valid is False
    errors = [i for i in result.issues if i.level == "error"]
    assert any("2.1.0" in i.message for i in errors)


# ---------------------------------------------------------------------------
# Warnings
# ---------------------------------------------------------------------------

def test_missing_cwe_warns(tmp_path: Path) -> None:
    result_obj = _result_with_location()
    # No CWE in result, rule tags, or message
    path = _write_sarif(tmp_path, _minimal_sarif(results=[result_obj]))
    result = validate_sarif(path)
    assert result.is_valid is True
    warnings = [i for i in result.issues if i.level == "warning"]
    assert any("CWE" in i.message for i in warnings)


def test_missing_locations_warns(tmp_path: Path) -> None:
    result_obj = {
        "ruleId": "rule-1",
        "level": "warning",
        "message": {"text": "CWE-89 issue"},
    }
    path = _write_sarif(tmp_path, _minimal_sarif(results=[result_obj]))
    result = validate_sarif(path)
    assert result.is_valid is True
    warnings = [i for i in result.issues if i.level == "warning"]
    assert any("locations" in i.message.lower() for i in warnings)


def test_invalid_level_warns(tmp_path: Path) -> None:
    result_obj = {
        "ruleId": "rule-1",
        "level": "critical",  # not a valid SARIF level
        "message": {"text": "CWE-89 issue"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}
        ],
    }
    path = _write_sarif(tmp_path, _minimal_sarif(results=[result_obj]))
    result = validate_sarif(path)
    warnings = [i for i in result.issues if i.level == "warning"]
    assert any("level" in i.message.lower() for i in warnings)


# ---------------------------------------------------------------------------
# Tier classification
# ---------------------------------------------------------------------------

def test_tier_enriched(tmp_path: Path) -> None:
    result_obj = {
        "ruleId": "rule-1",
        "level": "error",
        "message": {"text": "SQL injection"},
        "properties": {"stigIds": ["V-222607"]},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}
        ],
    }
    path = _write_sarif(tmp_path, _minimal_sarif(results=[result_obj]))
    result = validate_sarif(path)
    assert result.tier == "enriched"
    assert result.stig_enrichment is True


def test_tier_standard(tmp_path: Path) -> None:
    # CWE via rule tags
    path = FIXTURES / "cwe_in_tags.sarif"
    result = validate_sarif(path)
    assert result.tier == "standard"
    assert result.stig_enrichment is False


def test_tier_minimal(tmp_path: Path) -> None:
    # simple_example.sarif has no CWE in rules or results
    path = FIXTURES / "simple_example.sarif"
    result = validate_sarif(path)
    assert result.tier == "minimal"


# ---------------------------------------------------------------------------
# CWE coverage counting
# ---------------------------------------------------------------------------

def test_cwe_coverage_counts(tmp_path: Path) -> None:
    """Three results using three different CWE methods."""
    results = [
        # properties.stigIds
        {
            "ruleId": "rule-1",
            "level": "error",
            "message": {"text": "msg"},
            "properties": {"stigIds": ["V-222607"]},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}
            ],
        },
        # message.text fallback
        {
            "ruleId": "rule-1",
            "level": "warning",
            "message": {"text": "CWE-89 present in message"},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "b.py"}, "region": {"startLine": 2}}}
            ],
        },
        # no CWE at all
        {
            "ruleId": "rule-1",
            "level": "note",
            "message": {"text": "no cwe here"},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "c.py"}, "region": {"startLine": 3}}}
            ],
        },
    ]
    path = _write_sarif(tmp_path, _minimal_sarif(results=results))
    result = validate_sarif(path)
    assert result.cwe_coverage.get("properties.stigIds", 0) == 1
    assert result.cwe_coverage.get("message.text", 0) == 1
    assert result.cwe_coverage.get("none", 0) == 1


# ---------------------------------------------------------------------------
# Empty run
# ---------------------------------------------------------------------------

def test_empty_run_valid(tmp_path: Path) -> None:
    path = FIXTURES / "empty_run.sarif"
    result = validate_sarif(path)
    assert result.is_valid is True
    assert result.total_results == 0


# ---------------------------------------------------------------------------
# Integration: validate all fixture files
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fixture_name", [
    "cwe_in_message.sarif",
    "cwe_in_properties.sarif",
    "cwe_in_relationships.sarif",
    "cwe_in_tags.sarif",
    "empty_run.sarif",
    "simple_example.sarif",
    "multi_run.sarif",
    "trend_scan_1.sarif",
    "trend_scan_2.sarif",
])
def test_all_fixtures_are_valid(fixture_name: str) -> None:
    """All existing test fixtures should pass structural validation."""
    path = FIXTURES / fixture_name
    result = validate_sarif(path)
    errors = [i for i in result.issues if i.level == "error"]
    assert result.is_valid is True, (
        f"Fixture {fixture_name!r} failed validation with errors: {errors}"
    )


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

def test_cli_validate_exits_0_on_valid(tmp_path: Path) -> None:
    path = _write_sarif(tmp_path, _minimal_sarif())
    cli_result = runner.invoke(app, ["validate", str(path)])
    assert cli_result.exit_code == 0, cli_result.output


def test_cli_validate_exits_2_on_invalid(tmp_path: Path) -> None:
    p = tmp_path / "bad.sarif"
    p.write_text("not json", encoding="utf-8")
    cli_result = runner.invoke(app, ["validate", str(p)])
    assert cli_result.exit_code == 2


def test_cli_validate_exits_1_on_warnings(tmp_path: Path) -> None:
    # Result with no CWE produces a warning
    result_obj = _result_with_location()
    path = _write_sarif(tmp_path, _minimal_sarif(results=[result_obj]))
    cli_result = runner.invoke(app, ["validate", str(path)])
    assert cli_result.exit_code == 1, cli_result.output


def test_strict_mode_fails_on_warnings(tmp_path: Path) -> None:
    result_obj = _result_with_location()
    path = _write_sarif(tmp_path, _minimal_sarif(results=[result_obj]))
    cli_result = runner.invoke(app, ["validate", str(path), "--strict"])
    assert cli_result.exit_code == 2, cli_result.output


def test_cli_output_contains_scanner_info(tmp_path: Path) -> None:
    path = _write_sarif(tmp_path, _minimal_sarif())
    cli_result = runner.invoke(app, ["validate", str(path)])
    assert "TestScanner" in cli_result.output
    assert "1.0.0" in cli_result.output


def test_cli_missing_file_exits_2() -> None:
    cli_result = runner.invoke(app, ["validate", "/nonexistent/path.sarif"])
    assert cli_result.exit_code == 2
    assert "not found" in cli_result.output
