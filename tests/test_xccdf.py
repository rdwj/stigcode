"""Tests for the XCCDF parser.

All tests run against the real DISA STIG XCCDF file — no mocking.
"""

from pathlib import Path

import pytest
import yaml

from stigcode.ingest.xccdf import (
    StigBenchmark,
    StigFinding,
    findings_to_yaml,
    parse_xccdf,
)

XCCDF_PATH = Path(__file__).parent.parent / "data" / "stigs" / "application_security_and_development.xml"
EXPECTED_FINDING_COUNT = 286


@pytest.fixture(scope="module")
def benchmark() -> StigBenchmark:
    """Parse the XCCDF file once for the whole module."""
    return parse_xccdf(XCCDF_PATH)


@pytest.fixture(scope="module")
def v222387(benchmark: StigBenchmark) -> StigFinding:
    """Return the specific known finding V-222387."""
    findings_by_id = {f.vuln_id: f for f in benchmark.findings}
    return findings_by_id["V-222387"]


class TestBenchmarkMetadata:
    def test_finding_count(self, benchmark: StigBenchmark):
        assert len(benchmark.findings) == EXPECTED_FINDING_COUNT, (
            f"Expected {EXPECTED_FINDING_COUNT} findings, got {len(benchmark.findings)}"
        )

    def test_benchmark_id(self, benchmark: StigBenchmark):
        assert benchmark.benchmark_id == "Application_Security_Development_STIG"

    def test_title_non_empty(self, benchmark: StigBenchmark):
        assert "Application Security" in benchmark.title

    def test_version(self, benchmark: StigBenchmark):
        assert benchmark.version == "6"

    def test_release_non_empty(self, benchmark: StigBenchmark):
        assert benchmark.release != "", "Release should be non-empty"

    def test_date_non_empty(self, benchmark: StigBenchmark):
        assert benchmark.date != "", "Benchmark date should be non-empty"


class TestKnownFinding:
    def test_vuln_id(self, v222387: StigFinding):
        assert v222387.vuln_id == "V-222387"

    def test_rule_id(self, v222387: StigFinding):
        assert v222387.rule_id == "SV-222387r960735_rule"

    def test_check_id(self, v222387: StigFinding):
        assert v222387.check_id == "APSC-DV-000010"

    def test_title(self, v222387: StigFinding):
        assert "logon sessions" in v222387.title.lower()

    def test_severity(self, v222387: StigFinding):
        assert v222387.severity == "medium"

    def test_category(self, v222387: StigFinding):
        # medium → CAT II
        assert v222387.category == 2

    def test_description_non_empty(self, v222387: StigFinding):
        assert len(v222387.description) > 50, "VulnDiscussion should be substantial"

    def test_description_no_html_tags(self, v222387: StigFinding):
        assert "<VulnDiscussion>" not in v222387.description
        assert "&lt;" not in v222387.description

    def test_fix_text_non_empty(self, v222387: StigFinding):
        assert len(v222387.fix_text) > 10

    def test_check_content_non_empty(self, v222387: StigFinding):
        assert len(v222387.check_content) > 10


class TestCciExtraction:
    def test_v222387_has_cci_000054(self, v222387: StigFinding):
        assert "CCI-000054" in v222387.cci_refs, (
            f"Expected CCI-000054 in {v222387.cci_refs}"
        )

    def test_cci_refs_non_empty(self, benchmark: StigBenchmark):
        """Most findings should have at least one CCI ref."""
        with_cci = [f for f in benchmark.findings if f.cci_refs]
        # Allow a small number without CCI refs but the vast majority must have them
        assert len(with_cci) > len(benchmark.findings) * 0.95, (
            f"Only {len(with_cci)}/{len(benchmark.findings)} findings have CCI refs"
        )

    def test_cci_format(self, benchmark: StigBenchmark):
        """All CCI refs should follow the CCI-NNNNNN pattern."""
        for finding in benchmark.findings:
            for cci in finding.cci_refs:
                assert cci.startswith("CCI-"), (
                    f"Unexpected CCI format '{cci}' in {finding.vuln_id}"
                )


class TestSeverityMapping:
    @pytest.mark.parametrize("expected_severity,expected_cat", [
        ("high", 1),
        ("medium", 2),
        ("low", 3),
    ])
    def test_severity_to_category(
        self, benchmark: StigBenchmark, expected_severity: str, expected_cat: int
    ):
        matching = [
            f for f in benchmark.findings if f.severity == expected_severity
        ]
        if not matching:
            pytest.skip(f"No findings with severity '{expected_severity}' to test")
        for finding in matching:
            assert finding.category == expected_cat, (
                f"{finding.vuln_id}: severity={finding.severity} but category={finding.category}"
            )


class TestFindingCompleteness:
    def test_all_have_non_empty_title(self, benchmark: StigBenchmark):
        empty_titles = [f.vuln_id for f in benchmark.findings if not f.title.strip()]
        assert not empty_titles, f"Findings with empty titles: {empty_titles}"

    def test_all_have_non_empty_check_id(self, benchmark: StigBenchmark):
        empty_ids = [f.vuln_id for f in benchmark.findings if not f.check_id.strip()]
        assert not empty_ids, f"Findings with empty check IDs: {empty_ids}"

    def test_all_have_rule_id(self, benchmark: StigBenchmark):
        empty = [f.vuln_id for f in benchmark.findings if not f.rule_id.strip()]
        assert not empty, f"Findings with empty rule IDs: {empty}"

    def test_all_severities_are_valid(self, benchmark: StigBenchmark):
        valid = {"high", "medium", "low"}
        invalid = [
            (f.vuln_id, f.severity)
            for f in benchmark.findings
            if f.severity not in valid
        ]
        assert not invalid, f"Findings with invalid severity: {invalid}"

    def test_v222387_has_legacy_ids(self, v222387: StigFinding):
        assert len(v222387.legacy_ids) > 0, "V-222387 should have legacy IDs"


class TestProfileExtraction:
    def test_profiles_non_empty(self, benchmark: StigBenchmark):
        assert len(benchmark.profiles) > 0, "Should extract at least one profile"

    def test_mac1_classified_profile_exists(self, benchmark: StigBenchmark):
        assert "MAC-1_Classified" in benchmark.profiles, (
            f"MAC-1_Classified not found; profiles: {list(benchmark.profiles.keys())}"
        )

    def test_profile_contains_v222387(self, benchmark: StigBenchmark):
        mac1 = benchmark.profiles.get("MAC-1_Classified", [])
        assert "V-222387" in mac1, (
            f"V-222387 not in MAC-1_Classified profile; first 5: {mac1[:5]}"
        )

    def test_profile_finding_counts(self, benchmark: StigBenchmark):
        """Each profile should reference a substantial number of findings."""
        for profile_id, vuln_ids in benchmark.profiles.items():
            assert len(vuln_ids) > 100, (
                f"Profile {profile_id} has only {len(vuln_ids)} findings; expected >100"
            )


class TestYamlSerialization:
    def test_yaml_is_valid(self, benchmark: StigBenchmark):
        output = findings_to_yaml(benchmark)
        parsed = yaml.safe_load(output)
        assert isinstance(parsed, dict)

    def test_yaml_finding_count(self, benchmark: StigBenchmark):
        output = findings_to_yaml(benchmark)
        parsed = yaml.safe_load(output)
        assert len(parsed["findings"]) == EXPECTED_FINDING_COUNT

    def test_yaml_round_trip_vuln_id(self, benchmark: StigBenchmark):
        output = findings_to_yaml(benchmark)
        parsed = yaml.safe_load(output)
        vuln_ids = {f["vuln_id"] for f in parsed["findings"]}
        assert "V-222387" in vuln_ids

    def test_yaml_round_trip_cci_refs(self, benchmark: StigBenchmark):
        output = findings_to_yaml(benchmark)
        parsed = yaml.safe_load(output)
        by_id = {f["vuln_id"]: f for f in parsed["findings"]}
        assert "CCI-000054" in by_id["V-222387"]["cci_refs"]

    def test_yaml_preserves_severity(self, benchmark: StigBenchmark):
        output = findings_to_yaml(benchmark)
        parsed = yaml.safe_load(output)
        by_id = {f["vuln_id"]: f for f in parsed["findings"]}
        assert by_id["V-222387"]["severity"] == "medium"
        assert by_id["V-222387"]["category"] == 2

    def test_yaml_includes_metadata(self, benchmark: StigBenchmark):
        output = findings_to_yaml(benchmark)
        parsed = yaml.safe_load(output)
        assert parsed["benchmark_id"] == benchmark.benchmark_id
        assert parsed["title"] == benchmark.title
        assert parsed["version"] == benchmark.version


class TestErrorHandling:
    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_xccdf(Path("/nonexistent/path/stig.xml"))
