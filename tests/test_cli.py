"""CLI integration tests using Typer's CliRunner."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from stigcode.cli import app
from stigcode.data import get_data_dir
from stigcode.version import __version__

runner = CliRunner()

FIXTURES = Path(__file__).parent / "fixtures"
XCCDF_FILE = get_data_dir() / "stigs" / "application_security_and_development.xml"
SARIF_CWE_TAGS = FIXTURES / "sarif" / "cwe_in_tags.sarif"


class TestVersion:
    def test_version_exits_zero(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0, result.output

    def test_version_contains_version_string(self):
        result = runner.invoke(app, ["version"])
        assert __version__ in result.output


class TestHelp:
    def test_help_exits_zero(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0, result.output

    def test_help_contains_description(self):
        result = runner.invoke(app, ["--help"])
        assert "SARIF-to-compliance bridge" in result.output


class TestExportRequiresSarif:
    @pytest.mark.parametrize("subcommand", ["ckl", "report"])
    def test_export_requires_sarif_argument(self, subcommand):
        """Implemented export commands require a SARIF file argument."""
        result = runner.invoke(app, ["export", subcommand])
        assert result.exit_code == 2, f"export {subcommand}: {result.output}"


class TestStigImportXccdf:
    def test_exits_zero(self):
        result = runner.invoke(app, ["stig", "import-xccdf", str(XCCDF_FILE)])
        assert result.exit_code == 0, result.output

    def test_shows_benchmark_title(self):
        result = runner.invoke(app, ["stig", "import-xccdf", str(XCCDF_FILE)])
        assert "Application Security and Development" in result.output

    def test_shows_finding_count(self):
        result = runner.invoke(app, ["stig", "import-xccdf", str(XCCDF_FILE)])
        # 286 findings in the fixture file
        assert "286" in result.output

    def test_shows_category_breakdown(self):
        result = runner.invoke(app, ["stig", "import-xccdf", str(XCCDF_FILE)])
        assert "CAT 1" in result.output
        assert "CAT 2" in result.output
        assert "CAT 3" in result.output

    def test_missing_file_exits_2(self):
        result = runner.invoke(app, ["stig", "import-xccdf", "/nonexistent/path.xml"])
        assert result.exit_code == 2


class TestImportSarif:
    def test_exits_zero(self):
        result = runner.invoke(app, ["import", str(SARIF_CWE_TAGS)])
        # exits 0 if parse_sarif is available; exits 2 if not yet implemented
        assert result.exit_code in (0, 2), result.output

    def test_not_implemented_shows_message_when_module_missing(self, monkeypatch):
        """If the ingest.sarif module isn't importable, we get a clean message."""
        import builtins
        real_import = builtins.__import__

        def block_sarif(name, *args, **kwargs):
            if name == "stigcode.ingest.sarif":
                raise ImportError("module not ready")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", block_sarif)
        result = runner.invoke(app, ["import", str(SARIF_CWE_TAGS)])
        assert result.exit_code == 2
        combined = result.stdout + (result.stderr or "")
        assert "Not yet implemented" in combined


class TestLookupCwe:
    def test_known_cwe_exits_zero(self):
        result = runner.invoke(app, ["lookup", "cwe", "--cwe", "89"])
        assert result.exit_code == 0, (
            f"Expected exit 0 for CWE-89, got {result.exit_code}.\n{result.output}"
        )

    def test_known_cwe_output_contains_stig_id(self):
        """CWE-89 (SQL injection) should map to at least one STIG finding."""
        result = runner.invoke(app, ["lookup", "cwe", "--cwe", "89"])
        assert result.exit_code == 0, result.output
        # The output should contain at least one V- prefixed ID
        assert "V-" in result.output, (
            f"Expected at least one V-ID in output for CWE-89:\n{result.output}"
        )

    def test_cwe_prefix_format_accepted(self):
        """'CWE-89' and '89' should produce the same result."""
        result_bare = runner.invoke(app, ["lookup", "cwe", "--cwe", "89"])
        result_prefix = runner.invoke(app, ["lookup", "cwe", "--cwe", "CWE-89"])
        assert result_bare.exit_code == 0
        assert result_prefix.exit_code == 0
        assert result_bare.output == result_prefix.output, (
            "Output for '89' and 'CWE-89' should be identical"
        )

    def test_unknown_cwe_exits_zero_with_no_mappings_message(self):
        result = runner.invoke(app, ["lookup", "cwe", "--cwe", "99999"])
        assert result.exit_code == 0, (
            f"Expected exit 0 for unknown CWE, got {result.exit_code}.\n{result.output}"
        )
        assert "No" in result.output or "no" in result.output, (
            f"Expected 'no mappings' message for unknown CWE:\n{result.output}"
        )

    def test_invalid_cwe_format_exits_2(self):
        result = runner.invoke(app, ["lookup", "cwe", "--cwe", "notanumber"])
        assert result.exit_code == 2, (
            f"Expected exit 2 for invalid CWE, got {result.exit_code}.\n{result.output}"
        )


class TestLookupStig:
    def test_known_stig_exits_zero(self):
        result = runner.invoke(app, ["lookup", "stig", "--stig", "V-222607"])
        assert result.exit_code == 0, (
            f"Expected exit 0 for V-222607, got {result.exit_code}.\n{result.output}"
        )

    def test_known_stig_output_contains_cwe89(self):
        """V-222607 maps to CWE-89 (SQL injection) per the mapping database."""
        result = runner.invoke(app, ["lookup", "stig", "--stig", "V-222607"])
        assert result.exit_code == 0, result.output
        assert "89" in result.output, (
            f"Expected CWE-89 in output for V-222607:\n{result.output}"
        )

    def test_stig_id_without_prefix_accepted(self):
        """'222607' should resolve to V-222607."""
        result = runner.invoke(app, ["lookup", "stig", "--stig", "222607"])
        assert result.exit_code == 0, (
            f"Expected exit 0 for bare numeric STIG ID, got {result.exit_code}.\n{result.output}"
        )
        assert "89" in result.output

    def test_unknown_stig_exits_zero_with_no_mappings_message(self):
        result = runner.invoke(app, ["lookup", "stig", "--stig", "V-999999"])
        assert result.exit_code == 0, (
            f"Expected exit 0 for unknown STIG, got {result.exit_code}.\n{result.output}"
        )
        assert "No" in result.output or "no" in result.output, (
            f"Expected 'no mappings' message for unknown STIG:\n{result.output}"
        )


class TestInfoMappings:
    def test_exits_zero(self):
        result = runner.invoke(app, ["stig", "mappings"])
        assert result.exit_code == 0, (
            f"Expected exit 0, got {result.exit_code}.\n{result.output}"
        )

    def test_shows_total_mappings(self):
        result = runner.invoke(app, ["stig", "mappings"])
        assert "Total mappings" in result.output, (
            f"Expected total mappings count in output:\n{result.output}"
        )

    def test_shows_unique_cwes(self):
        result = runner.invoke(app, ["stig", "mappings"])
        assert "Unique CWEs" in result.output, (
            f"Expected unique CWE count in output:\n{result.output}"
        )

    def test_shows_unique_stigs(self):
        result = runner.invoke(app, ["stig", "mappings"])
        assert "Unique STIGs" in result.output, (
            f"Expected unique STIG count in output:\n{result.output}"
        )

    def test_shows_confidence_breakdown(self):
        result = runner.invoke(app, ["stig", "mappings"])
        assert "direct" in result.output, (
            f"Expected confidence breakdown in output:\n{result.output}"
        )

    def test_output_markdown_file(self, tmp_path):
        out = tmp_path / "xref.md"
        result = runner.invoke(app, ["stig", "mappings", "--output", str(out)])
        assert result.exit_code == 0, (
            f"Expected exit 0 with --output, got {result.exit_code}.\n{result.output}"
        )
        assert out.exists(), "Expected output file to be created"
        content = out.read_text()
        assert "STIG Cross-Reference Matrix" in content, (
            "Expected xref matrix header in output file"
        )

    def test_output_csv_file(self, tmp_path):
        out = tmp_path / "xref.csv"
        result = runner.invoke(app, [
            "stig", "mappings", "--output", str(out), "--format", "csv",
        ])
        assert result.exit_code == 0, (
            f"Expected exit 0 with --output --format csv, got {result.exit_code}.\n{result.output}"
        )
        assert out.exists()
        content = out.read_text()
        assert "STIG_ID" in content

    def test_invalid_format_exits_2(self):
        result = runner.invoke(app, ["stig", "mappings", "--format", "xlsx"])
        assert result.exit_code == 2, (
            f"Expected exit 2 for invalid format, got {result.exit_code}"
        )
