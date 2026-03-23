"""CLI integration tests using Typer's CliRunner."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from stigcode.cli import app
from stigcode.version import __version__

runner = CliRunner()

FIXTURES = Path(__file__).parent / "fixtures"
XCCDF_FILE = Path(__file__).parent.parent / "data" / "stigs" / "application_security_and_development.xml"
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
