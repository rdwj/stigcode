"""Stigcode CLI — SARIF-to-compliance bridge.

This package splits the CLI into focused modules:
- commands: top-level commands (report, coverage, poam, ckl, assess, import, version)
- lookup: lookup cwe/stig sub-commands
- info: info mappings sub-command
- stig: stig import-xccdf sub-command
- pipeline: shared pipeline loader
"""

from __future__ import annotations

import typer

DESCRIPTION = "SARIF-to-compliance bridge"
REPO_URL = "https://github.com/rdwj/stigcode"
ISSUES_URL = f"{REPO_URL}/issues"

app = typer.Typer(help=DESCRIPTION, no_args_is_help=True)
lookup_app = typer.Typer(help="Look up STIG/CWE mappings.", no_args_is_help=True)
info_app = typer.Typer(help="Inspect mapping data and metadata.", no_args_is_help=True)
stig_app = typer.Typer(help="Manage STIG benchmark data.", no_args_is_help=True)

app.add_typer(lookup_app, name="lookup")
app.add_typer(info_app, name="info")
app.add_typer(stig_app, name="stig")

# Register commands from submodules. The imports trigger @app.command()
# and @sub_app.command() decorators.
from stigcode.cli import ckl_command as _ckl_command  # noqa: F401, E402
from stigcode.cli import commands as _commands  # noqa: F401, E402
from stigcode.cli import info as _info  # noqa: F401, E402
from stigcode.cli import lookup as _lookup  # noqa: F401, E402
from stigcode.cli import oscal_command as _oscal_command  # noqa: F401, E402
from stigcode.cli import output_commands as _output_commands  # noqa: F401, E402
from stigcode.cli import stig as _stig  # noqa: F401, E402
from stigcode.cli import trend as _trend  # noqa: F401, E402
from stigcode.cli import validate_command as _validate_command  # noqa: F401, E402


def main() -> None:
    """Entry point declared in pyproject.toml."""
    app()
