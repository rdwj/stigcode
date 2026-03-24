"""Runtime data loading for stigcode.

Provides access to the mapping databases and CCI→NIST tables that ship
alongside the package.  The authoritative data lives inside this package
directory (``src/stigcode/data/``) so it is correctly included in both
editable installs and standard ``pip install`` deployments.

The top-level ``data/`` directory at the repo root is kept as a reference
copy for human browsing but is *not* used at runtime.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

import yaml

from stigcode.mapping.engine import MappingDatabase, load_mapping_database

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

# Resolved relative to *this* file so it works in both editable installs
# (where __file__ points into src/stigcode/data/) and standard pip installs
# (where __file__ points into site-packages/stigcode/data/).
_DATA_DIR = Path(__file__).parent


def get_data_dir() -> Path:
    """Return the path to the package's bundled ``data/`` directory.

    Raises:
        FileNotFoundError: if the directory cannot be located.
    """
    if _DATA_DIR.is_dir():
        return _DATA_DIR
    raise FileNotFoundError(
        f"Could not locate the stigcode data directory. "
        f"Expected it at: {_DATA_DIR}"
    )


# ---------------------------------------------------------------------------
# Mapping database
# ---------------------------------------------------------------------------

_DEFAULT_MAPPING_FILENAME = "asd_stig_v6r3.yaml"


@lru_cache(maxsize=None)
def get_mapping_database(filename: Optional[str] = None) -> MappingDatabase:
    """Load and cache the default CWE→STIG mapping database.

    Args:
        filename: Optional override for the mapping file name within
                  ``data/mappings/``. Defaults to the bundled ASD STIG V6R3
                  mapping file.

    Raises:
        FileNotFoundError: if the mapping file or data directory is missing.
        ValueError: if the mapping file is structurally invalid.
    """
    name = filename or _DEFAULT_MAPPING_FILENAME
    mapping_path = get_data_dir() / "mappings" / name
    return load_mapping_database(mapping_path)


# ---------------------------------------------------------------------------
# CCI→NIST mappings
# ---------------------------------------------------------------------------

@lru_cache(maxsize=None)
def get_cci_mappings() -> dict[str, str]:
    """Load CCI→NIST 800-53 control mappings.

    Returns a dict of ``{CCI-XXXXXX: "SI-10", ...}``.

    Raises:
        FileNotFoundError: if the CCI data directory or mapping file is missing.
        ValueError: if the CCI file cannot be parsed.
    """
    cci_dir = get_data_dir() / "cci"
    cci_file = cci_dir / "cci_to_nist.yaml"

    if not cci_file.exists():
        raise FileNotFoundError(
            f"CCI mapping file not found: {cci_file}. "
            "Ensure data/cci/cci_to_nist.yaml is present in the package."
        )

    raw = cci_file.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(raw)
    except Exception as exc:
        raise ValueError(f"Failed to parse CCI mapping file {cci_file}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(
            f"CCI mapping file {cci_file} must contain a YAML mapping at top level"
        )
    return {str(k): str(v) for k, v in data.items()}
