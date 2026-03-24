"""Runtime data loading for stigcode.

Provides access to the mapping databases, STIG profiles, and CCI-NIST tables
that ship alongside the package.  The authoritative data lives inside this
package directory (``src/stigcode/data/``) so it is correctly included in both
editable installs and standard ``pip install`` deployments.

The top-level ``data/`` directory at the repo root is kept as a reference
copy for human browsing but is *not* used at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from pathlib import Path

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
# STIG profile registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StigProfile:
    """A registered STIG profile from the registry."""

    key: str                    # short name: "asd"
    name: str                   # "Application Security and Development"
    version: str                # "V6R3"
    mapping_file: Path          # absolute path to mapping YAML
    classifications_file: Path  # absolute path to classifications YAML
    xccdf_file: Path | None     # absolute path to XCCDF XML, if available
    description: str


@cache
def _load_registry() -> dict:
    """Load and cache the raw registry YAML."""
    registry_path = get_data_dir() / "registry.yaml"
    if not registry_path.exists():
        raise FileNotFoundError(
            f"STIG registry not found: {registry_path}. "
            "Ensure data/registry.yaml is present in the package."
        )
    raw = registry_path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    if not isinstance(data, dict) or "stigs" not in data:
        raise ValueError(
            f"Invalid registry file {registry_path}: "
            "expected a YAML mapping with a 'stigs' key."
        )
    return data


def _build_profile(key: str, entry: dict) -> StigProfile:
    """Build a StigProfile from a registry entry dict."""
    data_dir = get_data_dir()

    xccdf_rel = entry.get("xccdf_file")
    xccdf_path = data_dir / xccdf_rel if xccdf_rel else None

    return StigProfile(
        key=key,
        name=entry["name"],
        version=entry["version"],
        mapping_file=data_dir / entry["mapping_file"],
        classifications_file=data_dir / entry["classifications_file"],
        xccdf_file=xccdf_path,
        description=entry.get("description", ""),
    )


def get_available_stigs() -> dict[str, StigProfile]:
    """Load the STIG registry and return all available profiles.

    Returns:
        A dict mapping short keys (e.g. ``"asd"``) to ``StigProfile`` objects.

    Raises:
        FileNotFoundError: if the registry file is missing.
        ValueError: if the registry is malformed.
    """
    registry = _load_registry()
    return {
        key: _build_profile(key, entry)
        for key, entry in registry["stigs"].items()
    }


def get_default_stig_key() -> str:
    """Return the default STIG key from the registry."""
    registry = _load_registry()
    return str(registry.get("default", "asd"))


def get_stig_profile(key: str | None = None) -> StigProfile:
    """Get a specific STIG profile by key, or the default.

    Args:
        key: Short name like ``"asd"``. If ``None``, returns the default profile.

    Raises:
        KeyError: if the requested key is not in the registry.
        FileNotFoundError: if the registry file is missing.
    """
    if key is None:
        key = get_default_stig_key()

    profiles = get_available_stigs()
    if key not in profiles:
        available = ", ".join(sorted(profiles.keys()))
        raise KeyError(
            f"Unknown STIG profile '{key}'. Available profiles: {available}"
        )
    return profiles[key]


# ---------------------------------------------------------------------------
# Mapping database
# ---------------------------------------------------------------------------

_DEFAULT_MAPPING_FILENAME = "asd_stig_v6r3.yaml"


@cache
def get_mapping_database(
    filename: str | None = None,
    *,
    stig_key: str | None = None,
) -> MappingDatabase:
    """Load and cache a CWE-STIG mapping database.

    Resolution order:

    1. If *filename* is provided, load ``data/mappings/<filename>`` directly
       (backwards compatible with existing callers).
    2. If *stig_key* is provided, look up the profile and use its mapping file.
    3. Otherwise, use the default profile's mapping file.

    Args:
        filename: Mapping file name within ``data/mappings/``.
        stig_key: STIG profile key (e.g. ``"asd"``).

    Raises:
        FileNotFoundError: if the mapping file or data directory is missing.
        ValueError: if the mapping file is structurally invalid.
        KeyError: if *stig_key* is not a registered profile.
    """
    if filename is not None:
        mapping_path = get_data_dir() / "mappings" / filename
    elif stig_key is not None:
        profile = get_stig_profile(stig_key)
        mapping_path = profile.mapping_file
    else:
        profile = get_stig_profile()
        mapping_path = profile.mapping_file
    return load_mapping_database(mapping_path)


# ---------------------------------------------------------------------------
# CCI-NIST mappings
# ---------------------------------------------------------------------------

@cache
def get_cci_mappings() -> dict[str, str]:
    """Load CCI-NIST 800-53 control mappings.

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
