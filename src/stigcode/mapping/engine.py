"""CWE→STIG mapping engine.

Loads YAML mapping databases and provides bidirectional lookups between
CWE identifiers and DISA STIG finding IDs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class StigMapping:
    """A single CWE→STIG mapping record."""

    cwe_id: int
    stig_id: str          # V-XXXXXX
    check_id: str         # APSC-DV-XXXXXX
    confidence: str       # direct | inferred | partial
    nist_control: str     # e.g. "SI-10"
    cci_refs: list[str] = field(default_factory=list)
    notes: str = ""

    VALID_CONFIDENCE = frozenset({"direct", "inferred", "partial"})

    def __post_init__(self) -> None:
        if self.confidence not in self.VALID_CONFIDENCE:
            raise ValueError(
                f"Invalid confidence '{self.confidence}' for CWE-{self.cwe_id}/"
                f"{self.stig_id}. Must be one of: {sorted(self.VALID_CONFIDENCE)}"
            )
        # Normalise stig_id to always carry the V- prefix
        if not self.stig_id.startswith("V-"):
            self.stig_id = f"V-{self.stig_id}"


@dataclass
class MappingDatabase:
    """The loaded CWE→STIG mapping database."""

    mappings: list[StigMapping]
    version: str
    stig_name: str
    stig_version: str

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def lookup_by_cwe(self, cwe_id: int) -> list[StigMapping]:
        """Return all STIG mappings for a CWE ID. Returns [] if not found."""
        return [m for m in self.mappings if m.cwe_id == cwe_id]

    def lookup_by_stig(self, stig_id: str) -> list[StigMapping]:
        """Return all CWE mappings for a STIG V-ID.

        Accepts the ID with or without the ``V-`` prefix.
        """
        normalized = stig_id if stig_id.startswith("V-") else f"V-{stig_id}"
        return [m for m in self.mappings if m.stig_id == normalized]

    def all_cwe_ids(self) -> set[int]:
        """All CWE IDs present in the database."""
        return {m.cwe_id for m in self.mappings}

    def all_stig_ids(self) -> set[str]:
        """All STIG V-IDs present in the database."""
        return {m.stig_id for m in self.mappings}


# ---------------------------------------------------------------------------
# YAML schema helpers
# ---------------------------------------------------------------------------

_REQUIRED_TOP_KEYS = {"version", "stig_name", "stig_version", "mappings"}
_REQUIRED_MAPPING_KEYS = {"cwe_id", "stig_id", "check_id", "confidence", "nist_control"}


def _validate_top(data: Any, path: Path) -> None:
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping at top level, got {type(data).__name__}")
    missing = _REQUIRED_TOP_KEYS - data.keys()
    if missing:
        raise ValueError(f"{path}: missing required top-level keys: {sorted(missing)}")
    if not isinstance(data["mappings"], list):
        raise ValueError(f"{path}: 'mappings' must be a list")


def _validate_mapping_record(record: Any, index: int, path: Path) -> None:
    if not isinstance(record, dict):
        raise ValueError(f"{path}: mappings[{index}] must be a mapping, got {type(record).__name__}")
    missing = _REQUIRED_MAPPING_KEYS - record.keys()
    if missing:
        raise ValueError(
            f"{path}: mappings[{index}] missing required keys: {sorted(missing)}"
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_mapping_database(path: Path) -> MappingDatabase:
    """Load a CWE→STIG mapping database from a YAML file.

    Raises:
        FileNotFoundError: if *path* does not exist.
        ValueError: if the file is structurally invalid or contains bad data.
        yaml.YAMLError: if the file cannot be parsed as YAML.
    """
    if not path.exists():
        raise FileNotFoundError(f"Mapping file not found: {path}")

    raw_text = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: YAML parse error — {exc}") from exc

    _validate_top(data, path)

    mappings: list[StigMapping] = []
    for i, record in enumerate(data["mappings"]):
        _validate_mapping_record(record, i, path)
        try:
            mappings.append(
                StigMapping(
                    cwe_id=int(record["cwe_id"]),
                    stig_id=str(record["stig_id"]),
                    check_id=str(record["check_id"]),
                    confidence=str(record["confidence"]),
                    nist_control=str(record["nist_control"]),
                    cci_refs=[str(c) for c in (record.get("cci_refs") or [])],
                    notes=str(record.get("notes") or ""),
                )
            )
        except (ValueError, TypeError) as exc:
            raise ValueError(f"{path}: mappings[{i}] — {exc}") from exc

    return MappingDatabase(
        mappings=mappings,
        version=str(data["version"]),
        stig_name=str(data["stig_name"]),
        stig_version=str(data["stig_version"]),
    )


def save_mapping_database(db: MappingDatabase, path: Path) -> None:
    """Serialise a MappingDatabase back to a YAML file.

    Creates parent directories if they do not exist.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    data: dict[str, Any] = {
        "version": db.version,
        "stig_name": db.stig_name,
        "stig_version": db.stig_version,
        "mappings": [
            {
                "cwe_id": m.cwe_id,
                "stig_id": m.stig_id,
                "check_id": m.check_id,
                "confidence": m.confidence,
                "nist_control": m.nist_control,
                "cci_refs": m.cci_refs,
                "notes": m.notes,
            }
            for m in db.mappings
        ],
    }

    path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False), encoding="utf-8")
