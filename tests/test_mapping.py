"""Tests for the CWE→STIG mapping engine."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from stigcode.mapping.engine import (
    MappingDatabase,
    StigMapping,
    load_mapping_database,
    save_mapping_database,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "mappings" / "test_mappings.yaml"


@pytest.fixture()
def db() -> MappingDatabase:
    """Load the shared test mapping database."""
    return load_mapping_database(FIXTURE_PATH)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def test_load_valid_file(db: MappingDatabase) -> None:
    assert db.version == "1.0.0"
    assert db.stig_name == "Application Security and Development"
    assert db.stig_version == "V6R3"
    assert len(db.mappings) == 8


def test_load_normalises_v_prefix(tmp_path: Path) -> None:
    """stig_id without V- prefix should be normalised on load."""
    data = {
        "version": "1.0.0",
        "stig_name": "Test",
        "stig_version": "V1",
        "mappings": [
            {
                "cwe_id": 89,
                "stig_id": "222607",        # no V- prefix
                "check_id": "APSC-DV-002540",
                "confidence": "direct",
                "nist_control": "SI-10",
            }
        ],
    }
    p = tmp_path / "m.yaml"
    p.write_text(yaml.dump(data))
    loaded = load_mapping_database(p)
    assert loaded.mappings[0].stig_id == "V-222607"


def test_load_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="not found"):
        load_mapping_database(tmp_path / "nonexistent.yaml")


def test_load_malformed_yaml(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("key: [unclosed bracket\n")
    with pytest.raises(ValueError, match="YAML parse error"):
        load_mapping_database(bad)


@pytest.mark.parametrize("missing_key", ["version", "stig_name", "stig_version", "mappings"])
def test_load_missing_top_level_key(tmp_path: Path, missing_key: str) -> None:
    data: dict = {
        "version": "1.0.0",
        "stig_name": "Test",
        "stig_version": "V1",
        "mappings": [],
    }
    del data[missing_key]
    p = tmp_path / "m.yaml"
    p.write_text(yaml.dump(data))
    with pytest.raises(ValueError, match=missing_key):
        load_mapping_database(p)


def test_load_invalid_confidence(tmp_path: Path) -> None:
    data = {
        "version": "1.0.0",
        "stig_name": "Test",
        "stig_version": "V1",
        "mappings": [
            {
                "cwe_id": 89,
                "stig_id": "V-999999",
                "check_id": "APSC-DV-000001",
                "confidence": "unknown_level",
                "nist_control": "SI-10",
            }
        ],
    }
    p = tmp_path / "m.yaml"
    p.write_text(yaml.dump(data))
    with pytest.raises(ValueError, match="confidence"):
        load_mapping_database(p)


def test_load_missing_mapping_key(tmp_path: Path) -> None:
    data = {
        "version": "1.0.0",
        "stig_name": "Test",
        "stig_version": "V1",
        "mappings": [
            {
                "cwe_id": 89,
                # stig_id intentionally omitted
                "check_id": "APSC-DV-002540",
                "confidence": "direct",
                "nist_control": "SI-10",
            }
        ],
    }
    p = tmp_path / "m.yaml"
    p.write_text(yaml.dump(data))
    with pytest.raises(ValueError, match="stig_id"):
        load_mapping_database(p)


# ---------------------------------------------------------------------------
# lookup_by_cwe
# ---------------------------------------------------------------------------

def test_lookup_by_cwe_known(db: MappingDatabase) -> None:
    results = db.lookup_by_cwe(79)
    stig_ids = {m.stig_id for m in results}
    assert stig_ids == {"V-222609", "V-222610"}, (
        f"Expected two STIG mappings for CWE-79, got: {stig_ids}"
    )


def test_lookup_by_cwe_single_result(db: MappingDatabase) -> None:
    results = db.lookup_by_cwe(89)
    assert len(results) == 1
    assert results[0].stig_id == "V-222607"
    assert results[0].confidence == "direct"
    assert results[0].nist_control == "SI-10"
    assert results[0].cci_refs == ["CCI-002754"]


def test_lookup_by_cwe_unknown_returns_empty(db: MappingDatabase) -> None:
    assert db.lookup_by_cwe(9999) == []


# ---------------------------------------------------------------------------
# lookup_by_stig
# ---------------------------------------------------------------------------

def test_lookup_by_stig_with_prefix(db: MappingDatabase) -> None:
    results = db.lookup_by_stig("V-222596")
    cwe_ids = {m.cwe_id for m in results}
    assert cwe_ids == {326, 327}, f"Expected CWE-326 and CWE-327, got: {cwe_ids}"


def test_lookup_by_stig_without_prefix(db: MappingDatabase) -> None:
    # Should work identically to the V- prefixed form
    with_prefix = db.lookup_by_stig("V-222596")
    without_prefix = db.lookup_by_stig("222596")
    assert with_prefix == without_prefix


def test_lookup_by_stig_unknown_returns_empty(db: MappingDatabase) -> None:
    assert db.lookup_by_stig("V-000000") == []


# ---------------------------------------------------------------------------
# all_cwe_ids / all_stig_ids
# ---------------------------------------------------------------------------

def test_all_cwe_ids(db: MappingDatabase) -> None:
    cwe_ids = db.all_cwe_ids()
    assert isinstance(cwe_ids, set)
    assert {89, 79, 22, 798, 326, 327, 306} <= cwe_ids


def test_all_stig_ids(db: MappingDatabase) -> None:
    stig_ids = db.all_stig_ids()
    assert isinstance(stig_ids, set)
    # All IDs must carry the V- prefix
    assert all(s.startswith("V-") for s in stig_ids), (
        f"Found STIG IDs without V- prefix: {[s for s in stig_ids if not s.startswith('V-')]}"
    )
    assert "V-222596" in stig_ids


# ---------------------------------------------------------------------------
# Save / load round-trip
# ---------------------------------------------------------------------------

def test_roundtrip(db: MappingDatabase, tmp_path: Path) -> None:
    out = tmp_path / "roundtrip.yaml"
    save_mapping_database(db, out)
    reloaded = load_mapping_database(out)

    assert reloaded.version == db.version
    assert reloaded.stig_name == db.stig_name
    assert reloaded.stig_version == db.stig_version
    assert len(reloaded.mappings) == len(db.mappings)

    original_by_key = {(m.cwe_id, m.stig_id): m for m in db.mappings}
    for m in reloaded.mappings:
        key = (m.cwe_id, m.stig_id)
        assert key in original_by_key, f"Mapping {key} lost after round-trip"
        orig = original_by_key[key]
        assert m.confidence == orig.confidence
        assert m.nist_control == orig.nist_control
        assert m.cci_refs == orig.cci_refs
        assert m.notes == orig.notes


def test_save_creates_parent_dirs(db: MappingDatabase, tmp_path: Path) -> None:
    out = tmp_path / "nested" / "deep" / "mappings.yaml"
    save_mapping_database(db, out)
    assert out.exists()


# ---------------------------------------------------------------------------
# StigMapping dataclass edge cases
# ---------------------------------------------------------------------------

def test_stig_mapping_default_fields() -> None:
    m = StigMapping(
        cwe_id=89,
        stig_id="V-222607",
        check_id="APSC-DV-002540",
        confidence="direct",
        nist_control="SI-10",
    )
    assert m.cci_refs == []
    assert m.notes == ""
