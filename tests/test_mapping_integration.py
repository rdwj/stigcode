"""Integration tests for the production CWE->STIG mapping database.

These tests validate the real asd_stig_v6r3.yaml mapping file against
the XCCDF source data and verify key CWE lookups work correctly.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from stigcode.data import get_data_dir
from stigcode.mapping.engine import MappingDatabase, load_mapping_database

_DATA_DIR = get_data_dir()
MAPPING_FILE = _DATA_DIR / "mappings" / "asd_stig_v6r3.yaml"
XCCDF_FILE = _DATA_DIR / "stigs" / "application_security_and_development.xml"
XCCDF_NS = {"xccdf": "http://checklists.nist.gov/xccdf/1.1"}

VALID_CONFIDENCE_LEVELS = {"direct", "inferred", "partial"}


@pytest.fixture(scope="module")
def mapping_db() -> MappingDatabase:
    """Load the production mapping database (once per test module)."""
    return load_mapping_database(MAPPING_FILE)


@pytest.fixture(scope="module")
def xccdf_stig_ids() -> set[str]:
    """Extract all V-IDs from the XCCDF file."""
    tree = ET.parse(XCCDF_FILE)
    root = tree.getroot()
    return {
        group.get("id")
        for group in root.findall(".//xccdf:Group", XCCDF_NS)
        if group.get("id")
    }


# ---------------------------------------------------------------------------
# Basic loading
# ---------------------------------------------------------------------------


def test_mapping_file_loads_successfully(mapping_db: MappingDatabase) -> None:
    assert mapping_db.version == "1.0.0"
    assert mapping_db.stig_name == "Application Security and Development"
    assert mapping_db.stig_version == "V6R3"
    assert len(mapping_db.mappings) > 0


def test_mapping_db_has_reasonable_coverage(mapping_db: MappingDatabase) -> None:
    """The database should cover all 80 SAST-assessable findings."""
    assert len(mapping_db.all_stig_ids()) == 80, (
        f"Expected 80 unique STIGs, got {len(mapping_db.all_stig_ids())}"
    )


# ---------------------------------------------------------------------------
# Well-known CWE lookups
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cwe_id, description",
    [
        (89, "SQL Injection"),
        (79, "Cross-Site Scripting"),
        (78, "OS Command Injection"),
        (352, "Cross-Site Request Forgery"),
        (120, "Buffer Overflow"),
        (190, "Integer Overflow"),
        (327, "Use of Broken Crypto"),
        (319, "Cleartext Transmission"),
        (311, "Missing Encryption"),
        (362, "Race Condition"),
        (384, "Session Fixation"),
        (614, "Cookie without Secure Flag"),
        (1004, "Cookie without HttpOnly"),
        (20, "Improper Input Validation"),
        (611, "XML External Entity"),
        (400, "Uncontrolled Resource Consumption"),
    ],
)
def test_well_known_cwe_has_mapping(
    mapping_db: MappingDatabase, cwe_id: int, description: str
) -> None:
    results = mapping_db.lookup_by_cwe(cwe_id)
    assert len(results) >= 1, (
        f"CWE-{cwe_id} ({description}) should have at least one STIG mapping, got 0"
    )


def test_cwe_89_maps_to_sql_injection_stig(mapping_db: MappingDatabase) -> None:
    """CWE-89 (SQL injection) must map to V-222607 directly."""
    results = mapping_db.lookup_by_cwe(89)
    stig_ids = {m.stig_id for m in results}
    assert "V-222607" in stig_ids, (
        f"CWE-89 should map to V-222607 (SQL injection finding), got: {stig_ids}"
    )
    # The direct mapping should have 'direct' confidence
    direct = [m for m in results if m.stig_id == "V-222607"]
    assert direct[0].confidence == "direct"


def test_cwe_79_maps_to_xss_stig(mapping_db: MappingDatabase) -> None:
    """CWE-79 (XSS) must map to V-222602 directly."""
    results = mapping_db.lookup_by_cwe(79)
    stig_ids = {m.stig_id for m in results}
    assert "V-222602" in stig_ids, (
        f"CWE-79 should map to V-222602 (XSS finding), got: {stig_ids}"
    )


def test_cwe_798_maps_to_credential_stig(mapping_db: MappingDatabase) -> None:
    """CWE-798 (hardcoded credentials) must map to at least one STIG."""
    results = mapping_db.lookup_by_cwe(798)
    assert len(results) >= 1, "CWE-798 should have at least one STIG mapping"


# ---------------------------------------------------------------------------
# Cross-reference with XCCDF
# ---------------------------------------------------------------------------


def test_all_mapping_stig_ids_exist_in_xccdf(
    mapping_db: MappingDatabase, xccdf_stig_ids: set[str]
) -> None:
    """Every STIG ID in the mapping database must exist in the XCCDF."""
    mapping_ids = mapping_db.all_stig_ids()
    missing = mapping_ids - xccdf_stig_ids
    assert not missing, (
        f"STIG IDs in mapping database not found in XCCDF: {sorted(missing)}"
    )


# ---------------------------------------------------------------------------
# Confidence values
# ---------------------------------------------------------------------------


def test_all_confidence_values_are_valid(mapping_db: MappingDatabase) -> None:
    """Every mapping must have a valid confidence level."""
    invalid = [
        (m.cwe_id, m.stig_id, m.confidence)
        for m in mapping_db.mappings
        if m.confidence not in VALID_CONFIDENCE_LEVELS
    ]
    assert not invalid, (
        f"Found mappings with invalid confidence: {invalid}"
    )


def test_confidence_distribution_is_reasonable(mapping_db: MappingDatabase) -> None:
    """Direct mappings should be the majority; partial should be the minority."""
    from collections import Counter

    counts = Counter(m.confidence for m in mapping_db.mappings)
    assert counts["direct"] > counts["inferred"], (
        f"Expected more direct than inferred mappings: {dict(counts)}"
    )
    assert counts["direct"] > counts["partial"], (
        f"Expected more direct than partial mappings: {dict(counts)}"
    )


# ---------------------------------------------------------------------------
# Data integrity
# ---------------------------------------------------------------------------


def test_every_mapping_has_notes(mapping_db: MappingDatabase) -> None:
    """Every mapping should have a non-empty notes field explaining the rationale."""
    empty_notes = [
        (m.cwe_id, m.stig_id) for m in mapping_db.mappings if not m.notes.strip()
    ]
    assert not empty_notes, (
        f"Found {len(empty_notes)} mapping(s) without notes: {empty_notes[:5]}..."
    )


def test_every_mapping_has_cci_refs(mapping_db: MappingDatabase) -> None:
    """Every mapping should have at least one CCI reference."""
    missing_cci = [
        (m.cwe_id, m.stig_id) for m in mapping_db.mappings if not m.cci_refs
    ]
    assert not missing_cci, (
        f"Found {len(missing_cci)} mapping(s) without CCI refs: {missing_cci[:5]}..."
    )


def test_every_mapping_has_check_id(mapping_db: MappingDatabase) -> None:
    """Every mapping should have an APSC-DV check ID."""
    missing = [
        (m.cwe_id, m.stig_id) for m in mapping_db.mappings if not m.check_id
    ]
    assert not missing, (
        f"Found {len(missing)} mapping(s) without check_id: {missing[:5]}..."
    )


def test_check_ids_follow_apsc_format(mapping_db: MappingDatabase) -> None:
    """Check IDs should follow the APSC-DV-XXXXXX format."""
    import re

    pattern = re.compile(r"^APSC-DV-\d{6}$")
    bad = [
        (m.cwe_id, m.stig_id, m.check_id)
        for m in mapping_db.mappings
        if not pattern.match(m.check_id)
    ]
    assert not bad, (
        f"Found {len(bad)} mapping(s) with malformed check_id: {bad[:5]}..."
    )
