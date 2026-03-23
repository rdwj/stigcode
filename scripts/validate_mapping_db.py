#!/usr/bin/env python3
"""Validate the CWE->STIG mapping database against XCCDF and CCI data.

Usage:
    python scripts/validate_mapping_db.py
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

import yaml

# Ensure the package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from stigcode.mapping.engine import load_mapping_database


MAPPING_FILE = Path("data/mappings/asd_stig_v6r3.yaml")
XCCDF_FILE = Path("data/stigs/application_security_and_development.xml")
CCI_FILE = Path("data/cci/cci_to_nist.yaml")
NS = {"xccdf": "http://checklists.nist.gov/xccdf/1.1"}


def load_xccdf_stig_ids() -> set[str]:
    """Extract all STIG V-IDs (new format) from the XCCDF file."""
    tree = ET.parse(XCCDF_FILE)
    root = tree.getroot()
    return {
        group.get("id")
        for group in root.findall(".//xccdf:Group", NS)
        if group.get("id")
    }


def load_cci_ids() -> set[str]:
    """Extract all CCI IDs from the CCI-to-NIST mapping file."""
    with open(CCI_FILE) as f:
        data = yaml.safe_load(f)
    return set(data["mappings"].keys())


def main() -> int:
    errors: list[str] = []

    # Step 1: Load the mapping database
    print(f"Loading mapping database: {MAPPING_FILE}")
    db = load_mapping_database(MAPPING_FILE)

    # Step 2: Load reference data
    xccdf_ids = load_xccdf_stig_ids()
    cci_ids = load_cci_ids()

    print(f"XCCDF contains {len(xccdf_ids)} STIG findings")
    print(f"CCI file contains {len(cci_ids)} CCI entries")
    print()

    # Step 3: Verify all STIG IDs in mappings exist in XCCDF
    mapping_stig_ids = db.all_stig_ids()
    missing_stigs = mapping_stig_ids - xccdf_ids
    if missing_stigs:
        errors.append(
            f"STIG IDs in mappings not found in XCCDF: {sorted(missing_stigs)}"
        )
    else:
        print("OK: All STIG IDs in mappings exist in the XCCDF")

    # Step 4: Verify all CCI refs match the CCI->NIST data
    all_cci_in_mappings: set[str] = set()
    for m in db.mappings:
        all_cci_in_mappings.update(m.cci_refs)

    missing_cci = all_cci_in_mappings - cci_ids
    if missing_cci:
        # Some newer CCI IDs may not be in the v2 file — warn, don't error
        print(
            f"WARN: {len(missing_cci)} CCI ref(s) in mappings not in CCI-to-NIST file: "
            f"{sorted(missing_cci)}"
        )
    else:
        print("OK: All CCI refs in mappings exist in the CCI-to-NIST file")

    # Step 5: Summary stats
    confidence_counts = Counter(m.confidence for m in db.mappings)

    print()
    print("=== SUMMARY ===")
    print(f"Total mappings:  {len(db.mappings)}")
    print(f"Unique CWEs:     {len(db.all_cwe_ids())}")
    print(f"Unique STIGs:    {len(mapping_stig_ids)}")
    print(f"By confidence:")
    for level in ("direct", "inferred", "partial"):
        print(f"  {level:12s}: {confidence_counts.get(level, 0)}")

    # Step 6: Print CWE coverage highlights
    print()
    print("=== CWE COVERAGE HIGHLIGHTS ===")
    highlight_cwes = [89, 79, 78, 22, 611, 798, 327, 311, 319, 120, 352, 362]
    for cwe in highlight_cwes:
        results = db.lookup_by_cwe(cwe)
        if results:
            stig_list = ", ".join(m.stig_id for m in results)
            print(f"  CWE-{cwe:4d}: {len(results)} mapping(s) -> {stig_list}")
        else:
            print(f"  CWE-{cwe:4d}: (no mappings)")

    if errors:
        print()
        print("=== ERRORS ===")
        for err in errors:
            print(f"  ERROR: {err}")
        return 1

    print()
    print("Validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
