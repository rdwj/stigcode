#!/usr/bin/env python3
"""Fix V-ID keys in finding_classifications.yaml.

The file was originally created with legacy V-IDs (e.g. V-69239) as keys.
The rest of the codebase uses current V-IDs (e.g. V-222387), which are the
Group id attributes in the XCCDF file. This mismatch causes determine_status
to never match classification data to findings.

This script:
1. Parses the XCCDF to build a legacy V-ID → current V-ID mapping.
2. Rewrites finding_classifications.yaml with current V-IDs as keys,
   preserving all classification data (title, assessment_method, rationale).

Any legacy V-IDs with no corresponding current V-ID in the XCCDF are
reported as warnings and dropped.

Usage:
    python scripts/fix_classification_vids.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import defusedxml.ElementTree as ET
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
XCCDF_PATH = REPO_ROOT / "data" / "stigs" / "application_security_and_development.xml"
CLASSIFICATIONS_PATH = REPO_ROOT / "data" / "mappings" / "finding_classifications.yaml"

NS = "http://checklists.nist.gov/xccdf/1.1"


def build_legacy_to_current_map(xccdf_path: Path) -> dict[str, str]:
    """Parse XCCDF and return {legacy_vid: current_vid}."""
    tree = ET.parse(str(xccdf_path))
    root = tree.getroot()

    mapping: dict[str, str] = {}
    for group_el in root.findall(f"{{{NS}}}Group"):
        current_id = group_el.get("id", "")
        if not current_id:
            continue

        rule_el = group_el.find(f"{{{NS}}}Rule")
        if rule_el is None:
            continue

        for ident_el in rule_el.findall(f"{{{NS}}}ident"):
            system = ident_el.get("system", "")
            value = (ident_el.text or "").strip()
            if system == "http://cyber.mil/legacy" and value.startswith("V-"):
                mapping[value] = current_id

    return mapping


def rewrite_classifications(
    classifications_path: Path,
    legacy_to_current: dict[str, str],
) -> tuple[int, int, list[str]]:
    """Rewrite the YAML file with current V-IDs as keys.

    Returns:
        (remapped_count, skipped_count, skipped_ids)
    """
    with open(classifications_path) as f:
        doc = yaml.safe_load(f)

    old_classifications: dict = doc.get("classifications", {})
    new_classifications: dict = {}
    skipped: list[str] = []

    for old_key, value in old_classifications.items():
        if old_key in legacy_to_current:
            new_key = legacy_to_current[old_key]
            new_classifications[new_key] = value
        else:
            skipped.append(old_key)

    doc["classifications"] = new_classifications

    with open(classifications_path, "w") as f:
        yaml.dump(doc, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

    return len(new_classifications), len(skipped), skipped


def main() -> int:
    if not XCCDF_PATH.exists():
        print(f"ERROR: XCCDF not found: {XCCDF_PATH}", file=sys.stderr)
        return 1

    if not CLASSIFICATIONS_PATH.exists():
        print(f"ERROR: Classifications file not found: {CLASSIFICATIONS_PATH}", file=sys.stderr)
        return 1

    print(f"Parsing XCCDF: {XCCDF_PATH}")
    legacy_to_current = build_legacy_to_current_map(XCCDF_PATH)
    print(f"  Found {len(legacy_to_current)} legacy→current V-ID mappings")

    print(f"\nRewriting: {CLASSIFICATIONS_PATH}")
    remapped, skipped_count, skipped_ids = rewrite_classifications(
        CLASSIFICATIONS_PATH, legacy_to_current
    )

    print(f"  Remapped: {remapped} entries")
    if skipped_ids:
        print(f"  Skipped (no XCCDF match): {skipped_count}")
        for vid in skipped_ids:
            print(f"    - {vid}")
    else:
        print("  No entries skipped")

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
