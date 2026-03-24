#!/usr/bin/env python3
"""Offline operation verification for stigcode.

Verifies that all bundled data is accessible and that a minimal parse→map
pipeline completes successfully without any network I/O.

Run from the repo root with the venv active:
    python scripts/verify_offline.py

This is also used as part of container smoke-test logic to confirm the
package data landed correctly inside the image.
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path


def check(description: str) -> None:
    print(f"  checking: {description} ...", end=" ", flush=True)


def ok() -> None:
    print("ok")


def fail(msg: str) -> None:
    print(f"FAILED\n    {msg}")
    sys.exit(1)


def main() -> None:
    print("Stigcode offline verification")
    print("=" * 40)

    # ------------------------------------------------------------------
    # 1. Data directory
    # ------------------------------------------------------------------
    check("data directory accessible via get_data_dir()")
    try:
        from stigcode.data import get_data_dir
        data_dir = get_data_dir()
        if not data_dir.is_dir():
            fail(f"get_data_dir() returned {data_dir} which is not a directory")
    except Exception as exc:
        fail(f"{exc}\n{traceback.format_exc()}")
    ok()

    # ------------------------------------------------------------------
    # 2. Expected data files present
    # ------------------------------------------------------------------
    expected_files: list[tuple[str, Path]] = [
        ("CWE→STIG mapping (ASD STIG v6r3)", data_dir / "mappings" / "asd_stig_v6r3.yaml"),
        ("finding classifications", data_dir / "mappings" / "finding_classifications.yaml"),
        ("CCI→NIST mappings", data_dir / "cci" / "cci_to_nist.yaml"),
        ("AppDev STIG XCCDF", data_dir / "stigs" / "application_security_and_development.xml"),
    ]

    for description, path in expected_files:
        check(f"{description} present at {path.relative_to(data_dir.parent)}")
        if not path.is_file():
            fail(f"Missing: {path}")
        if path.stat().st_size == 0:
            fail(f"Empty file: {path}")
        ok()

    # ------------------------------------------------------------------
    # 3. Mapping database loads cleanly
    # ------------------------------------------------------------------
    check("CWE→STIG mapping database loads and parses")
    try:
        from stigcode.data import get_mapping_database
        db = get_mapping_database()
        if not db.mappings:
            fail("Mapping database loaded but contains no records")
        mapping_count = len(db.mappings)
        cwe_count = len(db.all_cwe_ids())
        stig_count = len(db.all_stig_ids())
    except Exception as exc:
        fail(f"{exc}\n{traceback.format_exc()}")
    ok()
    print(f"    {mapping_count} mappings, {cwe_count} CWE IDs, {stig_count} STIG V-IDs")

    # ------------------------------------------------------------------
    # 4. CCI→NIST mappings load cleanly
    # ------------------------------------------------------------------
    check("CCI→NIST mappings load and parse")
    try:
        from stigcode.data import get_cci_mappings
        cci = get_cci_mappings()
        if not cci:
            fail("CCI mappings loaded but the dict is empty")
        cci_count = len(cci)
    except Exception as exc:
        fail(f"{exc}\n{traceback.format_exc()}")
    ok()
    print(f"    {cci_count} CCI entries")

    # ------------------------------------------------------------------
    # 5. SARIF parse → mapping lookup pipeline
    # ------------------------------------------------------------------
    # Use a fixture SARIF that has a CWE tag so we exercise the full path.
    fixture = Path(__file__).parent.parent / "tests" / "fixtures" / "sarif" / "cwe_in_tags.sarif"
    check(f"parse SARIF fixture ({fixture.name})")
    try:
        from stigcode.ingest.sarif import parse_sarif
        result = parse_sarif(fixture)
        if result.errors:
            fail(f"parse_sarif reported errors: {result.errors}")
        if not result.findings:
            fail(f"parse_sarif returned no findings from {fixture}")
    except Exception as exc:
        fail(f"{exc}\n{traceback.format_exc()}")
    ok()
    print(f"    {len(result.findings)} finding(s) from {result.scanner_name or 'unknown scanner'}")

    # ------------------------------------------------------------------
    # 6. CWE lookup on parsed findings
    # ------------------------------------------------------------------
    check("CWE→STIG lookup on parsed findings")
    try:
        hits: list[str] = []
        for finding in result.findings:
            for cwe_id in finding.cwe_ids:
                mapped = db.lookup_by_cwe(int(cwe_id))
                for m in mapped:
                    hits.append(f"CWE-{cwe_id} → {m.stig_id} [{m.confidence}]")
    except Exception as exc:
        fail(f"{exc}\n{traceback.format_exc()}")
    ok()
    if hits:
        for hit in hits[:3]:
            print(f"    {hit}")
        if len(hits) > 3:
            print(f"    ... and {len(hits) - 3} more")
    else:
        print("    (no CWE→STIG mappings matched — fixture CWEs may not be in database)")

    # ------------------------------------------------------------------
    # Done
    # ------------------------------------------------------------------
    print()
    print("Offline verification passed.")


if __name__ == "__main__":
    main()
