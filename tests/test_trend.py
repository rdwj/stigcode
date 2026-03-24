"""Tests for the trend analysis module (CA-7 evidence generation)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from stigcode.output.trend import (
    analyze_trend,
    fingerprint,
    load_scan_snapshots,
    trend_to_markdown,
)

FIXTURES = Path(__file__).parent / "fixtures" / "sarif"
SCAN_1 = FIXTURES / "trend_scan_1.sarif"
SCAN_2 = FIXTURES / "trend_scan_2.sarif"

# Expected fingerprints from the fixture files
FP_SQL = fingerprint("sql-injection", "src/app.py", 42)
FP_XSS = fingerprint("xss-reflected", "src/views.py", 88)
FP_KEY = fingerprint("hardcoded-key", "src/config.py", 12)
FP_PATH = fingerprint("path-traversal", "src/files.py", 25)


# ---------------------------------------------------------------------------
# Snapshot loading
# ---------------------------------------------------------------------------

def test_load_scan_snapshots_orders_by_date():
    """Files should be returned oldest-first regardless of argument order."""
    snapshots = load_scan_snapshots([SCAN_2, SCAN_1])  # reversed order
    assert len(snapshots) == 2
    assert snapshots[0].scan_date < snapshots[1].scan_date
    assert snapshots[0].source_file == "trend_scan_1.sarif"
    assert snapshots[1].source_file == "trend_scan_2.sarif"


def test_snapshots_contain_correct_fingerprints():
    snapshots = load_scan_snapshots([SCAN_1, SCAN_2])
    snap1, snap2 = snapshots

    assert FP_SQL in snap1.findings
    assert FP_XSS in snap1.findings
    assert FP_KEY in snap1.findings
    assert FP_PATH not in snap1.findings

    assert FP_SQL in snap2.findings
    assert FP_XSS not in snap2.findings
    assert FP_KEY in snap2.findings
    assert FP_PATH in snap2.findings


# ---------------------------------------------------------------------------
# Fingerprint stability
# ---------------------------------------------------------------------------

def test_fingerprint_stability():
    """Same rule + file + line always produces the same fingerprint."""
    fp1 = fingerprint("sql-injection", "src/app.py", 42)
    fp2 = fingerprint("sql-injection", "src/app.py", 42)
    assert fp1 == fp2


def test_fingerprint_differs_on_line():
    fp1 = fingerprint("rule", "file.py", 10)
    fp2 = fingerprint("rule", "file.py", 11)
    assert fp1 != fp2


def test_fingerprint_differs_on_file():
    fp1 = fingerprint("rule", "a.py", 10)
    fp2 = fingerprint("rule", "b.py", 10)
    assert fp1 != fp2


# ---------------------------------------------------------------------------
# Trend classification
# ---------------------------------------------------------------------------

def test_new_findings_detected():
    """path-traversal appears only in scan 2 → classified as new."""
    snapshots = load_scan_snapshots([SCAN_1, SCAN_2])
    report = analyze_trend(snapshots)
    new_fps = {e.fingerprint for e in report.new_findings}
    assert FP_PATH in new_fps, f"path-traversal not in new_findings: {new_fps}"


def test_remediated_findings_detected():
    """xss-reflected in scan 1 but not scan 2 → classified as remediated."""
    snapshots = load_scan_snapshots([SCAN_1, SCAN_2])
    report = analyze_trend(snapshots)
    rem_fps = {e.fingerprint for e in report.remediated_findings}
    assert FP_XSS in rem_fps, f"xss-reflected not in remediated_findings: {rem_fps}"


def test_persistent_findings_detected():
    """sql-injection and hardcoded-key appear in both scans → persistent."""
    snapshots = load_scan_snapshots([SCAN_1, SCAN_2])
    report = analyze_trend(snapshots)
    per_fps = {e.fingerprint for e in report.persistent_findings}
    assert FP_SQL in per_fps, f"sql-injection not in persistent_findings: {per_fps}"
    assert FP_KEY in per_fps, f"hardcoded-key not in persistent_findings: {per_fps}"


def test_new_finding_not_in_persistent_or_remediated():
    snapshots = load_scan_snapshots([SCAN_1, SCAN_2])
    report = analyze_trend(snapshots)
    other_fps = (
        {e.fingerprint for e in report.persistent_findings}
        | {e.fingerprint for e in report.remediated_findings}
    )
    assert FP_PATH not in other_fps


# ---------------------------------------------------------------------------
# Trend data per scan
# ---------------------------------------------------------------------------

def test_trend_data_per_scan():
    """trend_data should have one row per scan with correct counts."""
    snapshots = load_scan_snapshots([SCAN_1, SCAN_2])
    report = analyze_trend(snapshots)

    assert len(report.trend_data) == 2

    row1, row2 = report.trend_data
    assert row1["total"] == 3
    assert row1["new"] == 3      # first scan: everything is new vs. empty baseline
    assert row1["remediated"] == 0

    assert row2["total"] == 3
    assert row2["new"] == 1      # path-traversal is new
    assert row2["remediated"] == 1  # xss-reflected removed


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------

def test_trend_to_markdown_contains_sections():
    snapshots = load_scan_snapshots([SCAN_1, SCAN_2])
    report = analyze_trend(snapshots)
    md = trend_to_markdown(report)

    assert "# Security Scan Trend Report" in md
    assert "## Summary" in md
    assert "## Trend" in md
    assert "## New Findings" in md
    assert "## Remediated Findings" in md
    assert "## Persistent Findings" in md
    assert "## Assessment" in md
    assert "CA-7" in md


def test_trend_to_markdown_includes_finding_names():
    snapshots = load_scan_snapshots([SCAN_1, SCAN_2])
    report = analyze_trend(snapshots)
    md = trend_to_markdown(report)

    assert "path-traversal" in md
    assert "xss-reflected" in md
    assert "sql-injection" in md


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_single_scan_produces_all_new():
    """With only one scan, every finding should be classified as new."""
    snapshots = load_scan_snapshots([SCAN_1])
    report = analyze_trend(snapshots)

    assert len(report.remediated_findings) == 0
    assert len(report.persistent_findings) == 0
    assert len(report.new_findings) == 3


def test_empty_scans_handled(tmp_path):
    """A SARIF file with no findings should not crash trend analysis."""
    empty_sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "TestScanner", "version": "1.0"}},
                "invocations": [{"startTimeUtc": "2025-01-01T00:00:00Z"}],
                "results": [],
            }
        ],
    }
    path = tmp_path / "empty.sarif"
    path.write_text(json.dumps(empty_sarif), encoding="utf-8")

    snapshots = load_scan_snapshots([path])
    report = analyze_trend(snapshots)

    assert report.scan_count == 1
    assert report.total_unique_findings == 0
    assert report.new_findings == []
    assert report.remediated_findings == []
    assert report.persistent_findings == []


def test_empty_analyze_trend_no_crash():
    """analyze_trend with zero snapshots returns a sane empty report."""
    report = analyze_trend([])
    assert report.scan_count == 0
    assert report.total_unique_findings == 0
    assert report.new_findings == []


def test_all_remediated_between_scans(tmp_path):
    """If latest scan has no findings, all previous findings are remediated."""
    scan_with_findings = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "TestScanner", "version": "1.0"}},
                "invocations": [{"startTimeUtc": "2025-01-01T00:00:00Z"}],
                "results": [
                    {
                        "ruleId": "xss",
                        "level": "warning",
                        "message": {"text": "XSS finding"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    scan_clean = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "TestScanner", "version": "1.0"}},
                "invocations": [{"startTimeUtc": "2025-02-01T00:00:00Z"}],
                "results": [],
            }
        ],
    }
    p1 = tmp_path / "scan1.sarif"
    p2 = tmp_path / "scan2.sarif"
    p1.write_text(json.dumps(scan_with_findings), encoding="utf-8")
    p2.write_text(json.dumps(scan_clean), encoding="utf-8")

    snapshots = load_scan_snapshots([p1, p2])
    report = analyze_trend(snapshots)

    assert len(report.remediated_findings) == 1
    assert report.remediated_findings[0].rule_id == "xss"
    assert len(report.new_findings) == 0
    assert len(report.persistent_findings) == 0


# ---------------------------------------------------------------------------
# --since CLI filter (via the _extract_scan_date helper)
# ---------------------------------------------------------------------------

def test_since_filter_excludes_older_scans(tmp_path):
    """_extract_scan_date returns the invocation timestamp from SARIF."""
    from stigcode.output.trend import _extract_scan_date

    date = _extract_scan_date(SCAN_1)
    expected = datetime(2025, 2, 1, 10, 0, 0, tzinfo=timezone.utc)
    assert date == expected


def test_since_filter_falls_back_to_mtime(tmp_path):
    """Files without invocations fall back to mtime (just verify no crash)."""
    from stigcode.output.trend import _extract_scan_date

    bare = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "T", "version": "1"}},
                "results": [],
            }
        ],
    }
    p = tmp_path / "bare.sarif"
    p.write_text(json.dumps(bare), encoding="utf-8")

    date = _extract_scan_date(p)
    assert isinstance(date, datetime)
    assert date.tzinfo is not None
