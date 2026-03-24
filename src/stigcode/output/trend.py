"""Trend analysis engine for comparing SARIF findings across multiple scans.

Produces CA-7 (Continuous Monitoring) evidence by tracking findings that are
new, persistent, or remediated across time-ordered scans.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class ScanSnapshot:
    """A single SARIF scan's findings at a point in time."""

    scan_date: datetime
    scanner_name: str
    scanner_version: str
    source_file: str
    findings: set[str]                         # fingerprints for deduplication
    finding_details: dict[str, object]         # fingerprint -> NormalizedFinding


@dataclass
class TrendEntry:
    """A finding tracked across multiple scans."""

    fingerprint: str
    rule_id: str
    cwe_ids: list[int]
    severity: str
    file_path: str
    message: str
    first_seen: datetime
    last_seen: datetime
    status: str                  # "new", "persistent", "remediated"
    seen_in: list[str]           # scan file names where this appears


@dataclass
class TrendReport:
    """Trend analysis across multiple scans."""

    scan_count: int
    date_range: tuple[datetime, datetime]
    total_unique_findings: int
    new_findings: list[TrendEntry]
    remediated_findings: list[TrendEntry]
    persistent_findings: list[TrendEntry]
    trend_data: list[dict]      # per-scan summary: {date, total, new, remediated}


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------

def fingerprint(rule_id: str, file_path: str, start_line: int) -> str:
    """Return a stable cross-scan identifier for a finding."""
    return f"{rule_id}:{file_path}:{start_line}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_scan_snapshots(sarif_paths: list[Path]) -> list[ScanSnapshot]:
    """Load SARIF files and return them ordered by scan date (oldest first).

    Scan date is extracted from runs[0].invocations[0].startTimeUtc when
    available; falls back to the file's modification time.
    """
    from stigcode.ingest.sarif import parse_sarif

    snapshots: list[ScanSnapshot] = []

    for path in sarif_paths:
        result = parse_sarif(path)
        scan_date = _extract_scan_date(path)

        fps: set[str] = set()
        details: dict[str, object] = {}

        for f in result.findings:
            fp = fingerprint(f.rule_id, f.file_path, f.start_line)
            fps.add(fp)
            details[fp] = f

        snapshots.append(
            ScanSnapshot(
                scan_date=scan_date,
                scanner_name=result.scanner_name,
                scanner_version=result.scanner_version,
                source_file=path.name,
                findings=fps,
                finding_details=details,
            )
        )

    snapshots.sort(key=lambda s: s.scan_date)
    return snapshots


def analyze_trend(snapshots: list[ScanSnapshot]) -> TrendReport:
    """Compare findings across ordered scans and classify each finding."""
    if not snapshots:
        return TrendReport(
            scan_count=0,
            date_range=(datetime.min, datetime.min),
            total_unique_findings=0,
            new_findings=[],
            remediated_findings=[],
            persistent_findings=[],
            trend_data=[],
        )

    # Collect all unique fingerprints across all scans
    all_fps: set[str] = set()
    for snap in snapshots:
        all_fps.update(snap.findings)

    # For each fingerprint, find every scan it appears in
    fp_to_scans: dict[str, list[ScanSnapshot]] = {fp: [] for fp in all_fps}
    for snap in snapshots:
        for fp in snap.findings:
            fp_to_scans[fp].append(snap)

    latest = snapshots[-1]
    previous_fps: set[str] = set()
    for snap in snapshots[:-1]:
        previous_fps.update(snap.findings)

    new_findings: list[TrendEntry] = []
    remediated_findings: list[TrendEntry] = []
    persistent_findings: list[TrendEntry] = []

    for fp, seen_in_snaps in fp_to_scans.items():
        seen_in_snaps_sorted = sorted(seen_in_snaps, key=lambda s: s.scan_date)
        first_snap = seen_in_snaps_sorted[0]
        last_snap = seen_in_snaps_sorted[-1]

        # Pull finding detail from whichever snap has it
        detail = first_snap.finding_details.get(fp)
        rule_id = getattr(detail, "rule_id", fp.split(":")[0])
        cwe_ids = getattr(detail, "cwe_ids", [])
        severity = getattr(detail, "severity", "CAT II")
        file_path = getattr(detail, "file_path", "")
        message = getattr(detail, "message", "")

        seen_in_files = [s.source_file for s in seen_in_snaps_sorted]

        if len(snapshots) == 1:
            # Single scan: everything is "new"
            status = "new"
        elif fp in latest.findings and fp not in previous_fps:
            status = "new"
        elif fp not in latest.findings and fp in previous_fps:
            status = "remediated"
        else:
            status = "persistent"

        entry = TrendEntry(
            fingerprint=fp,
            rule_id=rule_id,
            cwe_ids=cwe_ids,
            severity=severity,
            file_path=file_path,
            message=message,
            first_seen=first_snap.scan_date,
            last_seen=last_snap.scan_date,
            status=status,
            seen_in=seen_in_files,
        )

        if status == "new":
            new_findings.append(entry)
        elif status == "remediated":
            remediated_findings.append(entry)
        else:
            persistent_findings.append(entry)

    # Build per-scan trend data
    trend_data = _build_trend_data(snapshots)

    return TrendReport(
        scan_count=len(snapshots),
        date_range=(snapshots[0].scan_date, snapshots[-1].scan_date),
        total_unique_findings=len(all_fps),
        new_findings=new_findings,
        remediated_findings=remediated_findings,
        persistent_findings=persistent_findings,
        trend_data=trend_data,
    )


def trend_to_markdown(report: TrendReport) -> str:
    """Render a TrendReport as Markdown suitable for CA-7 evidence packages."""
    lines: list[str] = []

    lines.append("# Security Scan Trend Report")
    lines.append("")

    # --- Summary table ---
    lines.append("## Summary")
    lines.append("")

    date_start = report.date_range[0].strftime("%Y-%m-%d")
    date_end = report.date_range[1].strftime("%Y-%m-%d")
    currently_open = len(report.new_findings) + len(report.persistent_findings)

    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Scans Analyzed | {report.scan_count} |")
    lines.append(f"| Date Range | {date_start} to {date_end} |")
    lines.append(f"| Total Unique Findings | {report.total_unique_findings} |")
    lines.append(f"| Currently Open | {currently_open} |")
    lines.append(f"| Remediated | {len(report.remediated_findings)} |")
    lines.append(f"| New (latest scan) | {len(report.new_findings)} |")
    lines.append("")

    # --- Per-scan trend table ---
    lines.append("## Trend")
    lines.append("")
    lines.append("| Date | Scanner | Total | New | Remediated |")
    lines.append("|------|---------|-------|-----|------------|")
    for row in reversed(report.trend_data):
        date_str = row["date"].strftime("%Y-%m-%d")
        scanner = f"{row['scanner_name']} {row['scanner_version']}".strip()
        lines.append(
            f"| {date_str} | {scanner} | {row['total']} | {row['new']} | {row['remediated']} |"
        )
    lines.append("")

    # --- New findings ---
    lines.append("## New Findings (since previous scan)")
    lines.append("")
    if report.new_findings:
        lines.append("| Rule | CWE | Severity | Location | Message |")
        lines.append("|------|-----|----------|----------|---------|")
        for e in sorted(report.new_findings, key=lambda x: (x.severity, x.rule_id)):
            cwe_str = ", ".join(f"CWE-{c}" for c in e.cwe_ids) or "—"
            loc = f"{e.file_path}:{e.first_seen.strftime('%Y-%m-%d')}" if not e.file_path else e.file_path
            lines.append(f"| {e.rule_id} | {cwe_str} | {e.severity} | {loc} | {_truncate(e.message, 60)} |")
    else:
        lines.append("No new findings in the latest scan.")
    lines.append("")

    # --- Remediated findings ---
    lines.append("## Remediated Findings (since previous scan)")
    lines.append("")
    if report.remediated_findings:
        lines.append("| Rule | CWE | Severity | Location | First Seen | Message |")
        lines.append("|------|-----|----------|----------|------------|---------|")
        for e in sorted(report.remediated_findings, key=lambda x: (x.severity, x.rule_id)):
            cwe_str = ", ".join(f"CWE-{c}" for c in e.cwe_ids) or "—"
            first_str = e.first_seen.strftime("%Y-%m-%d")
            lines.append(
                f"| {e.rule_id} | {cwe_str} | {e.severity} | {e.file_path} | {first_str} | {_truncate(e.message, 60)} |"
            )
    else:
        lines.append("No findings remediated since the previous scan.")
    lines.append("")

    # --- Persistent findings ---
    lines.append("## Persistent Findings")
    lines.append("")
    if report.persistent_findings:
        lines.append("| Rule | CWE | Severity | Location | First Seen | Scans |")
        lines.append("|------|-----|----------|----------|------------|-------|")
        for e in sorted(report.persistent_findings, key=lambda x: (-len(x.seen_in), x.severity)):
            cwe_str = ", ".join(f"CWE-{c}" for c in e.cwe_ids) or "—"
            first_str = e.first_seen.strftime("%Y-%m-%d")
            scan_ratio = f"{len(e.seen_in)}/{report.scan_count}"
            lines.append(
                f"| {e.rule_id} | {cwe_str} | {e.severity} | {e.file_path} | {first_str} | {scan_ratio} |"
            )
    else:
        lines.append("No findings appear in multiple scans.")
    lines.append("")

    # --- Assessment narrative ---
    lines.append("## Assessment")
    lines.append("")
    lines.append(
        "This trend data supports NIST 800-53 CA-7 (Continuous Monitoring). "
        "The development team is actively scanning and remediating security findings."
    )
    if report.remediated_findings:
        lines.append(
            f"{len(report.remediated_findings)} finding(s) have been remediated "
            f"since {date_start}."
        )
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_scan_date(path: Path) -> datetime:
    """Return the scan start time from SARIF metadata or fall back to mtime."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        for run in data.get("runs", []):
            for inv in run.get("invocations", []):
                ts = inv.get("startTimeUtc")
                if ts:
                    return _parse_iso(ts)
    except Exception:  # noqa: BLE001
        pass
    # Fall back to file modification time
    mtime = path.stat().st_mtime
    return datetime.fromtimestamp(mtime, tz=timezone.utc)


def _parse_iso(ts: str) -> datetime:
    """Parse an ISO-8601 UTC timestamp string."""
    ts = ts.rstrip("Z")
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _build_trend_data(snapshots: list[ScanSnapshot]) -> list[dict]:
    """Build per-scan summary rows for the trend table."""
    rows = []
    prev_fps: set[str] = set()

    for snap in snapshots:
        new_in_scan = snap.findings - prev_fps
        removed = prev_fps - snap.findings if prev_fps else set()
        rows.append(
            {
                "date": snap.scan_date,
                "scanner_name": snap.scanner_name,
                "scanner_version": snap.scanner_version,
                "total": len(snap.findings),
                "new": len(new_in_scan),
                "remediated": len(removed),
            }
        )
        prev_fps = snap.findings

    return rows


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len - 1] + "…"
