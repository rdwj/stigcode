"""STIG cross-reference matrix generator.

Produces a human-readable CWE → STIG Finding → NIST 800-53 control mapping
table in Markdown or CSV format.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from pathlib import Path

from stigcode.ingest.xccdf import StigBenchmark
from stigcode.mapping.engine import MappingDatabase


@dataclass
class XrefEntry:
    """A single row in the cross-reference matrix."""

    stig_id: str              # V-222607
    rule_ver: str             # APSC-DV-002540
    stig_title: str           # The application must not be subject to...
    severity: str             # high/medium/low
    category: int             # 1, 2, 3
    cwe_ids: list[int]        # [89, 564]
    nist_controls: list[str]  # ["SI-10"]
    cci_refs: list[str]       # ["CCI-002754"]
    confidence: str           # direct, inferred, partial
    assessment_method: str    # sast, procedural
    notes: str = ""


def build_xref_matrix(
    benchmark: StigBenchmark,
    mapping_db: MappingDatabase,
    cci_mappings: dict[str, str],
    classifications: dict[str, str | dict],
) -> list[XrefEntry]:
    """Build the complete cross-reference matrix for all STIG findings.

    Every finding in the benchmark gets an entry. SAST-assessable findings
    carry CWE mappings from the mapping database; procedural findings get
    empty cwe_ids and confidence "partial".

    Args:
        benchmark: Parsed STIG benchmark.
        mapping_db: CWE→STIG mapping database.
        cci_mappings: CCI → NIST control mapping dict.
        classifications: Per-finding classification dict from
                         finding_classifications.yaml, keyed by V-ID.

    Returns:
        List of XrefEntry sorted by assessment_method (sast first), then
        stig_id numerically.
    """
    entries: list[XrefEntry] = []

    # Index mapping database by stig_id for fast lookup
    mappings_by_stig: dict[str, list] = {}
    for m in mapping_db.mappings:
        mappings_by_stig.setdefault(m.stig_id, []).append(m)

    for finding in benchmark.findings:
        cls_data = classifications.get(finding.vuln_id, {})
        if isinstance(cls_data, dict) and "assessment_method" in cls_data:
            assessment_method = cls_data["assessment_method"]
        else:
            # Fall back: if the mapping database has entries for this finding,
            # it is SAST-detectable even if absent from the classifications file.
            assessment_method = "sast" if finding.vuln_id in mappings_by_stig else "procedural"

        stig_mappings = mappings_by_stig.get(finding.vuln_id, [])

        if assessment_method == "sast" and stig_mappings:
            # Aggregate all CWE IDs for this finding, preserving order
            cwe_ids: list[int] = []
            seen_cwe: set[int] = set()
            cci_refs: list[str] = list(finding.cci_refs)
            nist_controls: list[str] = []
            seen_nist: set[str] = set()
            notes_parts: list[str] = []

            # Use the first mapping's confidence (all mappings for a given
            # stig_id typically share confidence, but use most-authoritative)
            confidence_priority = {"direct": 0, "inferred": 1, "partial": 2}
            best_confidence = "partial"

            for m in stig_mappings:
                if m.cwe_id not in seen_cwe:
                    cwe_ids.append(m.cwe_id)
                    seen_cwe.add(m.cwe_id)
                if m.nist_control and m.nist_control not in seen_nist:
                    nist_controls.append(m.nist_control)
                    seen_nist.add(m.nist_control)
                for cci in m.cci_refs:
                    if cci not in cci_refs:
                        cci_refs.append(cci)
                if m.notes:
                    notes_parts.append(m.notes)
                if confidence_priority.get(m.confidence, 2) < confidence_priority.get(best_confidence, 2):
                    best_confidence = m.confidence

            # Supplement NIST controls from CCI refs on the finding itself
            for cci in finding.cci_refs:
                ctrl = cci_mappings.get(cci)
                if ctrl and ctrl not in seen_nist:
                    nist_controls.append(ctrl)
                    seen_nist.add(ctrl)

            entries.append(XrefEntry(
                stig_id=finding.vuln_id,
                rule_ver=finding.check_id or stig_mappings[0].check_id,
                stig_title=finding.title,
                severity=finding.severity,
                category=finding.category,
                cwe_ids=cwe_ids,
                nist_controls=nist_controls,
                cci_refs=cci_refs,
                confidence=best_confidence,
                assessment_method="sast",
                notes="; ".join(notes_parts),
            ))
        else:
            # Procedural finding — no CWE mapping; derive NIST from CCI refs
            nist_controls = []
            seen_nist: set[str] = set()
            for cci in finding.cci_refs:
                ctrl = cci_mappings.get(cci)
                if ctrl and ctrl not in seen_nist:
                    nist_controls.append(ctrl)
                    seen_nist.add(ctrl)

            entries.append(XrefEntry(
                stig_id=finding.vuln_id,
                rule_ver=finding.check_id,
                stig_title=finding.title,
                severity=finding.severity,
                category=finding.category,
                cwe_ids=[],
                nist_controls=nist_controls,
                cci_refs=list(finding.cci_refs),
                confidence="partial",
                assessment_method="procedural",
            ))

    # Sort: SAST first, then procedural; within each group by V-ID numerically
    def _sort_key(e: XrefEntry) -> tuple[int, int]:
        order = 0 if e.assessment_method == "sast" else 1
        try:
            num = int(e.stig_id.replace("V-", ""))
        except ValueError:
            num = 0
        return (order, num)

    entries.sort(key=_sort_key)
    return entries


def xref_to_markdown(entries: list[XrefEntry], benchmark_title: str = "") -> str:
    """Render the cross-reference matrix as a Markdown document.

    SAST-assessable findings appear first, then procedural findings.

    Args:
        entries: Pre-sorted list from build_xref_matrix.
        benchmark_title: Optional benchmark title for the document header.

    Returns:
        Markdown string.
    """
    sast = [e for e in entries if e.assessment_method == "sast"]
    procedural = [e for e in entries if e.assessment_method != "sast"]

    lines: list[str] = []
    lines.append("# STIG Cross-Reference Matrix")
    lines.append("")
    if benchmark_title:
        lines.append(benchmark_title)
        lines.append("")

    # --- SAST section ---
    lines.append(f"## SAST-Assessable Findings ({len(sast)})")
    lines.append("")
    lines.append("| V-ID | Check ID | Title | CAT | CWE(s) | NIST Control | Confidence |")
    lines.append("|------|----------|-------|-----|--------|--------------|------------|")
    for e in sast:
        cwe_str = ", ".join(str(c) for c in e.cwe_ids) if e.cwe_ids else "—"
        nist_str = ", ".join(e.nist_controls) if e.nist_controls else "—"
        title_trunc = e.stig_title[:60] + "…" if len(e.stig_title) > 60 else e.stig_title
        lines.append(
            f"| {e.stig_id} | {e.rule_ver} | {title_trunc} "
            f"| {e.category} | {cwe_str} | {nist_str} | {e.confidence} |"
        )
    lines.append("")

    # --- Procedural section ---
    lines.append(f"## Procedural Findings ({len(procedural)})")
    lines.append("")
    lines.append("| V-ID | Check ID | Title | CAT | NIST Control | Assessment |")
    lines.append("|------|----------|-------|-----|--------------|------------|")
    for e in procedural:
        nist_str = ", ".join(e.nist_controls) if e.nist_controls else "—"
        title_trunc = e.stig_title[:60] + "…" if len(e.stig_title) > 60 else e.stig_title
        lines.append(
            f"| {e.stig_id} | {e.rule_ver} | {title_trunc} "
            f"| {e.category} | {nist_str} | {e.assessment_method} |"
        )
    lines.append("")

    return "\n".join(lines)


def xref_to_csv(entries: list[XrefEntry]) -> str:
    """Render the cross-reference matrix as CSV.

    Columns: STIG_ID, Check_ID, Title, Severity, CAT, CWE_IDs, NIST_Controls,
             CCI_Refs, Confidence, Assessment_Method, Notes
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "STIG_ID", "Check_ID", "Title", "Severity", "CAT",
        "CWE_IDs", "NIST_Controls", "CCI_Refs",
        "Confidence", "Assessment_Method", "Notes",
    ])
    for e in entries:
        writer.writerow([
            e.stig_id,
            e.rule_ver,
            e.stig_title,
            e.severity,
            e.category,
            " ".join(str(c) for c in e.cwe_ids),
            " ".join(e.nist_controls),
            " ".join(e.cci_refs),
            e.confidence,
            e.assessment_method,
            e.notes,
        ])
    return buf.getvalue()


def write_xref(entries: list[XrefEntry], output_path: Path, fmt: str = "md",
               benchmark_title: str = "") -> None:
    """Write the cross-reference matrix to a file.

    Args:
        entries: Pre-built list from build_xref_matrix.
        output_path: Destination file.
        fmt: "md" for Markdown, "csv" for CSV.
        benchmark_title: Optional title for Markdown header.

    Raises:
        ValueError: if fmt is not "md" or "csv".
    """
    if fmt == "md":
        content = xref_to_markdown(entries, benchmark_title)
    elif fmt == "csv":
        content = xref_to_csv(entries)
    else:
        raise ValueError(f"Unknown format {fmt!r}. Use 'md' or 'csv'.")
    output_path.write_text(content, encoding="utf-8")
