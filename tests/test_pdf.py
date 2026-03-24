"""Tests for the Markdown-to-PDF converter (output.pdf)."""

from __future__ import annotations

from pathlib import Path

import pytest

from stigcode.output.pdf import (
    _parse_table_rows,
    markdown_to_pdf,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SIMPLE_MD = """\
# Test Report

## Summary

This is a paragraph with **bold** text.

- Bullet one
- Bullet two

---

## Table

| Header A | Header B | Header C |
|----------|----------|----------|
| Row 1A   | Row 1B   | Row 1C   |
| Row 2A   | Row 2B   | Row 2C   |
"""

HEADING_ONLY_MD = "# My Heading\n\n## Sub Heading\n\n### Deep\n\n#### Deeper\n"


def _pdf_bytes(tmp_path: Path, content: str, title: str = "Test") -> bytes:
    """Generate a PDF with compression disabled so text is searchable in raw bytes."""
    out = tmp_path / "output.pdf"
    markdown_to_pdf(content, out, title=title, compress=False)
    return out.read_bytes()


# ---------------------------------------------------------------------------
# File creation
# ---------------------------------------------------------------------------

def test_markdown_to_pdf_creates_file(tmp_path: Path) -> None:
    out = tmp_path / "report.pdf"
    markdown_to_pdf(SIMPLE_MD, out, compress=False)
    assert out.exists(), f"Expected {out} to exist after markdown_to_pdf()"
    assert out.stat().st_size > 0, "PDF file should not be empty"


def test_pdf_is_valid_pdf_magic(tmp_path: Path) -> None:
    data = _pdf_bytes(tmp_path, SIMPLE_MD)
    assert data[:4] == b"%PDF", f"File should start with %PDF, got {data[:4]!r}"


# ---------------------------------------------------------------------------
# Content checks (raw byte search — fpdf2 embeds text in the PDF stream)
# ---------------------------------------------------------------------------

def test_pdf_contains_heading(tmp_path: Path) -> None:
    data = _pdf_bytes(tmp_path, "# My Section\n\nSome text.\n")
    # fpdf2 stores text in the content stream; heading text should be present
    assert b"My Section" in data, "Heading text not found in PDF bytes"


def test_pdf_handles_bold_text(tmp_path: Path) -> None:
    data = _pdf_bytes(tmp_path, "A paragraph with **bold** words.\n")
    assert b"bold" in data, "Bold text content not found in PDF bytes"


def test_pdf_handles_bullets(tmp_path: Path) -> None:
    md = "- First item\n- Second item\n- Third item\n"
    data = _pdf_bytes(tmp_path, md)
    assert b"First item" in data
    assert b"Second item" in data


def test_pdf_handles_tables(tmp_path: Path) -> None:
    md = "| Col A | Col B |\n|-------|-------|\n| val1  | val2  |\n"
    data = _pdf_bytes(tmp_path, md)
    assert data[:4] == b"%PDF"
    assert b"Col A" in data


def test_pdf_handles_empty_markdown(tmp_path: Path) -> None:
    out = tmp_path / "empty.pdf"
    markdown_to_pdf("", out)
    assert out.exists()
    assert out.read_bytes()[:4] == b"%PDF"


def test_pdf_handles_all_heading_levels(tmp_path: Path) -> None:
    data = _pdf_bytes(tmp_path, HEADING_ONLY_MD)
    assert data[:4] == b"%PDF"
    assert b"My Heading" in data
    assert b"Sub Heading" in data
    assert b"Deep" in data
    assert b"Deeper" in data


# ---------------------------------------------------------------------------
# Multi-page
# ---------------------------------------------------------------------------

def test_pdf_page_count_multi_page(tmp_path: Path) -> None:
    # Generate enough content to force a page break (A4 page ~90 lines)
    lines = ["## Section\n\n" + "A line of text.\n" * 60 + "\n"]
    md = "\n".join(lines * 3)
    out = tmp_path / "multipage.pdf"
    markdown_to_pdf(md, out)
    data = out.read_bytes()
    assert data[:4] == b"%PDF"
    # fpdf2 embeds page count; more than one page means "Page" appears multiple times
    assert data.count(b"/Page") > 2, "Expected multiple pages in output"


# ---------------------------------------------------------------------------
# Table parsing unit tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("lines,expected", [
    (
        ["| A | B |", "|---|---|", "| 1 | 2 |"],
        [["A", "B"], ["1", "2"]],
    ),
    (
        ["| X |", "|---|", "| Y |"],
        [["X"], ["Y"]],
    ),
    (
        ["| A | B | C |", "|:--|:--:|--:|", "| a | b | c |"],
        [["A", "B", "C"], ["a", "b", "c"]],
    ),
    (
        [],
        [],
    ),
])
def test_parse_table_rows(lines: list[str], expected: list[list[str]]) -> None:
    assert _parse_table_rows(lines) == expected


# ---------------------------------------------------------------------------
# Integration: generate a real report markdown, convert to PDF
# ---------------------------------------------------------------------------

def test_integration_full_report_to_pdf(tmp_path: Path) -> None:
    """Generate real report Markdown, then convert to PDF — smoke test."""
    from datetime import datetime

    from stigcode.ingest.xccdf import StigBenchmark, StigFinding
    from stigcode.mapping.engine import MappingDatabase, StigMapping
    from stigcode.mapping.status import (
        CklStatus,
        DeterminationConfidence,
        FindingDetermination,
        StatusReport,
    )
    from stigcode.output.report import generate_report

    finding = StigFinding(
        vuln_id="V-222400",
        rule_id="SV-222400r508029_rule",
        check_id="APSC-DV-001310",
        title="Input validation check",
        severity="medium",
        category=2,
        description="The application must validate input.",
        fix_text="Implement input validation.",
        check_content="Verify input validation exists.",
        cci_refs=["CCI-001310"],
    )
    benchmark = StigBenchmark(
        benchmark_id="ASD_STIG_TEST",
        title="Application Security and Development STIG",
        version="5",
        release="2",
        date="01 Jan 2026",
        findings=[finding],
        profiles={},
    )

    mapping = StigMapping(
        cwe_id=20,
        stig_id="V-222400",
        check_id="APSC-DV-001310",
        confidence="direct",
        nist_control="SI-10",
    )
    db = MappingDatabase(
        mappings=[mapping],
        version="1.0",
        stig_name="ASD STIG",
        stig_version="V5R2",
    )

    det = FindingDetermination(
        stig_id="V-222400",
        status=CklStatus.OPEN,
        confidence=DeterminationConfidence.DIRECT,
        mapped_cwe_ids=[20],
        evidence=["src/main.py:42"],
    )
    report = StatusReport(
        determinations=[det],
        scan_summary={
            "scanner_name": "test-scanner",
            "scanner_version": "1.0",
            "total_stig_findings": 1,
        },
    )

    md = generate_report(report, benchmark, db, scan_date=datetime(2026, 1, 15))
    assert md.strip(), "generate_report returned empty string"

    out = tmp_path / "evidence.pdf"
    markdown_to_pdf(md, out, title="Security Assessment Evidence", compress=False)
    assert out.exists()
    data = out.read_bytes()
    assert data[:4] == b"%PDF", f"Output is not a PDF: {data[:20]!r}"
    assert b"Security Assessment" in data or b"Application Security" in data
