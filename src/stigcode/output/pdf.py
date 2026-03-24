"""Markdown-to-PDF converter for stigcode compliance reports.

Handles the specific Markdown constructs produced by stigcode's report generators:
headings (H1–H4), tables, bullet lists, bold text, horizontal rules, and paragraphs.

Uses fpdf2 (pure Python) — no system dependencies, works in air-gapped environments.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from fpdf import FPDF

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MARGIN = 15
PAGE_WIDTH_MM = 210  # A4
USABLE_WIDTH = PAGE_WIDTH_MM - 2 * MARGIN  # ~180 mm

COLOR_HEADING = (31, 73, 125)   # dark blue
COLOR_H1 = (17, 50, 90)
COLOR_RULE = (180, 180, 180)
COLOR_TABLE_HEADER = (220, 230, 242)
COLOR_TABLE_ALT = (245, 248, 252)
COLOR_TABLE_BORDER = (180, 180, 180)


# ---------------------------------------------------------------------------
# PDF class
# ---------------------------------------------------------------------------

class StigcodePDF(FPDF):
    """PDF generator for stigcode reports."""

    def header(self) -> None:
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, "STIGCODE", align="R")
        self.ln(10)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")


# ---------------------------------------------------------------------------
# Text sanitization
# ---------------------------------------------------------------------------

# Map common Unicode characters that fall outside Latin-1 to ASCII equivalents.
# fpdf2 core fonts (Helvetica) are Latin-1 only.
_UNICODE_REPLACEMENTS: dict[str, str] = {
    "\u2014": "--",   # em-dash
    "\u2013": "-",    # en-dash
    "\u2018": "'",    # left single quotation mark
    "\u2019": "'",    # right single quotation mark
    "\u201c": '"',    # left double quotation mark
    "\u201d": '"',    # right double quotation mark
    "\u2026": "...",  # horizontal ellipsis
    "\u00a0": " ",    # non-breaking space
}
_UNICODE_TABLE = str.maketrans(_UNICODE_REPLACEMENTS)


def _safe(text: str) -> str:
    """Replace common non-Latin-1 characters and drop anything else outside the range."""
    text = text.translate(_UNICODE_TABLE)
    return text.encode("latin-1", errors="replace").decode("latin-1")


# ---------------------------------------------------------------------------
# Inline bold renderer
# ---------------------------------------------------------------------------

def _write_with_bold(pdf: FPDF, text: str, base_size: int = 10) -> None:
    """Write a line of text, switching to bold for **..** spans."""
    parts = re.split(r"(\*\*[^*]+\*\*)", text)
    for part in parts:
        if part.startswith("**") and part.endswith("**"):
            pdf.set_font("Helvetica", "B", base_size)
            pdf.write(6, _safe(part[2:-2]))
        else:
            pdf.set_font("Helvetica", "", base_size)
            pdf.write(6, _safe(part))


# ---------------------------------------------------------------------------
# Element renderers
# ---------------------------------------------------------------------------

def _render_h1(pdf: FPDF, text: str) -> None:
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(*COLOR_H1)
    pdf.multi_cell(0, 10, _safe(text.strip()))
    pdf.set_draw_color(*COLOR_HEADING)
    pdf.set_line_width(0.5)
    pdf.line(MARGIN, pdf.get_y(), PAGE_WIDTH_MM - MARGIN, pdf.get_y())
    pdf.ln(4)
    pdf.set_text_color(0, 0, 0)


def _render_h2(pdf: FPDF, text: str) -> None:
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*COLOR_HEADING)
    pdf.multi_cell(0, 8, _safe(text.strip()))
    pdf.ln(1)
    pdf.set_text_color(0, 0, 0)


def _render_h3(pdf: FPDF, text: str) -> None:
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*COLOR_HEADING)
    pdf.multi_cell(0, 7, _safe(text.strip()))
    pdf.ln(1)
    pdf.set_text_color(0, 0, 0)


def _render_h4(pdf: FPDF, text: str) -> None:
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(60, 60, 60)
    pdf.multi_cell(0, 6, _safe(text.strip()))
    pdf.set_text_color(0, 0, 0)


def _render_bullet(pdf: FPDF, text: str) -> None:
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(0, 0, 0)
    y0 = pdf.get_y()
    pdf.set_xy(MARGIN + 3, y0)
    pdf.cell(5, 6, "-")
    pdf.set_xy(MARGIN + 8, y0)
    _write_with_bold(pdf, text.strip())
    pdf.ln(6)


def _render_hr(pdf: FPDF) -> None:
    pdf.ln(2)
    pdf.set_draw_color(*COLOR_RULE)
    pdf.set_line_width(0.3)
    pdf.line(MARGIN, pdf.get_y(), PAGE_WIDTH_MM - MARGIN, pdf.get_y())
    pdf.ln(3)


def _render_paragraph(pdf: FPDF, text: str) -> None:
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(0, 0, 0)
    pdf.set_x(MARGIN)
    _write_with_bold(pdf, text.strip())  # _safe() called inside _write_with_bold
    pdf.ln(6)


# ---------------------------------------------------------------------------
# Table renderer
# ---------------------------------------------------------------------------

def _parse_table_rows(lines: list[str]) -> list[list[str]]:
    """Parse GFM table lines into a 2D list. Skips separator rows (|---|)."""
    rows = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        # Separator row: cells contain only dashes, colons, spaces
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if all(re.match(r"^:?-+:?$", c) for c in cells if c):
            continue
        rows.append(cells)
    return rows


def _render_table(pdf: FPDF, rows: list[list[str]]) -> None:
    if not rows:
        return

    col_count = max(len(r) for r in rows)
    if col_count == 0:
        return

    col_w = USABLE_WIDTH / col_count
    row_h = 7

    pdf.set_draw_color(*COLOR_TABLE_BORDER)
    pdf.set_line_width(0.2)

    for row_idx, row in enumerate(rows):
        # Pad short rows
        cells = row + [""] * (col_count - len(row))

        is_header = row_idx == 0
        if is_header:
            pdf.set_fill_color(*COLOR_TABLE_HEADER)
            pdf.set_font("Helvetica", "B", 9)
        else:
            if row_idx % 2 == 0:
                pdf.set_fill_color(*COLOR_TABLE_ALT)
            else:
                pdf.set_fill_color(255, 255, 255)
            pdf.set_font("Helvetica", "", 9)

        pdf.set_text_color(0, 0, 0)
        x_start = MARGIN

        for cell_text in cells:
            # Truncate very long cells to avoid runaway rows
            truncated = cell_text[:80] + ("..." if len(cell_text) > 80 else "")
            display = _safe(truncated)
            pdf.set_xy(x_start, pdf.get_y())
            pdf.cell(col_w, row_h, display, border=1, fill=True)
            x_start += col_w

        pdf.ln(row_h)

    pdf.ln(2)


# ---------------------------------------------------------------------------
# Line classifier
# ---------------------------------------------------------------------------

def _iter_blocks(lines: list[str]) -> Iterator[tuple[str, list[str]]]:
    """Yield (block_type, lines) tuples from a flat line list.

    Block types: h1, h2, h3, h4, bullet, hr, table, paragraph, blank
    """
    i = 0
    while i < len(lines):
        line = lines[i]

        if line.startswith("# ") or line == "#":
            yield ("h1", [line[2:]])
            i += 1
        elif line.startswith("## "):
            yield ("h2", [line[3:]])
            i += 1
        elif line.startswith("### "):
            yield ("h3", [line[4:]])
            i += 1
        elif line.startswith("#### "):
            yield ("h4", [line[5:]])
            i += 1
        elif line.startswith("- "):
            yield ("bullet", [line[2:]])
            i += 1
        elif line.startswith("---"):
            yield ("hr", [])
            i += 1
        elif line.startswith("|"):
            # Collect all consecutive table lines
            table_lines = []
            while i < len(lines) and lines[i].startswith("|"):
                table_lines.append(lines[i])
                i += 1
            yield ("table", table_lines)
        elif line.strip() == "":
            yield ("blank", [])
            i += 1
        else:
            yield ("paragraph", [line])
            i += 1


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def markdown_to_pdf(
    markdown_text: str,
    output_path: Path,
    title: str = "Stigcode Report",
    compress: bool = True,
) -> None:
    """Convert a stigcode Markdown report to PDF.

    Handles the specific Markdown patterns produced by stigcode generators:
    headings (H1–H4), GFM tables, bullet lists, bold inline text,
    horizontal rules, and plain paragraphs.

    Args:
        markdown_text: Markdown source string.
        output_path: Destination path for the PDF file (will be created/overwritten).
        title: Document title embedded in the PDF metadata.
        compress: Whether to compress the PDF content stream. Disable for testing.
    """
    pdf = StigcodePDF(orientation="P", unit="mm", format="A4")
    pdf.set_compression(compress)
    pdf.alias_nb_pages()
    pdf.set_margins(MARGIN, MARGIN, MARGIN)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_title(title)
    pdf.add_page()

    lines = markdown_text.split("\n")

    for block_type, block_lines in _iter_blocks(lines):
        if block_type == "blank":
            continue
        elif block_type == "h1":
            _render_h1(pdf, block_lines[0])
        elif block_type == "h2":
            _render_h2(pdf, block_lines[0])
        elif block_type == "h3":
            _render_h3(pdf, block_lines[0])
        elif block_type == "h4":
            _render_h4(pdf, block_lines[0])
        elif block_type == "bullet":
            _render_bullet(pdf, block_lines[0])
        elif block_type == "hr":
            _render_hr(pdf)
        elif block_type == "table":
            rows = _parse_table_rows(block_lines)
            _render_table(pdf, rows)
        elif block_type == "paragraph":
            _render_paragraph(pdf, block_lines[0])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_path))
