# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

```bash
# Setup (Python 3.10+)
python -m venv .venv && source .venv/bin/activate
pip install -e .

# Run the CLI
stigcode

# Run tests
pytest
pytest tests/test_specific.py          # single file
pytest -k "test_name"                  # by pattern

# Lint / format (not yet configured — add ruff or similar when ready)
```

The package uses setuptools with `src/` layout. Entry point: `stigcode.cli:main` (defined in `pyproject.toml`). Version lives in `src/stigcode/version.py` and must be kept in sync with `pyproject.toml [project] version`.

## Project Status

Early scaffold — CLI prints a banner and exits. The `ingest/`, `mapping/`, `output/`, and `data/` subpackages described in the architecture below do not exist yet. The `data/` directory with YAML mappings also needs to be created.

# Stigcode — Project Context

Stigcode is a PyPI-distributed CLI tool that transforms SARIF scan results from any SAST scanner into compliance-native artifacts: DISA STIG Viewer checklists (.ckl), ATO evidence reports, NIST 800-53 coverage matrices, and (future) NIST OSCAL output.

It is the compliance companion to [Sanicode](https://github.com/rdwj/sanicode). See `docs/sarif-contract.md` for the SARIF integration contract between the two projects.

## Tech Stack

- Python 3.10+, package name `stigcode`
- CLI: Typer (matching sanicode's framework choice)
- SARIF parsing: Direct JSON parsing with schema validation
- Mapping database: YAML files in `data/mappings/`
- STIG metadata: Parsed from DISA XCCDF XML, stored as YAML in `data/stigs/`
- Output formats: CKL (XML), PDF, Markdown, CSV, Excel, JSON
- Container base: `registry.redhat.io/ubi9/python-311` (UBI9, multi-stage)

## Project Structure

```
stigcode/
├── src/stigcode/         # Main package
│   ├── cli.py            # CLI entry point
│   ├── ingest/           # SARIF parsing and normalization
│   ├── mapping/          # CWE→STIG mapping engine
│   ├── output/           # Output generators (ckl, report, coverage)
│   └── data/             # Runtime data loading
├── data/                 # Mapping databases and STIG metadata
│   ├── mappings/         # CWE→STIG YAML mappings
│   ├── stigs/            # Parsed STIG data
│   └── cci/              # CCI→NIST mappings
├── tests/                # pytest, mirrors src/stigcode/
├── docs/                 # Documentation
└── stigcode.toml         # Project config (optional)
```

## Key Architectural Decisions

**Scanner-agnostic, not sanicode-dependent.** Stigcode must work with SARIF from any scanner. Sanicode provides richer metadata, but stigcode's CWE→STIG mapping database handles the common case.

**Mapping confidence is first-class.** Every STIG finding status carries a confidence level: `direct` (explicit STIG ID in SARIF), `inferred` (CWE-based mapping), `partial` (incomplete coverage). This is surfaced in CKL comments so assessors know what to review.

**CKL fidelity is non-negotiable.** The .ckl output must import cleanly into STIG Viewer 2.x and 3.x. Test against real STIG Viewer imports, not just XML validation.

**Offline-native.** Zero network calls at runtime. All mapping data ships in the package.

## SARIF Contract

See `docs/sarif-contract.md` for the full specification. Key points:
- Stigcode looks for `properties.stigIds` first (highest confidence)
- Falls back to `properties.cweIds` or CWE tags on rules
- Maps severity: SARIF `error` → CAT I, `warning` → CAT II, `note` → CAT III

## Companion Project

Sanicode (the scanner) lives at https://github.com/rdwj/sanicode. When making changes to the SARIF contract, coordinate with sanicode's `src/sanicode/report/sarif.py`.
