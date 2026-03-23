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
