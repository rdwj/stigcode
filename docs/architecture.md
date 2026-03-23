# Stigcode Architecture

## Data Flow

```
SARIF Input (any scanner)
    │
    ▼
┌──────────────────────┐
│  stigcode.ingest     │  Parse SARIF, extract results, normalize properties
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  stigcode.mapping    │  Resolve CWE→STIG mappings, assign confidence levels
└──────────┬───────────┘
           │
           ├──────────────────────┬──────────────────────┐
           ▼                      ▼                      ▼
┌─────────────────┐  ┌──────────────────┐  ┌──────────────────────┐
│ stigcode.output │  │ stigcode.output  │  │ stigcode.output      │
│   .ckl          │  │   .report        │  │   .coverage          │
│                 │  │                  │  │                      │
│ DISA CKL files  │  │ ATO evidence     │  │ NIST 800-53 coverage │
│ (.ckl XML)      │  │ reports (MD/PDF) │  │ matrix (CSV/HTML)    │
└─────────────────┘  └──────────────────┘  └──────────────────────┘
```

## Core Components

### `stigcode.ingest` — SARIF Parser and Normalizer

Parses SARIF v2.1.0 JSON, validates against the SARIF schema, and extracts a normalized list of findings. Handles the three-tier resolution priority defined in `docs/sarif-contract.md`:

- Extracts `stigIds`, `stigCheckIds`, `cweIds` from result and rule properties
- Resolves CWE IDs from SARIF `relationships` arrays (Semgrep/CodeQL style)
- Maps SARIF `level` to preliminary severity categories
- Produces `NormalizedFinding` objects for the mapping engine

### `stigcode.mapping` — CWE→STIG Mapping Engine

The core resolution engine. Takes normalized findings and resolves them to concrete STIG finding entries with confidence levels:

- **Direct resolution**: V-IDs and APSC-DV IDs map directly to STIG findings via lookup tables
- **CWE-based inference**: CWE IDs map to STIG findings via the CWE→STIG database (one-to-many)
- **Heuristic fallback**: Rule ID pattern matching for minimal-tier SARIF
- Each resolved mapping carries a confidence level: `direct`, `inferred`, or `low`

### `stigcode.output.ckl` — CKL Generator

Produces DISA STIG Viewer-compatible CKL files (XML format). Each CKL groups findings by STIG check (APSC-DV ID) and sets finding status:

- `Open` — vulnerability detected, evidence from scanner
- `Not_Reviewed` — STIG check not covered by scanner rules
- `Not_Applicable` — explicitly marked N/A (via configuration or assessment input)
- `NotAFinding` — scanner confirms no instances found

Mapping confidence is recorded in the `COMMENTS` field so assessors can prioritize review of `inferred` and `low` confidence mappings.

### `stigcode.output.report` — ATO Evidence Report Generator

Produces human-readable reports for ATO (Authority to Operate) packages. Output formats: Markdown, PDF. Includes:

- Executive summary with finding counts by severity
- Detailed findings grouped by NIST 800-53 control family
- Remediation guidance (when available from enriched SARIF)
- Scanner metadata and scan timestamp

### `stigcode.output.coverage` — NIST 800-53 Coverage Matrix

Generates a matrix showing which NIST 800-53 controls are addressed by the scan results. Output formats: CSV, HTML, Excel. Shows:

- Controls with findings (pass/fail per control)
- Controls not covered by the scanner's rule set
- Coverage percentage by control family

### `stigcode.data` — Runtime Data Loading

Loads mapping databases and STIG metadata at runtime from the package's `data/` directory:

- YAML parsing with caching for repeated lookups
- Schema validation for mapping files
- Version tracking for STIG baselines

### `stigcode.cli` — CLI Entry Point

Typer-based CLI (matching sanicode's framework choice). Primary commands:

```
stigcode export ckl    --input results.sarif --output checklist.ckl
stigcode export report --input results.sarif --output evidence.md
stigcode export matrix --input results.sarif --output coverage.csv
stigcode info stigs    # List available STIG baselines
stigcode info mappings # Show CWE→STIG mapping statistics
```

## Data Directory Structure

```
data/
├── mappings/
│   └── cwe_to_stig.yaml      # CWE → STIG finding mappings
│                               # Maps CWE IDs to APSC-DV check IDs and V-IDs
│                               # Includes mapping confidence and notes
├── stigs/
│   └── app_security_v6.yaml   # Parsed STIG data from DISA XCCDF
│                               # Contains V-IDs, APSC-DV IDs, titles, fix text,
│                               # severity categories, and CCI references
└── cci/
    └── cci_to_nist.yaml       # CCI → NIST 800-53 rev5 control mappings
                                # Used to bridge STIG findings to NIST controls
                                # for coverage matrix generation
```

The data files are derived from official DISA sources (XCCDF XML, CCI XML) and checked into the repository as YAML for readability and diff-friendliness. Scripts to regenerate from upstream sources will live in `scripts/`.
