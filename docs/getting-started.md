# Getting Started

Stigcode transforms SARIF scan results from any SAST scanner into compliance-ready artifacts:
ATO evidence reports, NIST 800-53 coverage matrices, POA&M inputs, and STIG Viewer checklists.

## Installation

```bash
pip install stigcode
```

## Primary Workflow: ATO Evidence Package

The most common use case is preparing SA-11 evidence for an ATO security package. After running
any SAST tool that produces SARIF output, run these three commands:

```bash
stigcode report scan.sarif -o sa-11-evidence.md
stigcode coverage scan.sarif -o control-coverage.md
stigcode poam scan.sarif -o poam-candidates.md
```

The report maps scan findings to NIST 800-53 controls and produces an assessor-ready summary.
The coverage matrix shows which controls are addressed by the scan and which require other evidence.
The POA&M candidates give the ISSO a starting point for documenting open findings.

Both `coverage` and `poam` also support `--format csv` for spreadsheet workflows.

## Scanner Examples

### Sanicode

```bash
sanicode scan ./myapp --format sarif -o scan.sarif
stigcode report scan.sarif -o sa-11-evidence.md
```

### Semgrep

```bash
semgrep --config auto --sarif -o scan.sarif ./myapp
stigcode report scan.sarif -o sa-11-evidence.md
```

### CodeQL

```bash
codeql database analyze myapp-db --format=sarif-latest --output=scan.sarif
stigcode report scan.sarif -o sa-11-evidence.md
```

### Bandit

```bash
bandit -r ./myapp -f sarif -o scan.sarif
stigcode report scan.sarif -o sa-11-evidence.md
```

### Pipeline Mode

```bash
sanicode scan --format sarif ./myapp | stigcode report - -o sa-11-evidence.md
```

## AppDev STIG Checklist

For assessments that require a STIG Viewer checklist (.ckl), use the `ckl` command. Most
findings that require human assessment will be marked Not Reviewed; scan-assessable findings
are populated automatically.

```bash
stigcode ckl scan.sarif -o app-stig.ckl
```

To update an existing checklist without losing assessor notes:

```bash
stigcode ckl scan.sarif --update existing.ckl -o updated.ckl
```

## Inspect Before Generating

Verify a SARIF file parses correctly and review the finding summary before generating output:

```bash
stigcode import scan.sarif
```

Assess findings against the loaded STIG benchmark and see a status breakdown:

```bash
stigcode assess scan.sarif
```

## Reference Lookups

```bash
# Which STIG findings map to SQL injection?
stigcode lookup cwe --cwe CWE-89

# Which CWEs map to a specific STIG finding?
stigcode lookup stig --stig V-222387

# Show mapping database stats
stigcode info mappings
```

## Version

```bash
stigcode version
```

## Trend Analysis

Track compliance posture changes across successive scans:

```bash
stigcode trend scan1.sarif scan2.sarif scan3.sarif -o trend-report.md
stigcode trend scan1.sarif scan2.sarif --format csv -o trend.csv
```

## PDF Output

All commands that accept `--format` support `pdf` as a value:

```bash
stigcode report scan.sarif --format pdf -o sa-11-evidence.pdf
stigcode coverage scan.sarif --format pdf -o coverage.pdf
```
