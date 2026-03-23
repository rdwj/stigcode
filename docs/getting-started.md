# Getting Started

> This is a placeholder for the full getting-started guide. Stigcode is in early development.

## Installation

```bash
pip install stigcode
```

## Usage

### From Sanicode

```bash
sanicode scan ./myapp --format sarif -o results.sarif
stigcode export ckl --input results.sarif --output checklist.ckl
```

### From Semgrep

```bash
semgrep --config auto --sarif -o results.sarif ./myapp
stigcode export ckl --input results.sarif --output checklist.ckl
```

### From CodeQL

```bash
codeql database analyze myapp-db --format=sarif-latest --output=results.sarif
stigcode export ckl --input results.sarif --output checklist.ckl
```

### Pipeline Mode

```bash
sanicode scan --format sarif ./myapp | stigcode export ckl -o checklist.ckl
```

### Multiple Output Formats

```bash
# Generate CKL for STIG Viewer import
stigcode export ckl --input results.sarif --output checklist.ckl

# Generate ATO evidence report
stigcode export report --input results.sarif --output evidence.md

# Generate NIST 800-53 coverage matrix
stigcode export matrix --input results.sarif --output coverage.csv
```

### Inspect Available Data

```bash
# List loaded STIG baselines
stigcode info stigs

# Show CWE→STIG mapping statistics
stigcode info mappings
```
