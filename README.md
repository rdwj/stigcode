# Stigcode

**SARIF-to-compliance bridge.** Transforms SAST scan results from any scanner into ATO evidence artifacts, NIST 800-53 coverage matrices, POA&M candidates, STIG Viewer checklists, and OSCAL assessment results.

Stigcode bridges the gap between developer-facing scan output and the compliance artifacts that ISSOs, assessors, and authorizing officials need for Authority to Operate (ATO) packages. It consumes SARIF v2.1.0 from any scanner — [Sanicode](https://github.com/rdwj/sanicode), Semgrep, CodeQL, Bandit, SonarQube, SpotBugs — and produces assessor-ready output with no manual translation.

## Quick Start

```bash
pip install stigcode

# Three commands to generate an ATO evidence package from any SARIF scan:
stigcode report scan.sarif -o sa-11-evidence.md
stigcode coverage scan.sarif -o control-coverage.md
stigcode poam scan.sarif -o poam-candidates.md
```

The report maps findings to NIST 800-53 controls as SA-11 evidence. The coverage matrix shows which controls are addressed and which need other evidence. The POA&M candidates give the ISSO a starting point for documenting open findings.

## What It Produces

| Command | Output | Formats | Purpose |
|---------|--------|---------|---------|
| `stigcode report` | SA-11 evidence report | md, pdf | ATO security package artifact for SA-11 / SI-10 |
| `stigcode coverage` | NIST 800-53 coverage matrix | md, csv, pdf | Control family coverage with gap identification |
| `stigcode poam` | POA&M candidates | md, csv, pdf | Draft POA&M entries from open findings |
| `stigcode ckl` | STIG Viewer checklist | ckl (xml) | DISA STIG Viewer 2.x/3.x import |
| `stigcode oscal` | OSCAL Assessment Results | json | Automated ATO pipelines (Trestle, Lula) |
| `stigcode trend` | Trend analysis | md, csv | CA-7 continuous monitoring evidence |

## Scanner Examples

```bash
# Sanicode (enriched SARIF with STIG metadata — highest confidence)
sanicode scan ./app --format sarif -o scan.sarif
stigcode report scan.sarif -o sa-11-evidence.md

# Semgrep (standard SARIF with CWE tags — inferred mapping)
semgrep --config auto --sarif -o scan.sarif ./app
stigcode report scan.sarif -o sa-11-evidence.md

# CodeQL
codeql database analyze app-db --format=sarif-latest --output=scan.sarif
stigcode report scan.sarif -o sa-11-evidence.md

# Bandit
bandit -r ./app -f sarif -o scan.sarif
stigcode report scan.sarif -o sa-11-evidence.md

# Pipeline mode (stdin)
sanicode scan --format sarif ./app | stigcode report - -o sa-11-evidence.md
```

## How It Works

Stigcode uses a curated CWE→STIG mapping database to translate scanner findings into compliance language:

```
SARIF Input (any scanner)
    │
    ▼
┌──────────────────────┐
│  SARIF Ingestion     │  Parse results, extract CWE/STIG metadata
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Mapping Engine      │  CWE→STIG→NIST resolution with confidence levels
└──────────┬───────────┘
           │
    ┌──────┼──────┬──────┬──────┬──────┐
    ▼      ▼      ▼      ▼      ▼      ▼
 Report  Coverage POA&M  CKL   OSCAL  Trend
```

Every mapping carries a confidence level — `direct` (scanner provided explicit STIG IDs), `inferred` (mapped via CWE), or `partial` (incomplete coverage) — so assessors know what to review manually.

The mapping database covers the Application Security and Development STIG V6R3 with 126 CWE→STIG mappings across 80 SAST-assessable findings. The remaining 206 procedural findings (CCB processes, security training, backup procedures, etc.) are marked Not Reviewed with a clear note that they require human assessment.

## Additional Commands

```bash
# Verify a SARIF file parses correctly before generating output
stigcode validate scan.sarif

# Quick assessment summary
stigcode assess scan.sarif

# STIG Viewer checklist (with incremental update support)
stigcode ckl scan.sarif -o checklist.ckl
stigcode ckl scan.sarif --update existing.ckl -o updated.ckl

# OSCAL Assessment Results for automated ATO pipelines
stigcode oscal scan.sarif -o assessment-results.json

# Trend analysis across multiple scans (CA-7 evidence)
stigcode trend results/ -o trend-report.md

# Bidirectional mapping lookups
stigcode lookup cwe --cwe 89
stigcode lookup stig --stig V-222607

# Mapping database stats and cross-reference export
stigcode info mappings --output xref.md
```

## Air-Gapped Deployment

Stigcode is designed for disconnected environments. All mapping data ships inside the package — zero network calls at runtime.

```bash
# Container (UBI9 base, non-root, OpenShift-compatible)
podman build -t stigcode:0.1.0 -f Containerfile .
podman run --rm -v ./results:/data:Z stigcode:0.1.0 report /data/scan.sarif -o /data/evidence.md

# OpenShift Job
oc apply -f manifests/job.yaml -n <namespace>

# Standalone RHEL
pip install stigcode
```

See [docs/deployment.md](docs/deployment.md) for container builds, OpenShift manifests, and disconnected installation procedures.

## For Scanner Authors

Want stigcode to produce higher-confidence mappings from your scanner's output? Add CWE tags to your SARIF rules — that's all it takes to reach Standard tier. See the [SARIF Integration Guide](docs/sarif-integration-guide.md) for details and examples.

## Documentation

- [Getting Started](docs/getting-started.md) — installation, first commands, scanner examples
- [User Guide](docs/user-guide.md) — complete workflow reference
- [Context and Usage](docs/stigcode-context-and-usage.md) — how STIGs and ATO actually work for custom code
- [Architecture](docs/architecture.md) — data flow, components, design decisions
- [SARIF Contract](docs/sarif-contract.md) — technical spec for SARIF integration
- [SARIF Integration Guide](docs/sarif-integration-guide.md) — guide for scanner authors
- [Deployment](docs/deployment.md) — container builds, OpenShift, air-gapped installation

## Companion Project

[Sanicode](https://github.com/rdwj/sanicode) is an AI-powered SAST scanner purpose-built for air-gapped and sovereign environments. It produces enriched SARIF with explicit STIG metadata, giving stigcode the highest-confidence compliance mappings. Stigcode works with any SARIF producer, but Sanicode + Stigcode together provide the tightest scanner-to-compliance pipeline.

## License

Apache-2.0
