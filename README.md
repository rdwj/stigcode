# Stigcode

**SARIF-to-compliance bridge.** Transforms SAST scan results from any scanner into DISA STIG checklists, ATO evidence artifacts, and compliance-native output.

Stigcode is the compliance companion to [Sanicode](https://github.com/rdwj/sanicode). While Sanicode scans code for vulnerabilities, Stigcode transforms those findings into the formats that ISSOs, assessors, and authorizing officials actually need.

## Status

This project is in early development. See the [issue tracker](https://github.com/rdwj/stigcode/issues) for planned work.

## Architecture

```
Source Code → [Any SAST Scanner] → SARIF v2.1.0 → [Stigcode] → CKL / ATO Reports / OSCAL
```

Stigcode consumes SARIF from any scanner (Sanicode, Semgrep, CodeQL, SonarQube, Bandit, SpotBugs) and produces:

- **DISA STIG Viewer `.ckl` files** — import directly into assessment workflows
- **ATO evidence reports** — PDF/Markdown summaries for ATO packages
- **NIST 800-53 coverage matrices** — control family coverage with gap identification
- **OSCAL output** (future) — for automated ATO pipelines

## License

Apache-2.0
