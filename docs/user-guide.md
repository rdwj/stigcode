# Stigcode User Guide

Stigcode transforms SARIF scan results from any SAST scanner into compliance-ready artifacts:
SA-11 evidence reports, NIST 800-53 coverage matrices, POA&M candidates, and STIG Viewer
checklists. It bridges the gap between scanner output and the evidence packages that ISSOs
need to assemble for ATO assessments and continuous monitoring.

For installation and quick examples, see [Getting Started](getting-started.md).
For project background and the ATO context, see [Stigcode Context and Usage](stigcode-context-and-usage.md).


## Core Workflow

The typical ISSO workflow for an ATO evidence package. Quick examples for each scanner are in
[Getting Started](getting-started.md).

```bash
# 1. Verify the SARIF parses and review the finding summary
stigcode import scan.sarif

# 2. Generate the three primary ATO artifacts
stigcode report scan.sarif -o sa-11-evidence.md
stigcode coverage scan.sarif -o control-coverage.md
stigcode poam scan.sarif -o poam-candidates.md

# 3. (Optional) Generate a STIG Viewer checklist if the assessment team requires one
stigcode ckl scan.sarif -o app-stig.ckl
```

The report, coverage matrix, and POA&M candidates are the primary deliverables for the SA-11
section of a security package. The assessor uses them to map scan evidence to 800-53 controls
without requiring you to translate findings manually.


## Command Reference

Most commands share three optional overrides for the built-in mapping database:
`-x/--xccdf PATH` (DISA XCCDF XML for full benchmark metadata),
`-m/--mappings PATH` (CWE-to-STIG YAML), and
`-c/--classifications PATH` (finding classifications YAML).
These are only needed if you're supplying custom data; the defaults work out of the box.

### `stigcode import`

Validate and inspect a SARIF file before generating any output. Prints scanner name, finding
counts by severity, and which CWE/STIG metadata was detected. Accepts stdin (`-`).

```bash
stigcode import scan.sarif
sanicode scan ./myapp --format sarif | stigcode import -
```

---

### `stigcode assess`

Print a status breakdown against the STIG benchmark: findings by CAT I/II/III, scan-assessable
vs. procedural, and overall readiness.

```bash
stigcode assess scan.sarif
stigcode assess scan.sarif -x U_ASD_STIG_V6R1_Manual-xccdf.xml
```

---

### `stigcode report`

Generate the SA-11 evidence artifact. Maps findings to NIST 800-53 controls, summarizes
remediated and open findings, and produces an assessor-ready report.

```
Options: -o/--output PATH, -f/--format [md|pdf]
```

```bash
stigcode report scan.sarif -o sa-11-evidence.md
stigcode report scan.sarif -f pdf -o sa-11-evidence.pdf
```

The report includes scanner identification, scan date, findings by severity, per-control status,
confidence level for each mapping, and a finding-by-finding appendix.

---

### `stigcode coverage`

Generate a NIST 800-53 control coverage matrix: which controls the scan addresses, which are
partially covered, and which are out of scope for SAST.

```
Options: -o/--output PATH, -f/--format [md|csv|pdf]
```

```bash
stigcode coverage scan.sarif -o control-coverage.md
stigcode coverage scan.sarif -f csv -o control-coverage.csv
```

---

### `stigcode poam`

Generate POA&M candidates from open findings. Each entry includes severity, affected component,
mapped 800-53 control, CWE, and remediation description. These are candidates — the ISSO
reviews and merges them into the system POA&M with milestone dates and risk justification.

```
Options: -o/--output PATH, -f/--format [md|csv|pdf]
```

```bash
stigcode poam scan.sarif -o poam-candidates.md
stigcode poam scan.sarif -f csv -o poam-candidates.csv
```

---

### `stigcode ckl`

Generate a STIG Viewer 2.x/3.x compatible checklist (.ckl). Scan-assessable findings are
populated with status and evidence; procedural findings are marked `Not_Reviewed`.

```
Options: -o/--output PATH, --host-name TEXT, --host-ip TEXT,
         --classification TEXT [default: UNCLASSIFIED],
         -u/--update PATH (existing CKL to update, preserves assessor notes)
```

```bash
stigcode ckl scan.sarif -o app-stig.ckl --host-name myapp-prod
stigcode ckl scan-new.sarif --update app-stig.ckl -o app-stig-updated.ckl
```

See [Working with STIG Viewer](#working-with-stig-viewer) for how assessors interact with CKL output.

---

### `stigcode trend`

Analyze finding trends across multiple SARIF scans. Produces a report showing findings
introduced, remediated, and net change per scan period. Primary use case is CA-7 continuous
monitoring evidence.

```
stigcode trend [OPTIONS] SARIF_FILES...

Arguments:
  SARIF_FILES    SARIF files or a directory containing *.sarif files

Options:
  -o, --output PATH   Output file (stdout if omitted)
  -f, --format TEXT   md (default) or csv
  --since TEXT        Only include scans on or after this date (YYYY-MM-DD)
```

```bash
# Multiple explicit files
stigcode trend scan-2025-01.sarif scan-2025-02.sarif scan-2025-03.sarif -o trend-q1.md

# Directory of scans
stigcode trend results/ --since 2025-01-01 -o quarterly-trend.md
```

SARIF files must contain scan timestamps in their metadata for trend ordering to work correctly.

---

### `stigcode lookup cwe`

Look up which STIG findings map to a given CWE identifier.

```
stigcode lookup cwe --cwe CWE-ID
```

```bash
stigcode lookup cwe --cwe CWE-89     # SQL Injection
stigcode lookup cwe --cwe 89         # Same — both formats accepted
```

---

### `stigcode lookup stig`

Look up which CWEs map to a given STIG finding.

```
stigcode lookup stig --stig VULN-ID
```

```bash
stigcode lookup stig --stig V-222387
```

---

### `stigcode info mappings`

Show mapping database statistics: total CWE entries, STIG findings covered, confidence
distribution. Optionally write the full cross-reference matrix.

```
stigcode info mappings [OPTIONS]

Options:
  -o, --output PATH   Write full cross-reference matrix to this file
  -x, --xccdf PATH    DISA XCCDF XML for full finding metadata
  -f, --format TEXT   md (default) or csv
```

```bash
stigcode info mappings                          # Stats summary
stigcode info mappings -o matrix.md             # Full matrix in Markdown
stigcode info mappings -o matrix.csv -f csv     # CSV for spreadsheet use
```

---

### `stigcode stig import-xccdf`

Import a STIG benchmark from a DISA XCCDF XML file and print a summary. Used to verify
benchmark data before passing it to other commands via `--xccdf`.

```
stigcode stig import-xccdf XCCDF_FILE
```

```bash
stigcode stig import-xccdf U_ASD_STIG_V6R1_Manual-xccdf.xml
```

XCCDF files are available from [DISA's STIG downloads](https://public.cyber.mil/stigs/downloads/).
They are not bundled with stigcode due to DISA's redistribution policy.


## The Mapping Database

Stigcode's core value is a curated mapping database that translates between scanner output
(CWE IDs, SARIF rule identifiers) and compliance artifacts (NIST 800-53 controls, STIG finding IDs).

**How mappings work.** When stigcode processes a finding, it follows a resolution chain:

1. `result.properties.stigIds` — explicit V-IDs embedded by the scanner. Confidence: `direct`.
2. `result.properties.stigCheckIds` — APSC-DV check IDs, resolved to V-IDs via built-in lookup. Confidence: `direct`.
3. CWE IDs from result properties or rule `relationships` — looked up in the CWE→STIG database. Confidence: `inferred`.
4. Rule ID heuristics (e.g., rule name contains `sqli`, `xss`) — pattern-based CWE inference. Confidence: `low`.

**Confidence levels** appear in all output artifacts:

| Confidence | Meaning |
|------------|---------|
| `direct` | Scanner embedded an explicit STIG or check ID — 1:1 mapping |
| `inferred` | CWE→STIG mapping applied — one CWE may produce multiple STIG findings |
| `partial` | Mapping addresses part of the control, not the full requirement |
| `low` | Rule name heuristic — assessor should verify |

Assessors should pay attention to confidence levels. `direct` mappings can be accepted without
additional review; `low` mappings warrant manual verification.

**SAST vs procedural split.** Of the 286 AppDev STIG findings, approximately 80 are assessable
by SAST scanning and 206 are procedural (require interviews, documentation review, artifacts).
Stigcode only produces automated assessment for the 80 SAST-assessable findings. The rest are
marked `Not_Reviewed` in CKL output.

**Inspecting the database:**

```bash
stigcode info mappings                    # Summary stats
stigcode lookup cwe --cwe CWE-89          # What STIGs map to SQL injection?
stigcode lookup stig --stig V-222607      # What CWEs map to this finding?
```

For the full specification of how scanners embed compliance metadata, see [SARIF Contract](sarif-contract.md).


## Output Formats

**Markdown (`md`)** — Default for all commands. Suitable for inclusion in a security package
document set, Confluence, or any Markdown-aware wiki. Renders well in GitHub.

**CSV (`csv`)** — Available for `coverage`, `poam`, `trend`, and `info mappings`. Use this for
importing into existing compliance tracking spreadsheets (POA&M trackers, control matrices).

**PDF (`pdf`)** — Available for `report`, `coverage`, and `poam`. Produces a print-ready artifact
suitable for direct inclusion in a security package.

Output goes to stdout if `--output` is omitted, enabling pipeline composition:

```bash
stigcode report scan.sarif | pandoc -o sa-11.docx
stigcode coverage scan.sarif -f csv | upload-to-sharepoint.sh
```


## Working with STIG Viewer

**Importing a CKL.** In STIG Viewer, use File → Open → STIG Checklist and select the `.ckl`
file. The tool will show all 286 AppDev STIG findings with status populated for scan-assessable
items.

**What assessors will see.** Three finding statuses appear in CKL output generated by stigcode:

| Status | Meaning |
|--------|---------|
| `Open` | Scanner found a violation; finding has not been remediated |
| `NotAFinding` | Scanner found no violation; mapped STIG check passes |
| `Not_Reviewed` | Procedural finding — requires manual assessment by the assessor |

`Not_Reviewed` is the expected status for the majority (~72%) of AppDev STIG findings. This is
not a problem; it accurately reflects that those findings require human judgment.

**Where confidence appears.** For each scan-assessed finding, stigcode writes the confidence
level and scan evidence into the STIG Viewer `COMMENTS` field. Assessors can see exactly why a
finding was marked `Open` or `NotAFinding` and at what confidence.

**Incremental updates.** When the same application is scanned repeatedly, use `--update` to
apply new scan results to an existing CKL without overwriting assessor notes:

```bash
stigcode ckl new-scan.sarif --update previous.ckl -o updated.ckl
```

Findings that the assessor has manually set to `NotAFinding` or `Not_Applicable` with notes are
preserved. Only scan-assessable findings that stigcode manages are updated.


## Continuous Monitoring

**Periodic scans in CI/CD.** Integrate stigcode into your pipeline to generate fresh evidence
at each scan. Exit codes follow standard conventions: `0` on success, `1` when open findings
exist, `2` on error. A non-zero exit from a reporting command indicates findings that may need
attention but does not indicate a tool failure.

```yaml
# Example: GitHub Actions step
- name: Generate compliance evidence
  run: |
    stigcode report scan.sarif -o artifacts/sa-11-evidence.md
    stigcode poam scan.sarif -f csv -o artifacts/poam-candidates.csv
  # Non-zero exit if open findings — decide whether to block PR
  continue-on-error: true
```

**CA-7 trend evidence.** Run `stigcode trend` monthly or quarterly to produce a trend report
showing remediation velocity. This is the artifact assessors look for to satisfy CA-7
(Continuous Monitoring).

```bash
# Archive SARIF files with datestamped names
sanicode scan ./myapp --format sarif -o results/scan-$(date +%Y%m%d).sarif

# Monthly trend report
stigcode trend results/ --since 2025-01-01 -o monthly-trend.md
```

**Baseline comparison for new findings.** When reviewing a POA&M update, focus on findings
that are new since the last scan. Filter by scan date using `--since` in `trend`, or diff
POA&M CSV exports between periods.


## Scanner Compatibility

Full details in [SARIF Contract](sarif-contract.md).

| Scanner | CWE Method | Enriched | Notes |
|---------|------------|----------|-------|
| Sanicode | `properties.stigIds` | Yes | Highest confidence; embeds STIG IDs and 800-53 directly |
| Semgrep | `relationships` in rules | No | Good CWE coverage via taxonomy references |
| CodeQL | `relationships` in rules | No | Good CWE coverage; standard SARIF |
| Bandit | Tags (partial) | No | Python only; CWE coverage varies by rule |
| SonarQube | Varies by edition | No | SARIF export requires plugin; coverage varies |
| SpotBugs | `relationships` in rules | No | Java-focused; good CWE coverage |
| Trivy | `properties.CweIDs` | No | Primarily container/SCA; limited SAST CWE |

Any SARIF v2.1.0 output will work. Scanners without CWE metadata fall back to rule ID heuristics;
expect `low` confidence for those findings and plan for more manual review.


## Air-Gapped Deployment

For deployment in classified or disconnected environments, see `docs/deployment.md` (in progress).
The key considerations: stigcode makes no network calls at runtime, the mapping database ships
with the package, and DISA XCCDF files must be obtained separately and passed via `--xccdf`.


## FAQ

**What does `Not_Reviewed` mean in the CKL?**

The finding is procedural — it cannot be assessed by a scanner. Examples: "Does the team have
a Configuration Control Board?" or "Is there a documented threat model?" The assessor satisfies
these through interviews and documentation review. `Not_Reviewed` is the correct and expected
status for ~72% of AppDev STIG findings until the assessor completes that work.

**Why are only ~80 of 286 AppDev STIG findings assessed?**

The AppDev STIG V6 has 286 findings; ~206 are procedural. Stigcode maps scan results to the
~80 that SAST can actually assess (injection flaws, input validation, error handling, etc.).
Claiming automated assessment of procedural findings would misrepresent the evidence.

**Can I trust a `NotAFinding` status?**

Trust is proportional to confidence. A `direct`-confidence `NotAFinding` means the scanner
explicitly checked for that STIG finding and found nothing. An `inferred`-confidence
`NotAFinding` means the CWE→STIG mapping produced no match, but the scanner may not have full
coverage of that CWE. Check the COMMENTS field in STIG Viewer for the evidence and confidence
level before accepting it.

**How do I add findings the scanner missed?**

Stigcode consumes what the scanner reports. Fix coverage at the scanner level (tune rules,
add custom rules) and re-scan. Manual findings can be added directly in STIG Viewer and are
preserved by `--update` on subsequent scans.

**What if my scanner isn't listed?**

Any valid SARIF v2.1.0 output works. Scanners with CWE identifiers on rules get `inferred`
confidence; those without fall back to rule ID heuristics. Run `stigcode import` on the output
first to see what metadata was detected.

**Can I use stigcode without STIG Viewer?**

Yes. The `report`, `coverage`, and `poam` commands produce Markdown, CSV, and PDF with no
dependency on STIG Viewer. CKL output is only needed when an assessment team explicitly
requires a checklist file.
