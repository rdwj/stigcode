# Stigcode: Bridging Application Security Scanning and Federal Compliance

## How Security Compliance Actually Works for Custom Software

### The STIG Landscape Teams Know

Most teams with experience in DoD or federal environments are familiar with STIGs as something applied to infrastructure. A team deploying an application on RHEL runs the RHEL 9 STIG through SCAP (Security Content Automation Protocol), gets a machine-readable checklist, remediates the findings, and hands the results to their assessor. The same pattern applies to PostgreSQL, Apache, OpenShift, Windows Server, network devices, and dozens of other products. These STIGs have automated check and fix content — you can scan a host with `oscap` or DISA's SCC tool and get a scored report in minutes.

This workflow is well-understood, well-tooled, and largely automated. It is also entirely focused on the platform and infrastructure layer.

### What Happens to the Application Code

Custom application code lives in a different compliance universe. There is exactly one STIG that addresses it — the Application Security and Development STIG (currently Version 6, February 2025, with 286 findings). But unlike the RHEL or PostgreSQL STIGs, the AppDev STIG is almost entirely procedural. Its findings ask questions like:

- Does the development team follow coding standards? (V-222653)
- Is there a Configuration Control Board that meets every release cycle? (V-222633)
- Has a threat model been documented? (V-222655)
- Does a security tester exist on the team? (V-222646)
- Are backup copies stored in a fire-rated container? (V-222639)

These are not things a scanner can check. An assessor satisfies them through interviews, documentation review, and artifact collection. Most development teams have never heard of the AppDev STIG, and many ATO assessments do not explicitly walk through it finding-by-finding. Instead, the relevant security concerns are addressed through NIST 800-53 controls.

### The ATO Process: NIST 800-53, Not STIGs

When a system needs authorization to operate on a DoD or federal network, the governing framework is NIST 800-53 (via the Risk Management Framework, NIST SP 800-37). The process works like this:

1. **Categorize** the system using FIPS 199 (low, moderate, high impact)
2. **Select** applicable security controls from NIST 800-53 based on the impact level
3. **Implement** those controls across the system — code, infrastructure, operations, and policy
4. **Assess** the controls — an independent assessor validates that each control is satisfied
5. **Authorize** — the Authorizing Official reviews the security package and grants (or denies) the ATO

STIGs are one mechanism for implementing and demonstrating compliance with 800-53 controls. When you apply the RHEL STIG, you're satisfying a subset of 800-53 controls (AC, AU, CM, IA, SC, SI, etc.) for the operating system layer. But STIGs are not the only way, and for custom application code, they're rarely the primary mechanism.

For custom software, the relevant 800-53 controls are typically satisfied through a combination of:

- **SA-11 (Developer Testing and Evaluation):** Evidence that the development team performs security testing, including SAST, DAST, and penetration testing
- **SI-10 (Information Input Validation):** Evidence that the application validates input
- **SI-11 (Error Handling):** Evidence that error messages don't disclose sensitive information
- **SC-8 (Transmission Confidentiality and Integrity):** Evidence of TLS implementation
- **SC-28 (Protection of Information at Rest):** Evidence of encryption at rest
- **IA-2 (Identification and Authentication):** Evidence of authentication mechanisms
- **AC-3 (Access Enforcement):** Evidence of authorization controls
- **AU-2/AU-3 (Audit Events / Content of Audit Records):** Evidence of audit logging

In practice, the assessment team reviews scan reports, test results, architecture documentation, and operational procedures as evidence for these controls. They do not typically generate a CKL file against the AppDev STIG for each application.

### What Assessors Actually Want to See

An assessor evaluating custom application code for an ATO package is looking for specific artifacts:

- A SAST scan report showing what was tested, what was found, and what was remediated
- A vulnerability assessment or penetration test report
- Documentation of the SDLC security practices (does the team do code review, threat modeling, security training)
- Architecture documentation showing how security controls are implemented (authentication flow, encryption configuration, network segmentation)
- A Plan of Action and Milestones (POA&M) for any open findings

The assessor maps these artifacts to 800-53 controls in the Security Assessment Report (SAR). They might write something like:

> **SA-11 (Developer Testing and Evaluation):** Satisfied. The development team performs automated static analysis using [tool name]. Scan report dated [date] shows [N] findings identified, [M] remediated, [K] accepted with documented risk justification. See Appendix D, Artifact SA-11-001.

The scan report is evidence. The assessor does the mapping. There is no CKL involved for the application code.

---

## Where Stigcode Fits

Given this reality, Stigcode's value is not in generating AppDev STIG checklists — that's a niche workflow that most teams don't follow. The value is in reducing the manual work that sits between a scan result and an assessor-ready evidence package.

### The Gap Stigcode Fills

Today, the workflow looks like this:

1. Developer runs a SAST tool and gets a SARIF or JSON report
2. Security engineer reviews the findings, triages, and tracks remediation
3. When ATO assessment approaches, someone (usually the ISSO or a security engineer) manually:
   - Writes a narrative summary of the scan results
   - Maps the findings to the relevant 800-53 controls
   - Formats the evidence for the security package
   - Prepares a POA&M for any open findings
   - Answers assessor questions about which controls are covered by scanning

This manual translation step takes days and is error-prone. Every organization does it differently. And it repeats every time the system goes through continuous monitoring or reauthorization.

### What Stigcode Does

Stigcode takes SARIF input from any SAST tool and produces compliance-ready output:

**800-53 Control Evidence Reports.** Given a SARIF file, Stigcode maps findings to NIST 800-53 controls and generates a report that an assessor can directly reference. The report includes which controls are addressed by scan coverage, which findings exist against each control, and what the finding status is (open, remediated, risk-accepted). This is the artifact the assessor attaches to SA-11 in the SAR.

**Control Coverage Matrix.** A structured view showing which 800-53 controls are addressed by the scan, which are partially covered, and which are out of scope for SAST. This helps the ISSO understand what the scan does and doesn't prove, and plan for how to address the gaps (penetration testing, manual review, architectural documentation).

**POA&M Input.** Open findings from the scan, formatted as potential POA&M entries with severity, affected component, planned remediation, and mapped control. The ISSO can review and incorporate these into the system's existing POA&M rather than transcribing from a scan report by hand.

**Trend Analysis.** When given a series of SARIF files over time, Stigcode produces trend data showing findings introduced, findings remediated, and coverage changes. This supports continuous monitoring requirements (CA-7) and demonstrates that the development team is actively managing security posture.

**CKL Export (Secondary).** For the minority of assessments that do walk through the AppDev STIG finding-by-finding, Stigcode can generate a CKL file. But this is a secondary output, not the primary use case. The CKL maps scan findings to the subset of AppDev STIG findings that are detectable by SAST, marks them accordingly, and flags the procedural findings as Not Reviewed (since they require human assessment).

### What Stigcode Does Not Do

Stigcode does not perform scanning. It does not replace a SAST tool. It does not satisfy procedural or operational controls — it cannot tell an assessor whether the team has a CCB, whether developers receive annual security training, or whether backups are stored in a fire-rated container. It explicitly identifies which compliance requirements are outside its scope.

Stigcode also does not make compliance determinations. It presents evidence and mappings. The assessor makes the determination. The output is designed to make the assessor's job easier, not to replace their judgment.

---

## Usage Scenarios

### Scenario 1: ATO Assessment for a New Application

A team is building a Python/React application for deployment on an IL4 OpenShift cluster. The system is categorized as moderate impact. The ISSO needs to prepare the security package for the assessor.

```
# Developer runs Sanicode (or any SAST tool) and produces SARIF
sanicode scan ./app --format sarif -o scan-results.sarif

# ISSO runs Stigcode to generate evidence artifacts
stigcode report --input scan-results.sarif --format pdf -o sa-11-evidence.pdf
stigcode coverage --input scan-results.sarif --format xlsx -o control-coverage.xlsx
stigcode poam --input scan-results.sarif --format xlsx -o poam-candidates.xlsx
```

The ISSO includes `sa-11-evidence.pdf` in the security package as the SA-11 evidence artifact. The control coverage matrix informs the assessor which controls are addressed by scanning and which need other evidence. The POA&M candidates give the ISSO a starting point for documenting open findings.

### Scenario 2: Continuous Monitoring and Reauthorization

The application has an active ATO and undergoes continuous monitoring. Every sprint, the CI/CD pipeline runs a SAST scan. The ISSO needs to demonstrate ongoing security posture.

```
# CI/CD pipeline produces SARIF on every merge to main
sanicode scan ./app --format sarif -o results/scan-$(date +%Y%m%d).sarif

# Monthly, the ISSO generates a trend report for the continuous monitoring package
stigcode trend --input-dir results/ --since 2025-01-01 --format pdf -o monthly-trend.pdf
stigcode poam --input results/scan-latest.sarif --baseline results/scan-previous.sarif -o new-findings.xlsx
```

The trend report shows the assessor that the team is actively scanning, remediating, and maintaining security posture. New findings since the last period are flagged for POA&M review.

### Scenario 3: Scanner-Agnostic Compliance Bridge

An organization uses Semgrep for open-source projects and SonarQube for their Java enterprise apps. They need consistent compliance evidence across both.

```
# Semgrep output
semgrep --config auto --sarif -o semgrep-results.sarif ./open-source-app

# SonarQube export (via sonar-sarif-export or API)
sonar-export --project enterprise-app --format sarif -o sonar-results.sarif

# Stigcode normalizes both into the same evidence format
stigcode report --input semgrep-results.sarif --format pdf -o oss-app-evidence.pdf
stigcode report --input sonar-results.sarif --format pdf -o enterprise-app-evidence.pdf
stigcode coverage --input semgrep-results.sarif sonar-results.sarif --format xlsx -o org-coverage.xlsx
```

The organization gets consistent evidence artifacts regardless of which scanner produced the results. The org-wide coverage matrix shows the CISO which 800-53 controls are addressed across the portfolio.

### Scenario 4: AppDev STIG Checklist (When Required)

Some assessment teams or agency-specific policies do require a completed AppDev STIG checklist. In these cases, Stigcode can generate one, with the understanding that most findings will be marked Not Reviewed (procedural) and the SAST-assessable findings will be populated from scan results.

```
stigcode ckl --input scan-results.sarif --stig app-security-v6 --profile mac2-sensitive -o app-stig.ckl
```

The CKL can be opened in STIG Viewer. Scan-assessable findings are populated with status and evidence. Procedural findings are flagged for manual assessment. The assessor completes the remaining findings through interviews and documentation review.

---

## The Mapping Engine

Stigcode's core value is its mapping database — a curated, version-controlled dataset that translates between the language of scanners (CWE IDs, SARIF rule identifiers) and the language of compliance (NIST 800-53 controls, STIG finding IDs, CCI references).

The mapping works in layers:

1. **CWE → 800-53 Control.** CWE-89 (SQL Injection) maps to SI-10 (Information Input Validation). This is the most commonly needed translation and is well-established in the security community.

2. **CWE → STIG Finding ID.** CWE-89 maps to V-222607 in the AppDev STIG. This is a more specialized mapping, useful when CKL export is needed.

3. **SARIF Rule → CWE.** Most SAST tools include CWE references in their SARIF output. Stigcode uses these as the entry point into the mapping chain.

4. **Enriched SARIF (optional).** When the SARIF producer embeds explicit STIG or 800-53 metadata (as Sanicode does via `properties.stigIds` and `properties.nist80053`), Stigcode uses these directly for higher-confidence mappings.

Each mapping carries a confidence level:

- **Direct:** The mapping is explicitly defined in the source material (e.g., CWE-89 is cited in V-222607's description)
- **Inferred:** The mapping is derived from related CWEs or control descriptions but not explicitly stated
- **Partial:** The mapping addresses part of the control requirement but not all of it

The mapping database is stored as version-controlled YAML, versioned alongside the STIG versions it covers, and open for community contribution.

---

## What Stigcode is Not

To avoid misaligned expectations:

- **Not a scanner.** It does not analyze source code. It consumes scan results.
- **Not a compliance determination tool.** It presents evidence and mappings. Assessors make determinations.
- **Not a replacement for an ISSO.** It reduces manual work but does not eliminate the need for a knowledgeable security professional to prepare and present the security package.
- **Not limited to Sanicode output.** It works with any SARIF-producing scanner. Sanicode's enriched SARIF provides richer mappings, but Stigcode is useful without it.
- **Not a silver bullet for ATO.** Application security scanning addresses a subset of 800-53 controls. The majority of an ATO package involves infrastructure hardening, access control policy, incident response procedures, and operational documentation that have nothing to do with SAST results.
