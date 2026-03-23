# Stigcode — Background Research

## CKL Files

CKL (Checklist) files are the native format for DISA STIG Viewer. They are XML documents that represent a completed STIG assessment for a specific system or application.

### XML Structure

A CKL file contains:

- **`<ASSET>`** — Target system metadata (hostname, IP, role, technology area)
- **`<STIGS>`** — Container for one or more STIG checklists
  - **`<iSTIG>`** — A single STIG checklist
    - **`<STIG_INFO>`** — STIG metadata (title, version, release, UUID)
    - **`<VULN>`** — Individual vulnerability/check entries, each containing:
      - **`<STIG_DATA>`** elements with attribute-value pairs:
        - `Vuln_Num` (V-XXXXXX)
        - `Rule_ID` (SV-XXXXXXrXXXXXX_rule)
        - `Rule_Ver` (APSC-DV-XXXXXX)
        - `Severity` (high/medium/low → CAT I/II/III)
        - `CCI_REF` (CCI-XXXXXX references)
        - `Rule_Title`, `Vuln_Discuss`, `Fix_Text`, `Check_Content`
      - **`<STATUS>`** — Finding status: `Open`, `NotAFinding`, `Not_Reviewed`, `Not_Applicable`
      - **`<FINDING_DETAILS>`** — Evidence text (scanner output goes here)
      - **`<COMMENTS>`** — Assessor notes (confidence level and mapping source go here)
      - **`<SEVERITY_OVERRIDE>`** — Optional severity adjustment with justification

### Key Implementation Notes

- The CKL schema is not formally published as an XSD by DISA; implementations reverse-engineer from STIG Viewer's output
- Element order matters for STIG Viewer import compatibility
- Empty elements must be present (e.g., `<COMMENTS></COMMENTS>`) rather than omitted
- STIG Viewer 2.x and 3.x accept the same CKL format


## STIG Viewer

DISA STIG Viewer is the standard tool for reviewing and completing STIG checklists. Two major versions are relevant:

### STIG Viewer 2.x (Legacy)

- Java application, downloadable from DISA's public.cyber.mil
- Reads and writes CKL files
- Supports importing STIG libraries (XCCDF bundles)
- Widely deployed; many organizations still use it

### STIG Viewer 3.x (Current)

- Electron-based application, replacing the Java version
- Reads CKL files (backward compatible)
- Introduces `.cklb` format (JSON-based, but CKL XML remains supported)
- Adds features: multi-user review, dashboard views, enhanced filtering
- CKL import is the primary interoperability path

For stigcode, targeting CKL XML output ensures compatibility with both versions.


## Identifier Hierarchy

Understanding the DISA identifier chain is critical for correct mapping:

```
V-222607                    DISA STIG Viewer vulnerability number
  └── SV-222607r879887_rule   STIG rule ID (V-ID + revision)
        └── APSC-DV-002540      ASD STIG check ID / Rule_Ver
              └── CCI-002754        Control Correlation Identifier
                    └── SI-10           NIST 800-53 rev5 control
```

- **V-XXXXXX**: The stable vulnerability number that ISSOs and assessors reference. This is the primary key in CKL files.
- **SV-XXXXXXrXXXXXX_rule**: The rule ID, which includes a revision number. Changes when the STIG check is updated.
- **APSC-DV-XXXXXX**: The ASD STIG check ID (also called Rule_Ver). Groups related V-IDs by check category.
- **CCI-XXXXXX**: Control Correlation Identifier. Bridges STIG checks to NIST 800-53 controls. A single STIG check may reference multiple CCIs.
- **NIST 800-53 control**: The actual security control (e.g., SI-10 "Information Input Validation"). CCIs decompose controls into testable statements.


## CCI → NIST 800-53 Mapping

Control Correlation Identifiers (CCIs) are published by DISA as an XML file. Each CCI maps to exactly one NIST 800-53 control, but a single control may have many CCIs. The CCI list also tracks which revision of 800-53 each CCI references (rev4 vs rev5).

Source: [DISA CCI List](https://public.cyber.mil/stigs/cci/) (XML download)

The mapping chain for stigcode:
1. SARIF finding → CWE ID
2. CWE ID → STIG check (APSC-DV ID) via stigcode's mapping database
3. STIG check → CCI references (from XCCDF/STIG data)
4. CCI → NIST 800-53 control (from CCI XML)

This chain is what enables stigcode to generate NIST 800-53 coverage matrices from raw scanner output.


## XCCDF Format

XCCDF (Extensible Configuration Checklist Description Format) is the XML format DISA uses to publish STIGs. Each STIG release is an XCCDF bundle containing:

- **Benchmark XML** — The full STIG: all rules, check content, fix text, severity, CCI references
- **Manual XCCDF** — Same content structured for manual assessment
- **SCAP content** — Automated check definitions (OVAL) for applicable STIGs

Stigcode uses parsed XCCDF data to populate its STIG metadata database (`data/stigs/`). The relevant fields extracted from XCCDF:

- Rule `id` → V-ID and SV-ID
- `version` element → APSC-DV check ID (Rule_Ver)
- `title` → Rule title
- `severity` attribute → CAT level
- `ident` elements → CCI references
- `fixtext` → Remediation guidance
- `check-content` → Assessment procedure

Source: [DISA STIG Library](https://public.cyber.mil/stigs/downloads/) (ZIP bundles per technology)


## OSCAL Format (Future)

NIST OSCAL (Open Security Controls Assessment Language) is an emerging standard for machine-readable security assessment artifacts. It defines JSON, XML, and YAML schemas for:

- **System Security Plans (SSP)** — How controls are implemented
- **Assessment Plans (AP)** — What will be assessed and how
- **Assessment Results (AR)** — Findings from assessments
- **Plan of Action and Milestones (POA&M)** — Remediation tracking

OSCAL Assessment Results would be a natural output format for stigcode, complementing CKL output. Benefits:

- Machine-readable (JSON/XML with formal schemas)
- Maps directly to NIST 800-53 controls
- Supports continuous ATO (cATO) workflows
- Growing adoption in federal agencies and FedRAMP

OSCAL output is planned for a future release. The `nist-sp800-53-rev5` OSCAL catalog and the OSCAL AR schema would be the starting points.

Source: [NIST OSCAL Project](https://pages.nist.gov/OSCAL/)


## Key DISA Resources

- [DISA STIG Library](https://public.cyber.mil/stigs/downloads/) — All published STIGs (XCCDF bundles)
- [DISA CCI List](https://public.cyber.mil/stigs/cci/) — CCI → NIST 800-53 mapping XML
- [STIG Viewer Downloads](https://public.cyber.mil/stigs/srg-stig-tools/) — STIG Viewer 2.x and 3.x
- [DISA Application Security STIG](https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=app-security) — The primary STIG for software development findings (current: v6)
- [NIST 800-53 rev5 Control Catalog](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) — Security and privacy controls
- [NIST OSCAL](https://pages.nist.gov/OSCAL/) — Open Security Controls Assessment Language
- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) — OASIS SARIF v2.1.0 standard
- [CWE List](https://cwe.mitre.org/) — Common Weakness Enumeration
