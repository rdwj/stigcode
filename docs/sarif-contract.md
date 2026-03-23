# SARIF Integration Contract

## 1. Overview

SARIF v2.1.0 (Static Analysis Results Interchange Format) is the integration format between SAST scanners and stigcode. Any tool that produces valid SARIF can feed stigcode's compliance pipeline.

Stigcode supports three tiers of SARIF input, differentiated by the richness of compliance metadata embedded in the results:

| Tier | Description | Confidence | Example Scanners |
|------|-------------|------------|------------------|
| **Enriched** | SARIF with explicit STIG IDs and full compliance metadata | `direct` | Sanicode |
| **Standard** | SARIF with CWE identifiers on results or rule descriptors | `inferred` | Semgrep, CodeQL, Bandit |
| **Minimal** | SARIF with rule IDs only, no CWE or STIG metadata | `low` | Generic SARIF exporters |

Higher-tier input produces higher-confidence compliance mappings. Stigcode degrades gracefully: enriched input maps directly to STIG findings with full confidence, while minimal input relies on heuristic rule-ID matching and produces lower-confidence results that assessors should review manually.


## 2. SARIF Result Properties Convention

These optional `properties` fields on SARIF `result` objects allow any scanner to emit compliance metadata that stigcode consumes directly:

```json
{
  "ruleId": "SC006",
  "level": "error",
  "message": {"text": "SQL injection via string concatenation in query builder"},
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {"uri": "src/db/queries.py"},
        "region": {"startLine": 42, "startColumn": 12}
      }
    }
  ],
  "properties": {
    "stigIds": ["V-222607"],
    "stigCheckIds": ["APSC-DV-002540"],
    "cweIds": [89],
    "nist80053": ["SI-10"],
    "stigCategory": "I"
  }
}
```

Field definitions:

| Field | Type | Description |
|-------|------|-------------|
| `stigIds` | `string[]` | DISA STIG Viewer vulnerability numbers (`V-XXXXXX`). Highest confidence mapping. |
| `stigCheckIds` | `string[]` | ASD STIG check IDs / Rule_Ver (`APSC-DV-XXXXXX`). Resolved to V-IDs via stigcode's built-in lookup. |
| `cweIds` | `int[]` | CWE identifiers as integers. Mapped to STIG findings via stigcode's CWE→STIG database. |
| `nist80053` | `string[]` | NIST 800-53 rev5 control family IDs (e.g., `SI-10`, `AC-3`). Used for coverage matrix generation. |
| `stigCategory` | `string` | STIG severity category: `"I"`, `"II"`, or `"III"`. Overrides severity inferred from SARIF `level`. |

All fields are optional. Stigcode extracts whatever is available and uses its resolution priority chain (Section 4) to fill gaps.


## 3. SARIF Rule Properties Convention

The same property fields can appear on `reportingDescriptor` objects in `tool.driver.rules[]`. This is useful when the scanner assigns compliance metadata at the rule level rather than per-result:

```json
{
  "id": "SC006",
  "shortDescription": {"text": "SQL injection via string concatenation"},
  "helpUri": "https://cwe.mitre.org/data/definitions/89.html",
  "properties": {
    "stigIds": ["V-222607"],
    "stigCheckIds": ["APSC-DV-002540"],
    "cweIds": [89],
    "nist80053": ["SI-10"],
    "stigCategory": "I"
  }
}
```

When both result-level and rule-level properties exist, result-level properties take precedence. Rule-level properties serve as defaults for all results referencing that rule.

Stigcode also recognizes standard SARIF CWE tagging on rule descriptors via the `relationships` array with `superset` relationships to CWE taxonomy entries. This is the mechanism used by Semgrep and CodeQL.


## 4. Resolution Priority

When stigcode processes a SARIF result, it resolves STIG finding mappings using this priority chain. Earlier sources take precedence:

1. **`result.properties.stigIds`** — Explicit V-IDs provided by the scanner. Confidence: `direct`. No resolution needed; these map 1:1 to STIG Viewer findings.

2. **`result.properties.stigCheckIds`** — APSC-DV check IDs. Resolved to V-IDs using stigcode's built-in APSC-DV → V-ID lookup table (derived from DISA XCCDF data). Confidence: `direct`.

3. **`result.properties.cweIds`** or **CWE tags on the rule descriptor** — CWE identifiers mapped to STIG findings via stigcode's CWE→STIG mapping database. A single CWE may map to multiple STIG findings (e.g., CWE-89 maps to both V-222607 and V-222604). Confidence: `inferred`.

4. **Rule ID heuristics** — If the rule ID or rule name contains known vulnerability patterns (e.g., `sqli`, `xss`, `cmdi`, `path-traversal`), stigcode attempts CWE inference from those patterns. Confidence: `low`.

Each finding in the output carries its confidence level, allowing assessors to prioritize review of lower-confidence mappings.


## 5. Severity Mapping

SARIF `level` values map to STIG severity categories:

| SARIF `level` | STIG Category | Description |
|---------------|---------------|-------------|
| `error` | CAT I | Critical vulnerability, must fix |
| `warning` | CAT II | Moderate vulnerability, should fix |
| `note` | CAT III | Low-risk finding, best practice |
| `none` | — | Informational, not mapped to STIG |

If `properties.stigCategory` is present on either the result or its rule descriptor, it takes precedence over the `level`-based inference. This allows scanners to override severity for specific findings where the STIG category differs from the scanner's default severity assessment.


## 6. Sanicode Extended Properties

Sanicode (the companion scanner) emits additional rich metadata in `result.properties.compliance`:

```json
{
  "properties": {
    "cwe_id": 89,
    "compliance": {
      "cwe_id": 89,
      "cwe_name": "SQL Injection",
      "owasp_asvs": [{"id": "v5.0.0-1.2.4", "title": "...", "level": "L1"}],
      "nist_800_53": ["SI-10"],
      "asd_stig": [{"id": "APSC-DV-002540", "cat": "I", "title": "..."}],
      "pci_dss": ["6.2.3"],
      "fedramp": ["moderate", "high"],
      "cmmc": [{"id": "SI.L2-3.14.1", "level": 2, "title": "..."}],
      "remediation": "Use parameterized queries..."
    },
    "tags": ["injection", "sql"],
    "domain": "user_facing",
    "action": "fix"
  }
}
```

Stigcode can use these extended properties for enhanced report generation (e.g., including OWASP ASVS references, PCI DSS mappings, and remediation guidance in ATO evidence reports). However, this nested `compliance` object is **not** part of the scanner-agnostic contract. Scanners other than sanicode are not expected to emit it.

When `properties.compliance.asd_stig` is present, stigcode extracts APSC-DV IDs from it as an additional source, equivalent to `properties.stigCheckIds` in priority.


## 7. Compatibility Matrix

| Scanner | `stigIds` | `stigCheckIds` | `cweIds` | CWE in rules | Tier | Notes |
|---------|-----------|----------------|----------|---------------|------|-------|
| Sanicode | Yes | Yes | Yes | Yes | Enriched | Full compliance metadata via `properties.compliance` |
| Semgrep | No | No | Yes (some) | Yes | Standard | CWE via rule `relationships` or metadata tags |
| CodeQL | No | No | Yes | Yes | Standard | CWE via `relationships` to CWE taxonomy |
| Bandit (SARIF) | No | No | Yes | Partial | Standard | CWE in some rules, not all |
| SonarQube | No | No | Some | Some | Minimal–Standard | SARIF export varies by edition |
| Checkov | No | No | No | No | Minimal | Infrastructure-as-code focus, limited CWE tagging |
| SpotBugs | No | No | Yes | Yes | Standard | Java-focused, good CWE coverage |
| Trivy | No | No | Some | Some | Minimal–Standard | Primarily SCA/container, limited SAST CWE |


## 8. Example SARIF Documents

### 8.1 Enriched SARIF (Sanicode-Style)

Complete minimal SARIF with explicit STIG IDs and full compliance metadata:

```json
{
  "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "sanicode",
          "version": "0.4.0",
          "informationUri": "https://github.com/rdwj/sanicode",
          "rules": [
            {
              "id": "SC006",
              "shortDescription": {"text": "SQL injection via string concatenation"},
              "helpUri": "https://cwe.mitre.org/data/definitions/89.html",
              "properties": {
                "stigIds": ["V-222607"],
                "stigCheckIds": ["APSC-DV-002540"],
                "cweIds": [89],
                "nist80053": ["SI-10"],
                "stigCategory": "I"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "SC006",
          "level": "error",
          "message": {"text": "SQL injection: user input flows into query without parameterization"},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "src/db/queries.py", "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": 42, "startColumn": 12, "endLine": 42, "endColumn": 58}
              }
            }
          ],
          "properties": {
            "stigIds": ["V-222607"],
            "stigCheckIds": ["APSC-DV-002540"],
            "cweIds": [89],
            "nist80053": ["SI-10"],
            "stigCategory": "I"
          }
        }
      ]
    }
  ]
}
```

### 8.2 Standard SARIF (CWE-Only, e.g., from Semgrep)

SARIF with CWE information but no explicit STIG IDs. Stigcode infers STIG mappings via its CWE→STIG database:

```json
{
  "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "semgrep",
          "version": "1.56.0",
          "informationUri": "https://semgrep.dev",
          "rules": [
            {
              "id": "python.lang.security.audit.dangerous-system-call.dangerous-system-call",
              "shortDescription": {"text": "Detected dangerous system call with user input"},
              "helpUri": "https://semgrep.dev/r/python.lang.security.audit.dangerous-system-call",
              "defaultConfiguration": {"level": "error"},
              "relationships": [
                {
                  "target": {
                    "id": "78",
                    "guid": "a0a0a0a0-0000-0000-0000-000000000078",
                    "toolComponent": {"name": "CWE", "index": 0}
                  },
                  "kinds": ["superset"]
                }
              ]
            }
          ]
        },
        "extensions": []
      },
      "taxonomies": [
        {
          "name": "CWE",
          "version": "4.14",
          "informationUri": "https://cwe.mitre.org/data/published/cwe_v4.14.pdf",
          "taxa": [
            {
              "id": "78",
              "guid": "a0a0a0a0-0000-0000-0000-000000000078",
              "name": "OS Command Injection"
            }
          ]
        }
      ],
      "results": [
        {
          "ruleId": "python.lang.security.audit.dangerous-system-call.dangerous-system-call",
          "level": "error",
          "message": {"text": "Detected dangerous system call with user-controlled input"},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "src/utils/runner.py"},
                "region": {"startLine": 18, "startColumn": 4}
              }
            }
          ]
        }
      ]
    }
  ]
}
```

In this case, stigcode would:
1. Find no `stigIds` or `stigCheckIds` on the result
2. Find no `cweIds` on the result properties
3. Inspect the rule descriptor and find CWE-78 via the `relationships` array
4. Look up CWE-78 in its CWE→STIG mapping database
5. Map to APSC-DV-002510 → V-222604 with confidence `inferred`
6. Map SARIF `level: "error"` to CAT I (confirmed by APSC-DV-002510's actual CAT I classification)
