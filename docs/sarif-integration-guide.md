# SARIF Integration Guide for Scanner Authors

This guide explains how to embed STIG compliance metadata in your SARIF output so stigcode can produce high-confidence compliance artifacts from your scan results.

**Time to read:** ~10 minutes. For the full technical specification, see [`sarif-contract.md`](sarif-contract.md).


## The Three Tiers

Stigcode supports three levels of SARIF integration, in order of output quality:

| Tier | What you provide | Mapping confidence | Example output |
|------|------------------|--------------------|----------------|
| **Enriched** | Explicit STIG IDs (`stigIds`) | `direct` — 1:1 to STIG Viewer | CKL populated with exact V-IDs, no review needed |
| **Standard** | CWE identifiers (any method) | `inferred` — lookup via CWE→STIG database | CKL with mapped findings, assessor review recommended |
| **Minimal** | Rule IDs only | `low` — rule-name heuristics | CKL populated with low-confidence placeholders |

Most SAST tools can reach Standard tier with one small change. Enriched tier is for tools with STIG-specific rule sets.


## Quick Start: Standard Tier in One Step

Add CWE tags to your rule definitions. This is all stigcode needs to map findings to STIG controls:

```json
{
  "runs": [{
    "tool": {
      "driver": {
        "name": "my-scanner",
        "version": "1.0.0",
        "rules": [{
          "id": "sql-injection",
          "shortDescription": {"text": "SQL injection via user input"},
          "properties": {
            "tags": ["security", "external/cwe/cwe-89"]
          }
        }]
      }
    }
  }]
}
```

The tag format `external/cwe/cwe-NNN` is the convention used by Semgrep and CodeQL. Stigcode recognizes it on rule descriptors.


## Standard Tier: All Supported CWE Methods

Stigcode extracts CWE information from four locations, tried in this priority order:

### 1. Result properties — `cweIds`

Attach CWE IDs directly to individual results for the most precise per-finding control:

```json
{
  "ruleId": "sql-injection",
  "level": "error",
  "message": {"text": "User input flows into SQL query"},
  "properties": {
    "cweIds": [89]
  },
  "locations": [...]
}
```

### 2. Rule tags — `external/cwe/cwe-NNN`

Set CWE at the rule level and it applies to all results from that rule:

```json
{
  "id": "sql-injection",
  "properties": {
    "tags": ["security", "external/cwe/cwe-89"]
  }
}
```

Multiple CWEs are supported — just add multiple tags.

### 3. SARIF taxonomy relationships

The formal SARIF mechanism for linking rules to external taxonomies (used by CodeQL):

```json
{
  "id": "sql-injection",
  "relationships": [{
    "target": {
      "id": "89",
      "toolComponent": {"name": "CWE"}
    },
    "kinds": ["superset"]
  }]
}
```

This requires a `taxonomies` entry for the CWE taxonomy in the run. See the full spec for details.

### 4. Message text (fallback)

Stigcode will extract `CWE-NNN` references from result message text as a last resort. This is the lowest confidence method and is not recommended as a primary approach — prefer one of the methods above.


## Enriched Tier: Explicit STIG Metadata

If your tool has a STIG-specific rule set, you can provide explicit STIG identifiers that stigcode maps directly to STIG Viewer findings with no inference required:

```json
{
  "ruleId": "sql-injection",
  "level": "error",
  "message": {"text": "SQL injection: user input flows into query without parameterization"},
  "locations": [...],
  "properties": {
    "stigIds": ["V-222607"],
    "stigCheckIds": ["APSC-DV-002540"],
    "cweIds": [89],
    "nist80053": ["SI-10"],
    "stigCategory": "I"
  }
}
```

These same properties are also supported on rule descriptors, where they apply as defaults to all results referencing that rule. Result-level properties take precedence over rule-level properties.

**Field reference:**

| Field | Type | Effect |
|-------|------|--------|
| `stigIds` | `string[]` | Direct V-ID mapping. Highest confidence. |
| `stigCheckIds` | `string[]` | APSC-DV check IDs, resolved to V-IDs by stigcode. |
| `cweIds` | `int[]` | CWE integers, used for CWE→STIG lookup. |
| `nist80053` | `string[]` | NIST 800-53 control IDs for coverage matrix output. |
| `stigCategory` | `string` | `"I"`, `"II"`, or `"III"` — overrides inferred severity. |


## Severity Mapping

SARIF `level` maps to STIG categories automatically:

| SARIF level | STIG Category | Meaning |
|-------------|---------------|---------|
| `error` | CAT I | Critical — must fix |
| `warning` | CAT II | Moderate — should fix |
| `note` | CAT III | Low — best practice |
| `none` | — | Informational, not mapped |

Use `properties.stigCategory` to override this mapping for individual results or rules where the STIG classification differs from your tool's default severity.


## Validate Your Output

Use stigcode's `validate` command to check compatibility before integrating with a pipeline:

```bash
stigcode validate scan-results.sarif
```

For CI pipelines where warnings should be treated as failures:

```bash
stigcode validate scan-results.sarif --strict
```

Exit codes: `0` = valid, `1` = valid with warnings, `2` = invalid.

Example output:

```
Validating: scan-results.sarif

Scanner:      semgrep v1.56.0
SARIF version: 2.1.0
Tier:         standard (CWE-based mapping)

Results: 42 findings across 15 rules

CWE Coverage:
  Rule tags (external/cwe/cwe-NNN): 38 results
  CWE in message text (fallback): 3 results
  No CWE information: 1 result

Issues:
  ⚠ Result has no CWE information ...
    at runs[0].results[31]

  ℹ No enriched STIG metadata found (properties.stigIds). ...

Verdict: VALID (1 warning)
```


## Complete Example

A minimal but complete SARIF file demonstrating Standard tier with two findings at different severities:

```json
{
  "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "my-scanner",
        "version": "2.0.0",
        "informationUri": "https://example.com/my-scanner",
        "rules": [
          {
            "id": "sql-injection",
            "shortDescription": {"text": "SQL injection via user input"},
            "helpUri": "https://cwe.mitre.org/data/definitions/89.html",
            "properties": {
              "tags": ["security", "external/cwe/cwe-89"]
            }
          },
          {
            "id": "missing-auth",
            "shortDescription": {"text": "Missing authentication on sensitive endpoint"},
            "helpUri": "https://cwe.mitre.org/data/definitions/306.html",
            "properties": {
              "tags": ["security", "external/cwe/cwe-306"]
            }
          }
        ]
      }
    },
    "results": [
      {
        "ruleId": "sql-injection",
        "level": "error",
        "message": {"text": "User-controlled input flows into SQL query without parameterization."},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {
              "uri": "src/db/queries.py",
              "uriBaseId": "%SRCROOT%"
            },
            "region": {"startLine": 42, "startColumn": 12}
          }
        }]
      },
      {
        "ruleId": "missing-auth",
        "level": "warning",
        "message": {"text": "Endpoint /admin/config accessible without authentication."},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {
              "uri": "src/api/admin.py",
              "uriBaseId": "%SRCROOT%"
            },
            "region": {"startLine": 15, "startColumn": 1}
          }
        }]
      }
    ]
  }]
}
```

This produces Standard-tier output: stigcode maps CWE-89 and CWE-306 to their corresponding STIG findings with `inferred` confidence.
