"""SARIF validation for stigcode compatibility.

Checks a SARIF file for structural correctness and compatibility with
stigcode's ingestion pipeline. Reports errors (blocking), warnings
(non-blocking), and informational observations.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

_CWE_IN_TEXT_RE = re.compile(r"\bCWE-(\d+)\b", re.IGNORECASE)
_VALID_LEVELS = {"error", "warning", "note", "none"}


@dataclass
class ValidationIssue:
    """A single validation finding."""

    level: str    # "error", "warning", "info"
    message: str
    location: str  # JSON path like "runs[0].results[1]"


@dataclass
class ValidationResult:
    """Complete validation report."""

    is_valid: bool
    sarif_version: str
    scanner_name: str
    scanner_version: str
    total_results: int
    total_rules: int
    issues: list[ValidationIssue] = field(default_factory=list)
    cwe_coverage: dict[str, int] = field(default_factory=dict)
    stig_enrichment: bool = False
    tier: str = ""  # "enriched", "standard", "minimal"


def validate_sarif(path: Path) -> ValidationResult:
    """Validate a SARIF file for stigcode compatibility.

    Errors make is_valid=False. Warnings are noted but do not fail validation.
    """
    issues: list[ValidationIssue] = []

    # --- Load and parse JSON ---
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        issues.append(ValidationIssue("error", f"Cannot read file: {exc}", "<file>"))
        return _failed(issues)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        issues.append(ValidationIssue("error", f"Not valid JSON: {exc}", "<file>"))
        return _failed(issues)

    if not isinstance(data, dict):
        issues.append(ValidationIssue("error", "SARIF root must be a JSON object", "<root>"))
        return _failed(issues)

    # --- Required top-level fields ---
    sarif_version = data.get("version", "")
    if not sarif_version:
        issues.append(ValidationIssue("error", "Missing required 'version' field", "<root>"))
    elif sarif_version != "2.1.0":
        issues.append(ValidationIssue(
            "error",
            f"SARIF version must be '2.1.0', got '{sarif_version}'",
            "version",
        ))

    runs = data.get("runs")
    if runs is None:
        issues.append(ValidationIssue("error", "Missing required 'runs' array", "<root>"))
        return _build_result(
            issues=issues,
            sarif_version=sarif_version,
            scanner_name="",
            scanner_version="",
            total_results=0,
            total_rules=0,
            cwe_coverage={},
            stig_enrichment=False,
        )

    if not isinstance(runs, list):
        issues.append(ValidationIssue("error", "'runs' must be an array", "runs"))
        return _failed(issues)

    if _has_errors(issues):
        return _failed(issues)

    # --- Per-run analysis ---
    scanner_name = ""
    scanner_version = ""
    total_results = 0
    total_rules = 0
    cwe_coverage: dict[str, int] = {
        "properties.stigIds": 0,
        "properties.cweIds": 0,
        "rule.tags": 0,
        "rule.relationships": 0,
        "message.text": 0,
        "none": 0,
    }
    stig_enrichment = False

    for run_idx, run in enumerate(runs):
        loc_run = f"runs[{run_idx}]"

        if not isinstance(run, dict):
            issues.append(ValidationIssue("error", "Run is not an object", loc_run))
            continue

        driver = run.get("tool", {}).get("driver")
        if not driver or not isinstance(driver, dict):
            issues.append(ValidationIssue("error", "Run has no tool.driver", f"{loc_run}.tool"))
            continue

        if not scanner_name:
            scanner_name = driver.get("name", "")
            scanner_version = driver.get("version", "")

        rules: list[dict] = driver.get("rules", []) or []
        rules_by_id: dict[str, dict] = {}
        for rule in rules:
            if isinstance(rule, dict) and "id" in rule:
                rules_by_id[rule["id"]] = rule
                if not rule.get("shortDescription"):
                    issues.append(ValidationIssue(
                        "warning",
                        f"Rule '{rule['id']}' has no shortDescription",
                        f"{loc_run}.tool.driver.rules",
                    ))
        total_rules += len(rules_by_id)

        results: list = run.get("results", []) or []
        total_results += len(results)

        for res_idx, result in enumerate(results):
            loc_res = f"{loc_run}.results[{res_idx}]"
            if not isinstance(result, dict):
                continue

            # Validate level
            level = result.get("level", "warning")
            if level not in _VALID_LEVELS:
                issues.append(ValidationIssue(
                    "warning",
                    f"Unexpected level '{level}'; expected one of: {sorted(_VALID_LEVELS)}",
                    loc_res,
                ))

            # Validate locations
            locations = result.get("locations")
            if not locations or not isinstance(locations, list) or len(locations) == 0:
                issues.append(ValidationIssue(
                    "warning",
                    "Result has no locations — file/line information will be missing",
                    loc_res,
                ))

            # CWE coverage analysis
            rule_id = result.get("ruleId", "")
            rule = rules_by_id.get(rule_id, {})
            method = _detect_cwe_method(result, rule)

            if method == "properties.stigIds":
                stig_enrichment = True

            cwe_coverage[method] = cwe_coverage.get(method, 0) + 1

            # Emit info issue for no-CWE results
            if method == "none":
                issues.append(ValidationIssue(
                    "warning",
                    "Result has no CWE information — STIG mapping will rely on rule-ID heuristics",
                    loc_res,
                ))

    # Emit info about enrichment status
    if stig_enrichment:
        issues.append(ValidationIssue(
            "info",
            "Enriched STIG metadata detected (properties.stigIds) — highest-confidence mappings available",
            "<summary>",
        ))
    else:
        issues.append(ValidationIssue(
            "info",
            (
                "No enriched STIG metadata found (properties.stigIds). "
                "For highest-confidence mappings, see: "
                "https://github.com/rdwj/stigcode/blob/main/docs/sarif-integration-guide.md"
            ),
            "<summary>",
        ))

    # Tier classification
    tier = _classify_tier(cwe_coverage, stig_enrichment)

    return _build_result(
        issues=issues,
        sarif_version=sarif_version,
        scanner_name=scanner_name,
        scanner_version=scanner_version,
        total_results=total_results,
        total_rules=total_rules,
        cwe_coverage={k: v for k, v in cwe_coverage.items() if v > 0},
        stig_enrichment=stig_enrichment,
        tier=tier,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _detect_cwe_method(result: dict, rule: dict) -> str:
    """Return the CWE extraction method that would be used for this result."""
    result_props = {k.lower(): v for k, v in (result.get("properties") or {}).items()}
    rule_props = {k.lower(): v for k, v in (rule.get("properties") or {}).items()}

    # Direct STIG IDs
    stig_ids = result_props.get("stigids") or rule_props.get("stigids")
    if stig_ids:
        return "properties.stigIds"

    # CWE IDs in result properties
    if result_props.get("cweids") or result_props.get("cwe_ids"):
        return "properties.cweIds"

    # CWE IDs in rule properties
    if rule_props.get("cweids") or rule_props.get("cwe_ids"):
        return "properties.cweIds"

    # Rule tags (external/cwe/cwe-NNN)
    rule_tags = rule_props.get("tags") or rule.get("properties", {}).get("tags")
    if rule_tags and _has_cwe_tags(rule_tags):
        return "rule.tags"

    # Rule relationships
    if _has_cwe_relationships(rule):
        return "rule.relationships"

    # Message text fallback
    msg = result.get("message", {})
    msg_text = msg.get("text", "") if isinstance(msg, dict) else str(msg)
    if _CWE_IN_TEXT_RE.search(msg_text):
        return "message.text"

    return "none"


def _has_cwe_tags(tags: list) -> bool:
    for tag in tags:
        if isinstance(tag, str) and re.search(r"(?i)/cwe-\d+$", tag):
            return True
    return False


def _has_cwe_relationships(rule: dict) -> bool:
    for rel in rule.get("relationships", []) or []:
        if not isinstance(rel, dict):
            continue
        target = rel.get("target", {})
        if target.get("toolComponent", {}).get("name", "").upper() == "CWE":
            return True
    return False


def _classify_tier(cwe_coverage: dict[str, int], stig_enrichment: bool) -> str:
    if stig_enrichment or cwe_coverage.get("properties.stigIds", 0) > 0:
        return "enriched"
    cwe_results = sum(
        cwe_coverage.get(m, 0)
        for m in ("properties.cweIds", "rule.tags", "rule.relationships", "message.text")
    )
    if cwe_results > 0:
        return "standard"
    return "minimal"


def _has_errors(issues: list[ValidationIssue]) -> bool:
    return any(i.level == "error" for i in issues)


def _failed(issues: list[ValidationIssue]) -> ValidationResult:
    return ValidationResult(
        is_valid=False,
        sarif_version="",
        scanner_name="",
        scanner_version="",
        total_results=0,
        total_rules=0,
        issues=issues,
    )


def _build_result(
    *,
    issues: list[ValidationIssue],
    sarif_version: str,
    scanner_name: str,
    scanner_version: str,
    total_results: int,
    total_rules: int,
    cwe_coverage: dict[str, int],
    stig_enrichment: bool,
    tier: str = "",
) -> ValidationResult:
    return ValidationResult(
        is_valid=not _has_errors(issues),
        sarif_version=sarif_version,
        scanner_name=scanner_name,
        scanner_version=scanner_version,
        total_results=total_results,
        total_rules=total_rules,
        issues=issues,
        cwe_coverage=cwe_coverage,
        stig_enrichment=stig_enrichment,
        tier=tier or _classify_tier(cwe_coverage, stig_enrichment),
    )
