"""SARIF v2.1.0 ingestion and normalization.

Parses SARIF JSON from any scanner and produces NormalizedFinding objects
following the resolution priority chain defined in docs/sarif-contract.md:

  1. result.properties.stigIds           → confidence: direct
  2. result.properties.cweIds / rule tags → confidence: inferred
  3. rule.relationships (CWE taxonomy)   → confidence: inferred
  4. CWE mentioned in message text       → confidence: low
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# Regex for CWE IDs embedded in message text, e.g. "CWE-120" or "(CWE-20)"
_CWE_IN_TEXT_RE = re.compile(r"\bCWE-(\d+)\b", re.IGNORECASE)

# SARIF level → STIG category
_LEVEL_TO_CAT: dict[str, str] = {
    "error": "CAT I",
    "warning": "CAT II",
    "note": "CAT III",
}


@dataclass
class NormalizedFinding:
    """A single finding normalized from SARIF."""

    rule_id: str
    message: str
    file_path: str
    start_line: int
    start_column: int | None = None
    end_line: int | None = None
    severity: str = "CAT II"        # CAT I, CAT II, CAT III
    cwe_ids: list[int] = field(default_factory=list)
    stig_ids: list[str] = field(default_factory=list)
    nist_controls: list[str] = field(default_factory=list)
    confidence: str = "inferred"
    scanner_name: str = ""
    scanner_version: str = ""
    code_context: str = ""


@dataclass
class SarifIngestionResult:
    """Result of parsing a SARIF file."""

    findings: list[NormalizedFinding]
    scanner_name: str
    scanner_version: str
    runs_processed: int
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_sarif(source: Path | str) -> SarifIngestionResult:
    """Parse a SARIF file or JSON string and return normalised findings.

    Args:
        source: A Path to a .sarif file, or a JSON string (for stdin piping).

    Returns:
        SarifIngestionResult with all findings and any non-fatal parse errors.
    """
    errors: list[str] = []

    # Load JSON
    try:
        if isinstance(source, Path):
            raw = source.read_text(encoding="utf-8")
        else:
            raw = source
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        return SarifIngestionResult(
            findings=[],
            scanner_name="",
            scanner_version="",
            runs_processed=0,
            errors=[f"Failed to load SARIF: {exc}"],
        )

    # Validate top-level structure
    if not isinstance(data, dict):
        return SarifIngestionResult(
            findings=[],
            scanner_name="",
            scanner_version="",
            runs_processed=0,
            errors=["SARIF root is not a JSON object"],
        )

    version = data.get("version", "")
    if version != "2.1.0":
        errors.append(
            f"Unexpected SARIF version '{version}'; expected '2.1.0'. "
            "Attempting parse anyway."
        )

    runs = data.get("runs")
    if runs is None:
        return SarifIngestionResult(
            findings=[],
            scanner_name="",
            scanner_version="",
            runs_processed=0,
            errors=errors + ["SARIF document is missing 'runs' key"],
        )
    if not isinstance(runs, list):
        return SarifIngestionResult(
            findings=[],
            scanner_name="",
            scanner_version="",
            runs_processed=0,
            errors=errors + ["SARIF 'runs' is not an array"],
        )

    all_findings: list[NormalizedFinding] = []
    primary_scanner_name = ""
    primary_scanner_version = ""

    for run_idx, run in enumerate(runs):
        if not isinstance(run, dict):
            errors.append(f"Run {run_idx} is not an object; skipping")
            continue

        scanner_name, scanner_version, rules_by_id = _extract_tool_info(run)

        if not primary_scanner_name:
            primary_scanner_name = scanner_name
            primary_scanner_version = scanner_version

        results = run.get("results", [])
        if not isinstance(results, list):
            errors.append(f"Run {run_idx} 'results' is not an array; skipping")
            continue

        for result_idx, result in enumerate(results):
            if not isinstance(result, dict):
                errors.append(
                    f"Run {run_idx}, result {result_idx} is not an object; skipping"
                )
                continue
            try:
                finding = _normalize_result(
                    result, rules_by_id, scanner_name, scanner_version
                )
                if finding is not None:
                    all_findings.append(finding)
            except Exception as exc:  # noqa: BLE001
                errors.append(
                    f"Run {run_idx}, result {result_idx}: unexpected error: {exc}"
                )

    return SarifIngestionResult(
        findings=all_findings,
        scanner_name=primary_scanner_name,
        scanner_version=primary_scanner_version,
        runs_processed=len(runs),
        errors=errors,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_tool_info(
    run: dict,
) -> tuple[str, str, dict[str, dict]]:
    """Return (scanner_name, scanner_version, rules_by_id) from a run."""
    driver = run.get("tool", {}).get("driver", {})
    name = driver.get("name", "")
    version = driver.get("version", "")
    rules: list[dict] = driver.get("rules", []) or []
    rules_by_id = {r["id"]: r for r in rules if isinstance(r, dict) and "id" in r}
    return name, version, rules_by_id


def _normalize_result(
    result: dict,
    rules_by_id: dict[str, dict],
    scanner_name: str,
    scanner_version: str,
) -> NormalizedFinding | None:
    """Convert one SARIF result object into a NormalizedFinding.

    Returns None for level=="none" results (informational, not mapped to STIG).
    """
    rule_id = result.get("ruleId", "")
    level = result.get("level", "warning")

    if level == "none":
        return None

    message_text = _extract_message(result)
    file_path, start_line, start_col, end_line = _extract_location(result)

    rule = rules_by_id.get(rule_id, {})
    result_props = _normalise_props(result.get("properties") or {})
    rule_props = _normalise_props(rule.get("properties") or {})

    # --- STIG IDs (direct confidence) ---
    stig_ids = list(result_props.get("stigids", []))
    if not stig_ids:
        stig_ids = list(rule_props.get("stigids", []))

    # --- NIST controls ---
    nist_controls = list(result_props.get("nist80053", []))
    if not nist_controls:
        nist_controls = list(rule_props.get("nist80053", []))

    # --- CWE IDs & confidence (priority chain) ---
    cwe_ids, confidence = _resolve_cwes(
        result_props, rule_props, rule, message_text, bool(stig_ids)
    )

    # --- Severity ---
    severity = _resolve_severity(level, result_props, rule_props)

    return NormalizedFinding(
        rule_id=rule_id,
        message=message_text,
        file_path=file_path,
        start_line=start_line,
        start_column=start_col,
        end_line=end_line,
        severity=severity,
        cwe_ids=cwe_ids,
        stig_ids=stig_ids,
        nist_controls=nist_controls,
        confidence=confidence,
        scanner_name=scanner_name,
        scanner_version=scanner_version,
    )


def _normalise_props(props: dict) -> dict:
    """Return a copy of props with all keys lowercased for case-insensitive lookup."""
    return {k.lower(): v for k, v in props.items()}


def _extract_message(result: dict) -> str:
    msg = result.get("message", {})
    if isinstance(msg, dict):
        return msg.get("text", "")
    return str(msg)


def _extract_location(result: dict) -> tuple[str, int, int | None, int | None]:
    """Return (file_path, start_line, start_column, end_line)."""
    locations = result.get("locations")
    if not locations or not isinstance(locations, list):
        return "", 0, None, None

    loc = locations[0]
    if not isinstance(loc, dict):
        return "", 0, None, None

    phys = loc.get("physicalLocation", {})
    art = phys.get("artifactLocation", {})
    region = phys.get("region", {})

    uri = art.get("uri", "")
    start_line = region.get("startLine", 0)
    start_col = region.get("startColumn")
    end_line = region.get("endLine")

    return uri, start_line, start_col, end_line


def _parse_cwe_list(raw: list | None) -> list[int]:
    """Parse a list of CWE values that may be ints or strings like 'CWE-89' or '89'."""
    if not raw:
        return []
    result: list[int] = []
    for item in raw:
        if isinstance(item, int):
            result.append(item)
        elif isinstance(item, str):
            # Strip optional "CWE-" prefix
            clean = re.sub(r"(?i)^cwe-", "", item.strip())
            if clean.isdigit():
                result.append(int(clean))
    return result


def _extract_cwes_from_tags(tags: list | None) -> list[int]:
    """Extract CWE IDs from CodeQL/Semgrep-style tags like 'external/cwe/cwe-89'."""
    if not tags:
        return []
    cwe_ids: list[int] = []
    for tag in tags:
        if isinstance(tag, str):
            m = re.search(r"(?i)/cwe-(\d+)$", tag)
            if m:
                cwe_ids.append(int(m.group(1)))
    return cwe_ids


def _extract_cwes_from_relationships(rule: dict) -> list[int]:
    """Extract CWE IDs from a rule's SARIF taxonomy relationships array."""
    relationships = rule.get("relationships")
    if not relationships or not isinstance(relationships, list):
        return []
    cwe_ids: list[int] = []
    for rel in relationships:
        if not isinstance(rel, dict):
            continue
        target = rel.get("target", {})
        component = target.get("toolComponent", {})
        if component.get("name", "").upper() != "CWE":
            continue
        raw_id = target.get("id", "")
        clean = re.sub(r"(?i)^cwe-", "", str(raw_id).strip())
        if clean.isdigit():
            cwe_ids.append(int(clean))
    return cwe_ids


def _resolve_cwes(
    result_props: dict,
    rule_props: dict,
    rule: dict,
    message_text: str,
    has_stig_ids: bool,
) -> tuple[list[int], str]:
    """Apply the 4-tier CWE resolution priority chain.

    Returns (cwe_ids, confidence).
    """
    # Priority 1 / 2: result-level cweIds (already has stigIds → direct)
    raw_cwes = result_props.get("cweids") or result_props.get("cwe_ids")
    if raw_cwes:
        ids = _parse_cwe_list(raw_cwes)
        if ids:
            confidence = "direct" if has_stig_ids else "inferred"
            return ids, confidence

    # Priority 2b: rule-level cweIds
    raw_cwes = rule_props.get("cweids") or rule_props.get("cwe_ids")
    if raw_cwes:
        ids = _parse_cwe_list(raw_cwes)
        if ids:
            return ids, "inferred"

    # Priority 2c: rule tags (external/cwe/cwe-NNN)
    rule_tags = rule_props.get("tags") or rule.get("properties", {}).get("tags")
    ids = _extract_cwes_from_tags(rule_tags)
    if ids:
        return ids, "inferred"

    # Priority 3: rule relationships to CWE taxonomy
    ids = _extract_cwes_from_relationships(rule)
    if ids:
        return ids, "inferred"

    # Priority 4: CWE mentioned in message text (lowest confidence)
    matches = _CWE_IN_TEXT_RE.findall(message_text)
    if matches:
        ids = [int(m) for m in matches]
        return ids, "low"

    # No CWE found
    confidence = "direct" if has_stig_ids else "low"
    return [], confidence


def _resolve_severity(
    level: str,
    result_props: dict,
    rule_props: dict,
) -> str:
    """Map SARIF level to STIG CAT, respecting stigCategory overrides."""
    # stigCategory on result takes highest precedence
    cat = result_props.get("stigcategory") or rule_props.get("stigcategory")
    if cat:
        cat_str = str(cat).strip().upper().lstrip("CAT ").strip()
        mapping = {"I": "CAT I", "II": "CAT II", "III": "CAT III",
                   "1": "CAT I", "2": "CAT II", "3": "CAT III"}
        if cat_str in mapping:
            return mapping[cat_str]

    return _LEVEL_TO_CAT.get(level.lower(), "CAT II")
