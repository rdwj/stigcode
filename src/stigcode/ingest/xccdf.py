"""XCCDF parser for DISA STIG benchmark files.

Parses DISA XCCDF 1.1 XML files and extracts structured finding data
suitable for CKL generation and compliance mapping.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from pathlib import Path

import defusedxml.ElementTree as ET
import yaml

# XCCDF 1.1 namespace used by DISA STIGs
NS = "http://checklists.nist.gov/xccdf/1.1"
DC_NS = "http://purl.org/dc/elements/1.1/"

# Severity string → CAT integer
SEVERITY_TO_CAT: dict[str, int] = {
    "high": 1,
    "medium": 2,
    "low": 3,
}


@dataclass
class StigFinding:
    """A single STIG finding parsed from XCCDF."""

    vuln_id: str          # e.g. "V-222387"
    rule_id: str          # e.g. "SV-222387r960735_rule"
    check_id: str         # e.g. "APSC-DV-000010"
    title: str
    description: str      # VulnDiscussion text, cleaned
    severity: str         # "high", "medium", or "low"
    category: int         # CAT I=1, CAT II=2, CAT III=3
    cci_refs: list[str]   # ["CCI-000054", ...]
    fix_text: str
    check_content: str
    group_title: str = ""    # SRG-APP-XXXXXX from the XCCDF Group <title>
    legacy_ids: list[str] = field(default_factory=list)


@dataclass
class StigBenchmark:
    """Parsed STIG benchmark metadata plus all findings."""

    benchmark_id: str
    title: str
    version: str
    release: str
    date: str
    findings: list[StigFinding]
    profiles: dict[str, list[str]]  # profile_id → list of V-IDs


def _tag(local: str) -> str:
    """Return a fully-qualified XCCDF element tag."""
    return f"{{{NS}}}{local}"


def _find_text(element, local_tag: str, ns: str = NS) -> str:
    """Return stripped text of a child element, or empty string."""
    child = element.find(f"{{{ns}}}{local_tag}")
    if child is not None and child.text:
        return child.text.strip()
    return ""


def _extract_vuln_discussion(raw_description: str) -> str:
    """Extract VulnDiscussion text from an HTML-escaped XCCDF description.

    The XCCDF <description> field contains HTML-escaped inner XML.
    We unescape it, then parse the inner XML to pull out <VulnDiscussion>.
    Falls back to the raw unescaped text if parsing fails.
    """
    unescaped = html.unescape(raw_description)
    # Wrap in a root so ElementTree can parse it as a document fragment
    try:
        inner = ET.fromstring(f"<_root>{unescaped}</_root>")
        vuln = inner.find("VulnDiscussion")
        if vuln is not None and vuln.text:
            return vuln.text.strip()
    except ET.ParseError:
        pass
    return unescaped.strip()


def _parse_finding(group_el) -> StigFinding:
    """Parse a single <Group> element into a StigFinding."""
    vuln_id = group_el.get("id", "")
    group_title = _find_text(group_el, "title")

    rule_el = group_el.find(_tag("Rule"))
    if rule_el is None:
        raise ValueError(f"Group {vuln_id} has no <Rule> child")

    rule_id = rule_el.get("id", "")
    severity = rule_el.get("severity", "medium").lower()
    category = SEVERITY_TO_CAT.get(severity, 2)

    check_id = _find_text(rule_el, "version")
    title = _find_text(rule_el, "title")

    raw_desc = _find_text(rule_el, "description")
    description = _extract_vuln_discussion(raw_desc)

    # CCI and legacy ident refs
    cci_refs: list[str] = []
    legacy_ids: list[str] = []
    for ident_el in rule_el.findall(_tag("ident")):
        system = ident_el.get("system", "")
        value = (ident_el.text or "").strip()
        if system == "http://cyber.mil/cci":
            cci_refs.append(value)
        elif system == "http://cyber.mil/legacy":
            legacy_ids.append(value)

    fix_el = rule_el.find(_tag("fixtext"))
    fix_text = (fix_el.text or "").strip() if fix_el is not None else ""

    check_el = rule_el.find(_tag("check"))
    check_content = ""
    if check_el is not None:
        cc_el = check_el.find(_tag("check-content"))
        if cc_el is not None and cc_el.text:
            check_content = cc_el.text.strip()

    return StigFinding(
        vuln_id=vuln_id,
        rule_id=rule_id,
        check_id=check_id,
        title=title,
        description=description,
        severity=severity,
        category=category,
        cci_refs=cci_refs,
        fix_text=fix_text,
        check_content=check_content,
        group_title=group_title,
        legacy_ids=legacy_ids,
    )


def _parse_profiles(root) -> dict[str, list[str]]:
    """Extract Profile elements → {profile_id: [V-ID, ...]}."""
    profiles: dict[str, list[str]] = {}
    for profile_el in root.findall(_tag("Profile")):
        profile_id = profile_el.get("id", "")
        selected = [
            sel.get("idref", "")
            for sel in profile_el.findall(_tag("select"))
            if sel.get("selected", "false").lower() == "true"
        ]
        profiles[profile_id] = selected
    return profiles


def _parse_release_info(root) -> tuple[str, str]:
    """Extract release number and benchmark date from <plain-text id='release-info'>."""
    for pt in root.findall(_tag("plain-text")):
        if pt.get("id") == "release-info" and pt.text:
            text = pt.text.strip()
            # Format: "Release: 3 Benchmark Date: 02 Apr 2025"
            release = ""
            date = ""
            if "Release:" in text and "Benchmark Date:" in text:
                parts = text.split("Benchmark Date:")
                release_part = parts[0].replace("Release:", "").strip()
                release = release_part
                date = parts[1].strip() if len(parts) > 1 else ""
            else:
                release = text
            return release, date
    return "", ""


def parse_xccdf(path: Path) -> StigBenchmark:
    """Parse a DISA STIG XCCDF file and return a StigBenchmark.

    Args:
        path: Filesystem path to the XCCDF XML file.

    Returns:
        StigBenchmark with all findings and metadata populated.

    Raises:
        FileNotFoundError: If the path does not exist.
        ValueError: If the XML cannot be parsed as an XCCDF benchmark.
    """
    if not path.exists():
        raise FileNotFoundError(f"XCCDF file not found: {path}")

    tree = ET.parse(str(path))
    root = tree.getroot()

    benchmark_id = root.get("id", "")
    title = _find_text(root, "title")
    version = _find_text(root, "version")
    release, date = _parse_release_info(root)
    profiles = _parse_profiles(root)

    findings: list[StigFinding] = []
    for group_el in root.findall(_tag("Group")):
        findings.append(_parse_finding(group_el))

    return StigBenchmark(
        benchmark_id=benchmark_id,
        title=title,
        version=version,
        release=release,
        date=date,
        findings=findings,
        profiles=profiles,
    )


def findings_to_yaml(benchmark: StigBenchmark) -> str:
    """Serialize a StigBenchmark to YAML.

    The output is suitable for storage in data/stigs/ and round-trip
    loading. Each finding is a YAML mapping keyed by vuln_id.

    Args:
        benchmark: Parsed benchmark to serialize.

    Returns:
        YAML string.
    """
    doc: dict = {
        "benchmark_id": benchmark.benchmark_id,
        "title": benchmark.title,
        "version": benchmark.version,
        "release": benchmark.release,
        "date": benchmark.date,
        "profiles": benchmark.profiles,
        "findings": [
            {
                "vuln_id": f.vuln_id,
                "rule_id": f.rule_id,
                "check_id": f.check_id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "category": f.category,
                "cci_refs": f.cci_refs,
                "fix_text": f.fix_text,
                "check_content": f.check_content,
                "group_title": f.group_title,
                "legacy_ids": f.legacy_ids,
            }
            for f in benchmark.findings
        ],
    }
    return yaml.dump(doc, allow_unicode=True, sort_keys=False, default_flow_style=False)
