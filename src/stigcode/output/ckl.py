"""CKL (DISA STIG Viewer Checklist) XML generator.

Produces .ckl files compatible with STIG Viewer 2.x and 3.x from a
StatusReport and StigBenchmark.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from stigcode.ingest.xccdf import StigBenchmark, StigFinding
from stigcode.mapping.status import (
    CklStatus,
    FindingDetermination,
    StatusReport,
)

# The exact order of STIG_DATA attributes per VULN.
# STIG Viewer is order-sensitive; do not reorder.
_VULN_ATTRIBUTES: list[str] = [
    "Vuln_Num",
    "Severity",
    "Group_Title",
    "Rule_ID",
    "Rule_Ver",
    "Rule_Title",
    "Vuln_Discuss",
    "IA_Controls",
    "Check_Content",
    "Fix_Text",
    "False_Positives",
    "False_Negatives",
    "Documentable",
    "Mitigations",
    "Potential_Impact",
    "Third_Party_Tools",
    "Mitigation_Control",
    "Responsibility",
    "Security_Override_Guidance",
    "Check_Content_Ref",
    "Weight",
    "Class",
    "STIGRef",
    "TargetKey",
    "STIG_UUID",
]

# STIG_INFO fields in the order STIG Viewer expects them.
_STIG_INFO_FIELDS: list[str] = [
    "version",
    "classification",
    "customname",
    "stigid",
    "description",
    "filename",
    "releaseinfo",
    "title",
    "uuid",
    "notice",
    "source",
]


@dataclass
class AssetInfo:
    """Target system metadata for the CKL ASSET block."""

    host_name: str = ""
    host_ip: str = ""
    host_mac: str = ""
    host_fqdn: str = ""
    role: str = "None"
    asset_type: str = "Computing"
    marking: str = "CUI"
    target_comment: str = ""
    tech_area: str = ""
    web_or_database: bool = False
    web_db_site: str = ""
    web_db_instance: str = ""


def generate_ckl(
    report: StatusReport,
    benchmark: StigBenchmark,
    asset: AssetInfo | None = None,
    classification: str = "UNCLASSIFIED",
) -> str:
    """Generate CKL XML string from a status report and benchmark."""
    if asset is None:
        asset = AssetInfo()

    root = ET.Element("CHECKLIST")
    _build_asset(root, asset)
    _build_stigs(root, report, benchmark, classification)

    tree = ET.ElementTree(root)
    ET.indent(tree, space="\t")

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        + ET.tostring(root, encoding="unicode")
    )


def write_ckl(
    report: StatusReport,
    benchmark: StigBenchmark,
    output_path: Path,
    asset: AssetInfo | None = None,
    classification: str = "UNCLASSIFIED",
) -> None:
    """Write CKL XML to a file."""
    xml_str = generate_ckl(report, benchmark, asset, classification)
    output_path.write_text(xml_str, encoding="utf-8")


# ---------------------------------------------------------------------------
# Tree-building helpers
# ---------------------------------------------------------------------------

def _build_asset(root: ET.Element, asset: AssetInfo) -> None:
    """Append the ASSET element to the CHECKLIST root."""
    el = ET.SubElement(root, "ASSET")
    _sub_text(el, "ROLE", asset.role)
    _sub_text(el, "ASSET_TYPE", asset.asset_type)
    _sub_text(el, "MARKING", asset.marking)
    _sub_text(el, "HOST_NAME", asset.host_name)
    _sub_text(el, "HOST_IP", asset.host_ip)
    _sub_text(el, "HOST_MAC", asset.host_mac)
    _sub_text(el, "HOST_FQDN", asset.host_fqdn)
    _sub_text(el, "TARGET_COMMENT", asset.target_comment)
    _sub_text(el, "TECH_AREA", asset.tech_area)
    _sub_text(el, "TARGET_KEY", "")
    _sub_text(el, "WEB_OR_DATABASE", str(asset.web_or_database).lower())
    _sub_text(el, "WEB_DB_SITE", asset.web_db_site)
    _sub_text(el, "WEB_DB_INSTANCE", asset.web_db_instance)


def _build_stigs(
    root: ET.Element,
    report: StatusReport,
    benchmark: StigBenchmark,
    classification: str,
) -> None:
    """Append the STIGS > iSTIG block."""
    stigs = ET.SubElement(root, "STIGS")
    istig = ET.SubElement(stigs, "iSTIG")
    _build_stig_info(istig, benchmark, classification)

    # Index determinations by stig_id for O(1) lookup
    det_by_id: dict[str, FindingDetermination] = {
        d.stig_id: d for d in report.determinations
    }

    stig_ref = _format_stig_ref(benchmark)

    for finding in benchmark.findings:
        det = det_by_id.get(finding.vuln_id)
        _build_vuln(istig, finding, det, stig_ref)


def _build_stig_info(
    istig: ET.Element,
    benchmark: StigBenchmark,
    classification: str,
) -> None:
    """Append the STIG_INFO block with SI_DATA entries."""
    info = ET.SubElement(istig, "STIG_INFO")

    values: dict[str, str] = {
        "version": benchmark.version,
        "classification": classification,
        "customname": "",
        "stigid": benchmark.benchmark_id,
        "description": f"{benchmark.title} STIG",
        "filename": "",
        "releaseinfo": f"Release: {benchmark.release}",
        "title": benchmark.title,
        "uuid": "",
        "notice": "",
        "source": "STIG.DOD.MIL",
    }

    for field_name in _STIG_INFO_FIELDS:
        si = ET.SubElement(info, "SI_DATA")
        _sub_text(si, "SID_NAME", field_name)
        value = values.get(field_name, "")
        if value:
            _sub_text(si, "SID_DATA", value)
        else:
            # Empty SID_DATA must still be present as an element
            ET.SubElement(si, "SID_DATA")


def _build_vuln(
    istig: ET.Element,
    finding: StigFinding,
    det: FindingDetermination | None,
    stig_ref: str,
) -> None:
    """Append a single VULN element for one STIG finding."""
    vuln = ET.SubElement(istig, "VULN")

    # Map finding fields to VULN_ATTRIBUTE values
    attr_values: dict[str, str] = {
        "Vuln_Num": finding.vuln_id,
        "Severity": finding.severity,
        "Group_Title": finding.group_title,
        "Rule_ID": finding.rule_id,
        "Rule_Ver": finding.check_id,
        "Rule_Title": finding.title,
        "Vuln_Discuss": finding.description,
        "IA_Controls": "",
        "Check_Content": finding.check_content,
        "Fix_Text": finding.fix_text,
        "False_Positives": "",
        "False_Negatives": "",
        "Documentable": "false",
        "Mitigations": "",
        "Potential_Impact": "",
        "Third_Party_Tools": "",
        "Mitigation_Control": "",
        "Responsibility": "",
        "Security_Override_Guidance": "",
        "Check_Content_Ref": "M",
        "Weight": "10.0",
        "Class": "Unclass",
        "STIGRef": stig_ref,
        "TargetKey": "",
        "STIG_UUID": "",
    }

    # Write the 25 fixed STIG_DATA attributes in order
    for attr_name in _VULN_ATTRIBUTES:
        _add_stig_data(vuln, attr_name, attr_values.get(attr_name, ""))

    # CCI_REF entries (one per CCI)
    for cci in finding.cci_refs:
        _add_stig_data(vuln, "CCI_REF", cci)

    # STATUS, FINDING_DETAILS, COMMENTS, SEVERITY_OVERRIDE, SEVERITY_JUSTIFICATION
    if det is not None:
        _sub_text(vuln, "STATUS", det.status.value)
        _sub_text(vuln, "FINDING_DETAILS", _format_finding_details(det))
        _sub_text(vuln, "COMMENTS", _format_comments(det))
    else:
        _sub_text(vuln, "STATUS", CklStatus.NOT_REVIEWED.value)
        _sub_text(vuln, "FINDING_DETAILS", "")
        _sub_text(vuln, "COMMENTS", "")

    _sub_text(vuln, "SEVERITY_OVERRIDE", "")
    _sub_text(vuln, "SEVERITY_JUSTIFICATION", "")


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _format_stig_ref(benchmark: StigBenchmark) -> str:
    """Build the STIGRef string: '{title} :: Version {ver}, Release: {rel}'."""
    return f"{benchmark.title} :: Version {benchmark.version}, Release: {benchmark.release}"


def _format_finding_details(det: FindingDetermination) -> str:
    """Build the FINDING_DETAILS text from a determination."""
    parts: list[str] = []
    if det.review_notes:
        parts.append(det.review_notes)
    if det.evidence:
        parts.append("Evidence locations:")
        parts.extend(f"  {e}" for e in det.evidence)
    return "\n".join(parts)


def _format_comments(det: FindingDetermination) -> str:
    """Build the COMMENTS text with confidence metadata."""
    parts = [
        "Stigcode assessment",
        f"Confidence: {det.confidence.value}",
    ]
    if det.review_notes:
        parts.append(det.review_notes)
    return " | ".join(parts)


def _add_stig_data(parent: ET.Element, attr_name: str, value: str) -> None:
    """Append a STIG_DATA child with VULN_ATTRIBUTE and ATTRIBUTE_DATA."""
    sd = ET.SubElement(parent, "STIG_DATA")
    _sub_text(sd, "VULN_ATTRIBUTE", attr_name)
    _sub_text(sd, "ATTRIBUTE_DATA", value)


def _sub_text(parent: ET.Element, tag: str, text: str) -> ET.Element:
    """Create a sub-element with text content. Empty text creates an empty element."""
    child = ET.SubElement(parent, tag)
    child.text = text if text else None
    return child
