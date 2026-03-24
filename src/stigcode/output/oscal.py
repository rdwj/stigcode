"""NIST OSCAL Assessment Results generator.

Produces OSCAL AR JSON documents from stigcode status reports.
The output conforms to OSCAL 1.1.2 and is suitable for ingestion by
automated ATO pipelines such as Trestle and Lula.

Reference: https://pages.nist.gov/OSCAL/reference/latest/assessment-results/json-outline/
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from stigcode.ingest.xccdf import StigBenchmark, StigFinding
from stigcode.mapping.engine import MappingDatabase
from stigcode.mapping.status import CklStatus, FindingDetermination, StatusReport
from stigcode.version import __version__

OSCAL_VERSION = "1.1.2"

# Deterministic UUID namespace for stigcode so the same inputs produce the
# same UUIDs across runs (important for diffing).
_STIGCODE_NS = uuid.UUID("d4e5f6a7-b8c9-4d0e-a1f2-b3c4d5e6f7a8")


def _uuid5(name: str) -> str:
    """Return a deterministic UUID-5 string within the stigcode namespace."""
    return str(uuid.uuid5(_STIGCODE_NS, name))


def _nist_control_id(raw: str) -> str:
    """Normalise a NIST control ID to OSCAL convention (lowercase, hyphens)."""
    return raw.strip().lower()


def _iso_timestamp(dt: datetime) -> str:
    """Format a datetime as an ISO-8601 string with timezone."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _ckl_status_to_oscal_state(status: CklStatus) -> str:
    """Map CklStatus to OSCAL finding target state."""
    if status == CklStatus.NOT_A_FINDING:
        return "satisfied"
    if status in (CklStatus.OPEN, CklStatus.NOT_APPLICABLE):
        return "not-satisfied"
    return "other"


# ------------------------------------------------------------------
# Control-level grouping
# ------------------------------------------------------------------

def _resolve_nist_controls(
    det: FindingDetermination,
    benchmark: StigBenchmark,
    mapping_db: MappingDatabase,
    cci_mappings: dict[str, str],
) -> set[str]:
    """Return the set of NIST control IDs associated with a determination."""
    controls: set[str] = set()

    # CCI path: look up the STIG finding's CCI refs in the benchmark
    stig_finding = _find_stig_finding(det.stig_id, benchmark)
    if stig_finding:
        for cci in stig_finding.cci_refs:
            ctrl = cci_mappings.get(cci)
            if ctrl:
                controls.add(ctrl)

    # Mapping DB fallback
    for m in mapping_db.lookup_by_stig(det.stig_id):
        if m.nist_control:
            controls.add(m.nist_control)

    return controls


def _find_stig_finding(
    vuln_id: str, benchmark: StigBenchmark
) -> StigFinding | None:
    for f in benchmark.findings:
        if f.vuln_id == vuln_id:
            return f
    return None


def _group_by_control(
    report: StatusReport,
    benchmark: StigBenchmark,
    mapping_db: MappingDatabase,
    cci_mappings: dict[str, str],
) -> dict[str, list[FindingDetermination]]:
    """Group determinations by NIST control ID.

    Returns a dict mapping normalised control IDs to their contributing
    determinations.  Determinations that map to no known control are
    collected under the key ``"unknown"``.
    """
    grouped: dict[str, list[FindingDetermination]] = {}
    for det in report.determinations:
        controls = _resolve_nist_controls(det, benchmark, mapping_db, cci_mappings)
        if not controls:
            grouped.setdefault("unknown", []).append(det)
            continue
        for ctrl in controls:
            nid = _nist_control_id(ctrl)
            grouped.setdefault(nid, []).append(det)
    return grouped


# ------------------------------------------------------------------
# OSCAL document assembly
# ------------------------------------------------------------------

def _build_metadata(scan_date: datetime) -> dict:
    return {
        "title": "Stigcode SAST Assessment Results",
        "last-modified": _iso_timestamp(scan_date),
        "version": __version__,
        "oscal-version": OSCAL_VERSION,
        "props": [
            {"name": "tool", "value": f"stigcode {__version__}"},
        ],
    }


def _build_observation(det: FindingDetermination, scan_date: datetime) -> dict:
    """Build an OSCAL observation from an Open finding."""
    obs_uuid = _uuid5(f"obs-{det.stig_id}")
    evidence_links = [
        {"href": loc, "text": loc} for loc in det.evidence
    ]
    return {
        "uuid": obs_uuid,
        "title": f"Finding for {det.stig_id}",
        "description": det.review_notes or f"Open finding on {det.stig_id}",
        "methods": ["TEST"],
        "types": ["finding"],
        "relevant-evidence": [
            {
                "description": "SARIF scan output",
                "links": evidence_links,
            },
        ] if evidence_links else [],
        "collected": _iso_timestamp(scan_date),
    }


def _build_finding_for_control(
    control_id: str,
    dets: list[FindingDetermination],
    observations: dict[str, str],
    scan_date: datetime,
) -> dict:
    """Build a single OSCAL finding entry for a NIST control.

    ``observations`` maps stig_id -> observation UUID for cross-referencing.
    """
    finding_uuid = _uuid5(f"finding-{control_id}")

    # Determine overall state: if any determination is Open the control
    # is not-satisfied; if all are NotAFinding it is satisfied; otherwise other.
    has_open = any(d.status == CklStatus.OPEN for d in dets)
    all_clear = all(d.status == CklStatus.NOT_A_FINDING for d in dets)

    if has_open:
        state = "not-satisfied"
    elif all_clear:
        state = "satisfied"
    else:
        state = "other"

    # Summarise contributing STIGs
    stig_ids = sorted({d.stig_id for d in dets})
    cwe_ids = sorted({c for d in dets for c in d.mapped_cwe_ids})
    cwe_str = ", ".join(f"CWE-{c}" for c in cwe_ids) if cwe_ids else ""

    desc_parts = [f"STIG(s): {', '.join(stig_ids)}"]
    if cwe_str:
        desc_parts.append(f"CWE(s): {cwe_str}")

    title_state = "Open" if has_open else ("Clear" if all_clear else "Not Reviewed")
    title = f"{control_id.upper()}: {title_state}"

    # Related observations (only for Open findings that have observations)
    related = []
    for d in dets:
        if d.stig_id in observations:
            related.append({"observation-uuid": observations[d.stig_id]})

    result: dict = {
        "uuid": finding_uuid,
        "title": title,
        "description": "; ".join(desc_parts),
        "target": {
            "type": "statement-id",
            "target-id": f"{control_id}_smt",
            "status": {"state": state},
        },
    }
    if related:
        result["related-observations"] = related
    if state == "other":
        result["target"]["status"]["remarks"] = (
            "Control requires manual/procedural assessment"
        )
    return result


def generate_oscal_ar(
    report: StatusReport,
    benchmark: StigBenchmark,
    mapping_db: MappingDatabase,
    cci_mappings: dict[str, str],
    scan_date: datetime | None = None,
) -> dict:
    """Generate an OSCAL Assessment Results document as a Python dict."""
    now = scan_date or datetime.now(tz=timezone.utc)

    # Group determinations by control
    by_control = _group_by_control(report, benchmark, mapping_db, cci_mappings)

    # Build observations for every Open finding
    observations_list: list[dict] = []
    obs_uuid_map: dict[str, str] = {}  # stig_id -> observation uuid
    for det in report.determinations:
        if det.status == CklStatus.OPEN:
            obs = _build_observation(det, now)
            observations_list.append(obs)
            obs_uuid_map[det.stig_id] = obs["uuid"]

    # Build findings (one per control)
    findings_list: list[dict] = []
    for ctrl_id in sorted(by_control):
        if ctrl_id == "unknown":
            continue
        finding = _build_finding_for_control(
            ctrl_id, by_control[ctrl_id], obs_uuid_map, now,
        )
        findings_list.append(finding)

    # reviewed-controls: all non-unknown controls
    control_ids = sorted(c for c in by_control if c != "unknown")
    include_controls = [{"control-id": cid} for cid in control_ids]

    result_entry: dict = {
        "uuid": _uuid5("result-0"),
        "title": "SAST Scan Results",
        "description": "Automated static analysis findings mapped to NIST controls",
        "start": _iso_timestamp(now),
        "reviewed-controls": {
            "control-selections": [
                {"include-controls": include_controls},
            ],
        },
    }
    if observations_list:
        result_entry["observations"] = observations_list
    if findings_list:
        result_entry["findings"] = findings_list

    return {
        "assessment-results": {
            "uuid": _uuid5("ar-doc"),
            "metadata": _build_metadata(now),
            "import-ap": {"href": "#"},
            "results": [result_entry],
        },
    }


def oscal_to_json(ar: dict, pretty: bool = True) -> str:
    """Serialize an OSCAL AR dict to a JSON string."""
    indent = 2 if pretty else None
    return json.dumps(ar, indent=indent, ensure_ascii=False)


def write_oscal(
    report: StatusReport,
    benchmark: StigBenchmark,
    mapping_db: MappingDatabase,
    cci_mappings: dict[str, str],
    output_path: Path,
    scan_date: datetime | None = None,
) -> None:
    """Write OSCAL Assessment Results JSON to a file."""
    ar = generate_oscal_ar(report, benchmark, mapping_db, cci_mappings, scan_date)
    output_path.write_text(oscal_to_json(ar), encoding="utf-8")
