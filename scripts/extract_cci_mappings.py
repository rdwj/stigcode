#!/usr/bin/env python3
"""
Extract CCI→NIST 800-53 mappings from the DISA CCI v2 SARIF taxonomy file,
then validate the chain against the ASD STIG XCCDF findings.

Outputs:
  data/cci/cci_to_nist.yaml           — CCI→NIST mapping table
  data/mappings/finding_classifications.yaml — SAST vs procedural classification
"""

import json
import re
import sys
import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CCI_SARIF = ROOT / "tests/fixtures/reference/DISA_CCI_v2.sarif"
XCCDF = ROOT / "data/stigs/application_security_and_development.xml"
OUT_CCI = ROOT / "data/cci/cci_to_nist.yaml"
OUT_CLASS = ROOT / "data/mappings/finding_classifications.yaml"

XCCDF_NS = "http://checklists.nist.gov/xccdf/1.1"

# ---------------------------------------------------------------------------
# Step 1 & 2: Extract CCI→NIST from SARIF taxonomy
# ---------------------------------------------------------------------------

def extract_cci_mappings() -> dict:
    with open(CCI_SARIF) as f:
        sarif = json.load(f)

    taxa = sarif["runs"][0]["taxonomies"][0]["taxa"]
    mappings = {}
    for taxon in taxa:
        cci_id = taxon["id"]
        title = taxon.get("shortDescription", {}).get("text", "")
        nist_controls = []
        for rel in taxon.get("relationships", []):
            target = rel.get("target", {})
            if target.get("toolComponent", {}).get("name") == "NIST":
                nist_controls.append(target["id"])
        mappings[cci_id] = {
            "nist_controls": nist_controls,
            "title": title,
        }
    return mappings


def write_cci_yaml(mappings: dict) -> None:
    # Build ordered dict for cleaner YAML output
    out = {
        "mappings": {
            cci_id: {
                # Single control is the common case; keep list for multi-control CCIs
                "nist_control": (
                    data["nist_controls"][0]
                    if len(data["nist_controls"]) == 1
                    else data["nist_controls"]
                ),
                "title": data["title"],
            }
            for cci_id, data in sorted(mappings.items())
        }
    }
    header = (
        "# CCI to NIST 800-53 mapping\n"
        "# Source: DISA CCI v2 (via sarif-standard/taxonomies)\n"
        "# Generated from: tests/fixtures/reference/DISA_CCI_v2.sarif\n"
    )
    OUT_CCI.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_CCI, "w") as f:
        f.write(header)
        yaml.dump(out, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    print(f"Wrote {len(out['mappings'])} CCI entries → {OUT_CCI}")


# ---------------------------------------------------------------------------
# Step 3: Parse XCCDF and validate CCI→NIST chain
# ---------------------------------------------------------------------------

def ns(tag: str) -> str:
    return f"{{{XCCDF_NS}}}{tag}"


def parse_xccdf() -> list[dict]:
    tree = ET.parse(XCCDF)
    root = tree.getroot()
    rules = root.findall(f".//{ns('Rule')}")

    findings = []
    for rule in rules:
        rule_id = rule.get("id", "")
        severity = rule.get("severity", "")

        # V-ID is in ident elements (first one starting with V-)
        v_id = None
        ccis = []
        for ident in rule.findall(ns("ident")):
            val = (ident.text or "").strip()
            if val.startswith("V-") and v_id is None:
                v_id = val
            elif val.startswith("CCI-"):
                ccis.append(val)

        title_el = rule.find(ns("title"))
        title = (title_el.text or "").strip() if title_el is not None else ""

        desc_el = rule.find(ns("description"))
        desc_raw = (desc_el.text or "") if desc_el is not None else ""
        # VulnDiscussion is embedded XML — extract text between tags
        vuln_match = re.search(r"<VulnDiscussion>(.*?)</VulnDiscussion>", desc_raw, re.DOTALL)
        vuln_discussion = vuln_match.group(1).strip() if vuln_match else desc_raw.strip()

        check_el = rule.find(f".//{ns('check-content')}")
        check_content = (check_el.text or "").strip() if check_el is not None else ""

        findings.append({
            "rule_id": rule_id,
            "v_id": v_id or rule_id,
            "severity": severity,
            "title": title,
            "vuln_discussion": vuln_discussion,
            "check_content": check_content,
            "ccis": ccis,
        })
    return findings


def summarize_cci_chain(findings: list[dict], cci_map: dict) -> None:
    all_ccis = set()
    for f in findings:
        all_ccis.update(f["ccis"])
    print(f"\n--- CCI Chain Validation ---")
    print(f"Total findings: {len(findings)}")
    print(f"Unique CCIs referenced: {len(all_ccis)}")

    # 10-finding sample
    print("\nSample of 10 findings (V-ID | CCIs → NIST controls):")
    for finding in findings[:10]:
        nist = []
        for cci in finding["ccis"]:
            entry = cci_map.get(cci, {})
            ctrl = entry.get("nist_controls", [])
            nist.extend(ctrl)
        print(f"  {finding['v_id']:12s} | CCIs: {', '.join(finding['ccis']) or 'none':20s} | "
              f"NIST: {', '.join(sorted(set(nist))) or 'none'}")


# ---------------------------------------------------------------------------
# Step 4: Classify findings as sast vs procedural
# ---------------------------------------------------------------------------

# Keywords strongly indicative of SAST-detectable issues
SAST_PATTERNS = [
    # Injection
    r"\bsql\s*injection\b", r"\bcommand\s*injection\b", r"\bldap\s*injection\b",
    r"\bxml\s*injection\b", r"\bxpath\s*injection\b", r"\bxss\b",
    r"\bcross.site\s*script", r"\binjection\b",
    # Crypto
    r"\bweak\s*(encryption|crypto|cipher|hash|algorithm)\b",
    r"\binsecure\s*(algorithm|hash|crypto|cipher|encryption)\b",
    r"\bmd5\b", r"\bsha.?1\b", r"\bdes\b", r"\b3des\b", r"\brc4\b",
    r"\bweak\s*key", r"\bkey\s*(length|size|strength)",
    r"\bencrypt", r"\bcryptograph",
    r"\bcertificate\s*(validat|verif)", r"\btls\b", r"\bssl\b", r"\bpki\b",
    # Hardcoded secrets
    r"\bhardcoded\b", r"\bhard.coded\b", r"\bhardcode\b",
    r"\bembedded\s*(password|credential|key|secret)\b",
    r"\bprivate\s*key\b", r"\bsymmetric\s*key\b",
    # Memory safety
    r"\bbuffer\s*overflow\b", r"\bbuffer\s*overrun\b", r"\bstack\s*overflow\b",
    r"\bmemory\s*(alloc|management|safety|corruption)\b",
    r"\binteger\s*overflow\b", r"\buse.after.free\b",
    # Path/traversal
    r"\bpath\s*traversal\b", r"\bdirectory\s*traversal\b",
    r"\bcanonical(ization)?\b",
    # Deserialization
    r"\bdeserialization\b", r"\bdeserializ", r"\bunsafe\s*deseri",
    # Information disclosure in code
    r"\berror\s*message.*detail\b", r"\bstack\s*trace\b",
    r"\bexception\s*(detail|message|handling)\b",
    r"\binformation\s*leak", r"\bdata\s*leak",
    r"\bsensitive\s*(data|information)\s*(in\s*)?(error|message|log|output|response)",
    # Input validation
    r"\binput\s*validat", r"\bvalidat(e|ion)\s*(input|data)\b",
    r"\bdata\s*validat", r"\bsaniti[sz]", r"\bescap(e|ing)\b",
    r"\bformat\s*string\b",
    # Randomness
    r"\binsecure\s*random", r"\bpseudo.?random\b", r"\bweak\s*random",
    r"\brandom\s*(number|seed|generat)\b",
    # Race conditions
    r"\brace\s*condition\b", r"\btime.of.check", r"\btoctou\b",
    # Output encoding
    r"\boutput\s*encod", r"\bhtml\s*encod", r"\burl\s*encod",
    # Redirect/forward
    r"\bopen\s*redirect\b", r"\bunvalidated\s*redirect\b",
    # CSRF / clickjacking
    r"\bcsrf\b", r"\bcross.site\s*request\b", r"\bclickjack\b",
    # File upload / inclusion
    r"\bfile\s*(upload|inclusion|execut)\b", r"\bremote\s*file\s*inclus\b",
    r"\blocal\s*file\s*inclus\b",
    # XXE
    r"\bxxe\b", r"\bxml\s*(external\s*entity|entity\s*expan)",
    # Prototype pollution / eval
    r"\beval\(\b", r"\bproto(type)?\s*pollution\b",
    # Access control at code level
    r"\bauthoriz(e|ation)\s*(check|validat|verif)\b",
    r"\bauthentication\s*(token|session|cookie)\b",
    # Session
    r"\bsession\s*(fixation|hijack|token\s*generat)\b",
    r"\bcookie\s*(secur|httponly|samesite)\b",
    # Logging sensitive data
    r"\blog(ging)?\s*(password|credential|sensitive|pii|secret)\b",
    # SSRF
    r"\bssrf\b", r"\bserver.side\s*request\s*forg\b",
]

# Keywords strongly indicative of procedural/policy controls
PROCEDURAL_PATTERNS = [
    r"\baccess\s*control\s*polic",
    r"\bsystem\s*documentation\b", r"\bdocument(ation|ed)?\s*(procedure|process|polic)",
    r"\bpolicies?\s*and\s*procedures?\b",
    r"\baudit\s*(log|trail|record|event)\s*(review|retention|generat|collec|monit)",
    r"\bpatch\s*(management|level|version)\b",
    r"\bsoftware\s*(maintenance|update|patch|version)\b",
    r"\bcode\s*review\b", r"\bpeer\s*review\b", r"\bmanual\s*review\b",
    r"\bsecurity\s*(training|awareness|plan)\b",
    r"\bsystem\s*owner\b", r"\bdata\s*owner\b",
    r"\bconting(ency|encies)\s*plan",
    r"\bincident\s*response\b",
    r"\bchange\s*management\b", r"\bconfiguration\s*management\b",
    r"\bbackup\s*(procedure|policy|plan)\b",
    r"\bphysical\s*(security|access)\b",
    r"\bpersonnel\s*security\b",
    r"\bnetwork\s*(architecture|topology|segment)\b",
    r"\bfirewall\s*(rule|policy|config)\b",
    r"\bsystem\s*interconnect\b",
    r"\bscanning\s*(tool|result|report)\b",
    r"\bvulnerability\s*scan",
    r"\bapplication\s*owner\b",
    r"\borganization.defined\b",
    r"\bprocedure\s*(for|to)\b",
    r"\bsession\s*timeout\b", r"\bidle\s*(timeout|session)\b",
    r"\bmaximum\s*(session|login|logon|connection)\b",
    r"\bnumber\s*of\s*(sessions|connections|logons)\b",
    r"\blimit\s*(number|concurrent)\b",
    r"\bapplication\s*must\s*(be\s*)?(configured|documented|reviewed|provid(e|ing)\s*(a\s*)?capability)\b",
    r"\bdesigned\s*and\s*configured\b",
    r"\bapplication\s*must\s*be\s*designed\b",
    r"\bsecurity\s*assessment\b",
    r"\brisk\s*assessment\b",
    r"\bauthority\s*to\s*operate\b", r"\bato\b",
]

# Compile patterns once
SAST_RE = [re.compile(p, re.IGNORECASE) for p in SAST_PATTERNS]
PROC_RE = [re.compile(p, re.IGNORECASE) for p in PROCEDURAL_PATTERNS]


def score_finding(finding: dict) -> tuple[int, int]:
    """Return (sast_score, procedural_score) based on text pattern matching."""
    text = " ".join([
        finding["title"],
        finding["vuln_discussion"],
        finding["check_content"],
    ])
    sast_score = sum(1 for r in SAST_RE if r.search(text))
    proc_score = sum(1 for r in PROC_RE if r.search(text))
    return sast_score, proc_score


def classify_finding(finding: dict) -> tuple[str, str]:
    """Return (method, rationale).

    Strategy:
    1. Score title + vuln_discussion with SAST/procedural patterns (the "what")
    2. Use check_content only as a tiebreaker signal (the "how to verify")
    3. Forced procedural override only when the title itself describes a
       process/policy/audit/scan requirement rather than a code property.
    """
    title = finding["title"]
    check = finding["check_content"]
    vuln = finding["vuln_discussion"]

    # Score title + vuln_discussion separately from check_content.
    # Check content describes the *verification method*, which often starts with
    # "interview/review docs" even for purely code-level vulnerabilities.
    title_vuln = " ".join([title, vuln])
    tv_sast = sum(1 for r in SAST_RE if r.search(title_vuln))
    tv_proc = sum(1 for r in PROC_RE if r.search(title_vuln))
    _, check_proc = sum(1 for r in SAST_RE if r.search(check)), sum(
        1 for r in PROC_RE if r.search(check)
    )

    # Combined scores weight title+vuln 2x vs check_content
    sast_score = tv_sast * 2
    proc_score = tv_proc * 2 + check_proc

    # Forced procedural: title directly describes a scan/assessment/audit *process*
    # or a documentation/identification requirement — inherently non-automatable
    title_is_process = bool(re.search(
        r"\b(assessment|testing|scan|review|audit|code\s*review|interview|"
        r"configuration\s*guide|policy|procedure|training|plan|document)\s+"
        r"(must|should|shall|will|is|are)?\s*(be\s*)?(conducted|performed|"
        r"created|documented|maintained|established|developed|provided|"
        r"included|reviewed|tested|approved)\b",
        title, re.IGNORECASE
    )) or bool(re.search(
        r"\b(must\s+be\s+(identified\s+and\s+documented|documented\s+and\s+identified)|"
        r"requirements?\s+must\s+be\s+(identified|documented|established))\b",
        title, re.IGNORECASE
    ))
    if title_is_process:
        return "procedural", "Title describes a process/audit requirement, not a code property"

    # Check-content heuristic: does the verification involve reading source code?
    code_review_check = bool(re.search(
        r"\b(review\s+(the\s+)?(source\s*code|code\s+to|application\s*code)|"
        r"examine\s+(the\s+)?(source|code)|inspect\s+(the\s+)?code|"
        r"search\s+(the\s+)?code)\b",
        check, re.IGNORECASE
    ))
    doc_review_check = bool(re.search(
        r"\b(documentation|interview|system\s*owner|review\s*the\s*system|"
        r"policy|procedure|configuration\s*(file|setting)|organizational|"
        r"review\s*(the\s*)?(system|policy|procedure|plan|document)|"
        r"number\s*of|limit\s*(the\s*)?(number|concurrent|logon|session))\b",
        check, re.IGNORECASE
    ))

    if sast_score > proc_score and sast_score >= 2:
        method = "sast"
        matched = [p for r, p in zip(SAST_RE, SAST_PATTERNS) if r.search(title_vuln)]
        rationale = f"Code-level vulnerability indicators: {', '.join(matched[:3])}"
    elif proc_score > sast_score and proc_score >= 4:
        method = "procedural"
        matched = [p for r, p in zip(PROC_RE, PROCEDURAL_PATTERNS) if r.search(title_vuln)]
        rationale = f"Policy/process control: {', '.join(matched[:3])}"
    elif sast_score > 0 and code_review_check:
        method = "sast"
        rationale = "Check content requires source code inspection; SAST indicators present"
    elif proc_score > sast_score and doc_review_check and tv_sast == 0:
        method = "procedural"
        rationale = "No SAST indicators in title/description; check requires documentation review"
    elif sast_score == proc_score and sast_score > 0:
        # Tie: lean toward sast per task instructions
        method = "sast"
        rationale = "Ambiguous — leaning sast (borderline inclusion policy)"
    elif sast_score == 0 and proc_score == 0:
        # No strong signals — look at title keywords alone
        sast_title = bool(re.search(
            r"\b(inject|xss|overflow|encrypt|decrypt|hash|crypto|password|"
            r"credential|key|random|validat|sanitiz|traversal|buffer|"
            r"\bsql\b|header|cookie|token|deseri|encod|xxe|csrf|redirect|"
            r"certificate|tls|ssl|cipher|signature|fips|saml|pki)\b",
            title, re.IGNORECASE
        ))
        if sast_title:
            method = "sast"
            rationale = "Title describes code-level vulnerability or crypto property"
        else:
            method = "procedural"
            rationale = "No SAST indicators found; defaulting to procedural"
    else:
        method = "sast" if sast_score >= proc_score else "procedural"
        rationale = f"Scores: sast={sast_score}, procedural={proc_score}"

    # Final trim: shorten rationale regex pattern to readable text
    rationale = re.sub(r"\\b|\\s\*|\(\?:.*?\)|[\\()]", " ", rationale).strip()
    rationale = re.sub(r"\s+", " ", rationale)
    return method, rationale


def classify_all(findings: list[dict]) -> dict:
    classifications = {}
    for f in findings:
        method, rationale = classify_finding(f)
        classifications[f["v_id"]] = {
            "assessment_method": method,
            "rationale": rationale,
        }
    return classifications


def write_classifications(findings: list[dict], classifications: dict) -> None:
    sast_count = sum(1 for v in classifications.values() if v["assessment_method"] == "sast")
    proc_count = sum(1 for v in classifications.values() if v["assessment_method"] == "procedural")

    # Annotate with title for readability
    titled = {}
    for f in findings:
        vid = f["v_id"]
        c = classifications[vid]
        titled[vid] = {
            "title": f["title"],
            "assessment_method": c["assessment_method"],
            "rationale": c["rationale"],
        }

    header = (
        "# SAST-assessable classification for ASD STIG V6 findings\n"
        "# sast = detectable by static analysis\n"
        "# procedural = requires human review\n"
        f"# Totals: {sast_count} sast, {proc_count} procedural out of {len(findings)} findings\n"
    )
    out = {"classifications": titled}
    OUT_CLASS.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_CLASS, "w") as f:
        f.write(header)
        yaml.dump(out, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    print(f"\n--- Classification Summary ---")
    print(f"  SAST:       {sast_count:4d} / {len(findings)}")
    print(f"  Procedural: {proc_count:4d} / {len(findings)}")
    print(f"Wrote classifications → {OUT_CLASS}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=== Step 1-2: Extracting CCI→NIST mappings ===")
    cci_map = extract_cci_mappings()
    write_cci_yaml(cci_map)

    print("\n=== Step 3: Parsing XCCDF and validating CCI chain ===")
    findings = parse_xccdf()
    summarize_cci_chain(findings, cci_map)

    print("\n=== Step 4: Classifying findings ===")
    classifications = classify_all(findings)
    write_classifications(findings, classifications)


if __name__ == "__main__":
    main()
