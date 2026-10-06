"""
report_evidence.py — Deterministic report evidence enrichment for Feature 2.

Builds an enriched, fully traceable evidence object for the 6 report sections:
  1. WHY        — Priority rationale, dynamic score breakdown table, formula/version
  2. WHAT       — Description, decoded CVSS, KEV vulnerability name/description
  3. WHERE      — Affected vendors/products/CPEs with explicit version ranges
  4. HOW        — KEV exploitation status, ransomware use, EPSS, decoded attack vector
  5. RESOLUTION — Ordered remediation actions, KEV due date, grouped patch/advisory URLs, CWE mitigations
  6. ORIGIN     — MITRE CWE root cause, description, consequences, lifecycle timeline

Evidence-grounding rule:
If the evidence does not contain a specific detail, it explicitly states
"Not stated in available evidence".
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from app.config import (
    CVSS_WEIGHT,
    EPSS_WEIGHT,
    KEV_WEIGHT,
    RECOMMENDED_ACTIONS,
)
from app.db import get_all_sync_states, get_cve, get_cwe, get_kev, upsert_cwe

logger = logging.getLogger(__name__)

NOT_STATED = "Not stated in available evidence"

# ── Built-in MITRE CWE Knowledge Base (Offline fallback & seed cache) ──────────

BUILTIN_CWE_CATALOG: dict[str, dict[str, Any]] = {
    "CWE-79": {
        "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "description": "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
        "consequences": [
            "Execution of unauthorized code or scripts in victim browser",
            "Session hijacking and credential theft",
            "Defacement and redirecting victims to malicious hosts",
        ],
        "mitigations": [
            "Context-aware output encoding (HTML, JavaScript, CSS, URL encoding)",
            "Strict Content Security Policy (CSP) headers",
            "Input validation using allowlists and automated sanitization libraries",
        ],
    },
    "CWE-89": {
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "description": "The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
        "consequences": [
            "Unauthorized read, modification, or deletion of sensitive database contents",
            "Authentication bypass and administrative takeover",
            "Remote command execution via database administrative extensions",
        ],
        "mitigations": [
            "Use parameterized queries / prepared statements for all database interactions",
            "Employ Object Relational Mapping (ORM) frameworks with parameter binding",
            "Enforce principle of least privilege on database accounts",
        ],
    },
    "CWE-787": {
        "name": "Out-of-bounds Write",
        "description": "The software writes data past the end, or before the beginning, of the intended buffer, potentially corrupting data, crashing the system, or executing arbitrary code.",
        "consequences": [
            "Arbitrary code execution with privileges of the vulnerable process",
            "Memory corruption resulting in persistent denial of service (DoS)",
            "Control flow hijacking via overwritten return addresses or function pointers",
        ],
        "mitigations": [
            "Use memory-safe programming languages (Rust, Go, Swift, Java)",
            "Perform bounds checking on all buffer write and copy operations",
            "Enable compiler exploit mitigations: ASLR, DEP/NX, Stack Canaries, and SafeStack",
        ],
    },
    "CWE-125": {
        "name": "Out-of-bounds Read",
        "description": "The software reads data past the end, or before the beginning, of the intended buffer.",
        "consequences": [
            "Exposure of confidential memory contents (keys, passwords, addresses)",
            "Denial of service through memory segmentation faults",
        ],
        "mitigations": [
            "Validate all buffer read boundaries before accessing array indices",
            "Use bounds-checked data structures and standard container accessors",
        ],
    },
    "CWE-20": {
        "name": "Improper Input Validation",
        "description": "The product receives input or data, but it does not validate or incorrectly validates that the input conforms to expectations regarding syntax, structure, or semantics.",
        "consequences": [
            "Altered control flow leading to unauthorized feature execution",
            "Unexpected application crash or resource exhaustion",
        ],
        "mitigations": [
            "Validate all untrusted input against strict positive specifications (allowlisting)",
            "Perform canonicalization before validation",
        ],
    },
    "CWE-22": {
        "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "description": "The product uses external input to construct a pathname that should be within a restricted directory, but does not properly neutralize sequences such as '..' that can resolve to a location outside that directory.",
        "consequences": [
            "Arbitrary file disclosure (configuration, source code, credentials)",
            "Arbitrary file overwrite leading to remote code execution",
        ],
        "mitigations": [
            "Use indirect reference maps (index keys) instead of user-supplied filenames",
            "Resolve absolute canonical paths and verify the path remains within the base directory",
        ],
    },
    "CWE-416": {
        "name": "Use After Free",
        "description": "Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.",
        "consequences": [
            "Arbitrary code execution",
            "Denial of service via crash",
        ],
        "mitigations": [
            "Set pointers to NULL immediately after freeing memory",
            "Use smart pointers or automatic memory management",
        ],
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "description": "When an actor claims to have a given identity, the software does not prove or improperly proves that the claim is correct.",
        "consequences": [
            "Complete authentication bypass",
            "Unauthorized access to administrative resources",
        ],
        "mitigations": [
            "Implement multi-factor authentication (MFA)",
            "Use proven standard authentication libraries and frameworks",
        ],
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
        "consequences": [
            "Remote code execution via gadget chains",
            "Denial of service and data tampering",
        ],
        "mitigations": [
            "Avoid deserializing binary formats from untrusted sources; prefer JSON or Protocol Buffers",
            "Sign and encrypt serialized objects to prevent unauthorized alteration",
        ],
    },
    "CWE-77": {
        "name": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
        "description": "The software constructs an operating system command using externally-influenced input without sufficient neutralization.",
        "consequences": [
            "Arbitrary command execution in the host environment",
            "Full host system compromise and lateral movement",
        ],
        "mitigations": [
            "Avoid invoking OS shell interpreters directly; use structured API calls with discrete arguments",
            "Enforce strict character and argument allowlists",
        ],
    },
}


# ── CVSS Vector Decoder (Pure Python) ─────────────────────────────────────────

_CVSS_MAPS: dict[str, dict[str, str]] = {
    "AV": {
        "N": "Network (Remotely exploitable across the Internet without physical or local subnet access)",
        "A": "Adjacent Network (Exploitable only from the local subnetwork/broadcast domain)",
        "L": "Local (Requires local shell or console access on the vulnerable host)",
        "P": "Physical (Requires physical interaction with the device hardware)",
    },
    "AC": {
        "L": "Low (No specialized access conditions or complex configurations required)",
        "H": "High (Exploit depends on unpredictable conditions or race windows)",
    },
    "PR": {
        "N": "None (No prior authentication or privileges required)",
        "L": "Low (Requires basic unprivileged user account access)",
        "H": "High (Requires administrative or elevated system privileges)",
    },
    "UI": {
        "N": "None (Vulnerability can be exploited without any user interaction)",
        "R": "Required (Requires a victim user to perform an action, such as visiting a link or opening a file)",
    },
    "S": {
        "U": "Unchanged (Exploited component affects only its own security authority)",
        "C": "Changed (Exploitation allows impacting components beyond its security authority)",
    },
    "C": {
        "H": "High (Total confidentiality breach; all data can be read or exfiltrated)",
        "L": "Low (Partial access to restricted information)",
        "N": "None (No confidentiality impact)",
    },
    "I": {
        "H": "High (Total integrity loss; critical files, logic, or data can be modified)",
        "L": "Low (Modification of limited non-critical data)",
        "N": "None (No integrity impact)",
    },
    "A": {
        "H": "High (Complete denial of service; system or service becomes fully unavailable)",
        "L": "Low (Reduced performance or intermittent availability disruptions)",
        "N": "None (No availability impact)",
    },
}


def decode_cvss_vector(vector_string: str | None) -> dict[str, Any]:
    """Decode a CVSS v3.x vector string into structured plain-English metrics."""
    if not vector_string:
        return {
            "raw_vector": NOT_STATED,
            "version": NOT_STATED,
            "attack_vector": NOT_STATED,
            "attack_complexity": NOT_STATED,
            "privileges_required": NOT_STATED,
            "user_interaction": NOT_STATED,
            "scope": NOT_STATED,
            "confidentiality_impact": NOT_STATED,
            "integrity_impact": NOT_STATED,
            "availability_impact": NOT_STATED,
            "summary": "CVSS metrics not stated in available evidence.",
        }

    raw = vector_string.strip()
    version = "3.1" if "CVSS:3.1" in raw else "3.0" if "CVSS:3.0" in raw else "2.0"
    parts = raw.split("/")

    decoded: dict[str, str] = {}
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            decoded[k.upper()] = v.upper()

    av = _CVSS_MAPS["AV"].get(decoded.get("AV", ""), decoded.get("AV", NOT_STATED))
    ac = _CVSS_MAPS["AC"].get(decoded.get("AC", ""), decoded.get("AC", NOT_STATED))
    pr = _CVSS_MAPS["PR"].get(decoded.get("PR", ""), decoded.get("PR", NOT_STATED))
    ui = _CVSS_MAPS["UI"].get(decoded.get("UI", ""), decoded.get("UI", NOT_STATED))
    sc = _CVSS_MAPS["S"].get(decoded.get("S", ""), decoded.get("S", NOT_STATED))
    c = _CVSS_MAPS["C"].get(decoded.get("C", ""), decoded.get("C", NOT_STATED))
    i = _CVSS_MAPS["I"].get(decoded.get("I", ""), decoded.get("I", NOT_STATED))
    a = _CVSS_MAPS["A"].get(decoded.get("A", ""), decoded.get("A", NOT_STATED))

    summary_parts = []
    if decoded.get("AV"):
        summary_parts.append(f"Attack Vector: {av}")
    if decoded.get("AC"):
        summary_parts.append(f"Attack Complexity: {ac}")
    if decoded.get("PR"):
        summary_parts.append(f"Privileges Required: {pr}")
    if decoded.get("UI"):
        summary_parts.append(f"User Interaction: {ui}")
    if decoded.get("C") or decoded.get("I") or decoded.get("A"):
        summary_parts.append(f"Impact: Confidentiality [{decoded.get('C', '-')}] Integrity [{decoded.get('I', '-')}] Availability [{decoded.get('A', '-')}]")

    return {
        "raw_vector": raw,
        "version": version,
        "attack_vector": av,
        "attack_complexity": ac,
        "privileges_required": pr,
        "user_interaction": ui,
        "scope": sc,
        "confidentiality_impact": c,
        "integrity_impact": i,
        "availability_impact": a,
        "summary": " | ".join(summary_parts) if summary_parts else NOT_STATED,
    }


# ── CWE Catalog Service ───────────────────────────────────────────────────────

async def fetch_cwe_from_mitre(cwe_id: str) -> Optional[dict[str, Any]]:
    """
    Fetch an official CWE entry from the MITRE CWE catalog website and parse structured metadata.
    """
    clean_id = cwe_id.strip().upper()
    if not clean_id.startswith("CWE-"):
        clean_id = f"CWE-{clean_id}"
    num = clean_id.replace("CWE-", "")
    if not num.isdigit():
        return None

    url = f"https://cwe.mitre.org/data/definitions/{num}.html"
    try:
        from bs4 import BeautifulSoup
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(url, headers={"User-Agent": "KEVIDENCE/2.0 (Security Advisory Engine)"})
            if resp.status_code != 200:
                return None
            html = resp.text

        soup = BeautifulSoup(html, "html.parser")

        # Name
        name = clean_id
        title_el = soup.find("title")
        if title_el:
            t_text = " ".join(title_el.text.split())
            if f"CWE-{num}:" in t_text:
                name_part = t_text.split(f"CWE-{num}:", 1)[1]
                if "(" in name_part and name_part.rstrip().endswith(")"):
                    name_part = name_part.rsplit("(", 1)[0]
                name = name_part.strip()

        # Description
        desc_text = NOT_STATED
        desc_el = soup.find("div", id="Description")
        if desc_el:
            indent = desc_el.find("div", class_="indent")
            desc_text = (indent or desc_el).get_text(" ", strip=True)

        # Consequences
        consequences: list[str] = []
        conseq_el = soup.find("div", id="Common_Consequences")
        if conseq_el:
            for row in conseq_el.find_all("tr"):
                tds = row.find_all("td")
                if len(tds) >= 2:
                    impact = tds[1].get_text(" ", strip=True)
                    if impact and len(impact) > 10 and impact not in consequences:
                        consequences.append(impact)
                        if len(consequences) >= 4:
                            break
        if not consequences:
            consequences = [NOT_STATED]

        # Mitigations
        mitigations: list[str] = []
        mitig_el = soup.find("div", id="Potential_Mitigations")
        if mitig_el:
            for tr in mitig_el.find_all("tr"):
                tds = tr.find_all("td")
                if len(tds) >= 2:
                    mitig_text = tds[1].get_text(" ", strip=True)
                    if mitig_text and len(mitig_text) > 15 and mitig_text not in mitigations:
                        mitigations.append(mitig_text)
                        if len(mitigations) >= 4:
                            break

        return {
            "cwe_id": clean_id,
            "name": name,
            "description": desc_text,
            "consequences": consequences,
            "mitigations": mitigations,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        logger.debug("Live MITRE CWE fetch failed for %s: %s", clean_id, exc)
        return None


async def get_or_fetch_cwe(cwe_id: str) -> dict[str, Any]:
    """
    Retrieve CWE information from the cached table, or fetch live from MITRE CWE catalog.
    Refreshes stale entries weekly (older than 7 days).
    Falls back to built-in catalog or cached copy if offline / unreachable.
    """
    clean_id = cwe_id.strip().upper()
    if not clean_id.startswith("CWE-"):
        clean_id = f"CWE-{clean_id}"

    # 1. Check local DB table
    cached = await get_cwe(clean_id)
    is_stale = False
    if cached:
        fetched_at = cached.get("fetched_at")
        if fetched_at:
            try:
                dt = datetime.fromisoformat(fetched_at)
                if (datetime.now(timezone.utc) - dt).days > 7:
                    is_stale = True
            except ValueError:
                is_stale = True
        else:
            is_stale = True

        # If fresh and has real data, return it
        if not is_stale and cached.get("name") and cached["name"] != NOT_STATED:
            return cached

    # 2. If not in DB or stale, try live fetch from MITRE
    fetched = await fetch_cwe_from_mitre(clean_id)
    if fetched and fetched.get("name") and fetched["name"] != NOT_STATED:
        await upsert_cwe(fetched)
        return fetched

    # If live fetch failed but we have a cached version in DB, keep using it
    if cached and cached.get("name") and cached["name"] != NOT_STATED:
        return cached

    # 3. Check built-in catalog seed
    if clean_id in BUILTIN_CWE_CATALOG:
        entry = dict(BUILTIN_CWE_CATALOG[clean_id])
        entry["cwe_id"] = clean_id
        entry["fetched_at"] = datetime.now(timezone.utc).isoformat()
        await upsert_cwe(entry)
        return entry

    # 4. Default fallback for unknown CWE IDs
    fallback = {
        "cwe_id": clean_id,
        "name": f"{clean_id} Weakness Definition",
        "description": NOT_STATED,
        "consequences": [NOT_STATED],
        "mitigations": [
            "Follow secure coding standards and least-privilege architecture",
            "Perform regular code reviews and dynamic application security testing (DAST)",
        ],
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    await upsert_cwe(fallback)
    return fallback


# ── Structured Enriched Report Evidence ───────────────────────────────────────

@dataclass
class ReportEvidence:
    """Enriched, deterministic evidence container for all 6 report sections."""

    cve_id: str
    data_hash: str

    # WHY section data
    priority_label: str
    priority_score: float
    score_breakdown: list[dict[str, Any]]
    score_formula: str
    scoring_version: str
    reasons: list[str]

    # WHAT section data
    description: str
    cvss_base_score: float | None
    cvss_severity: str
    cvss_decoded: dict[str, Any]
    kev_vulnerability_name: str
    kev_short_description: str

    # WHERE section data
    vendors: list[str]
    products: list[str]
    affected_cpes: list[str]
    version_ranges: list[dict[str, Any]]
    attack_vector: str

    # HOW section data
    in_kev: bool
    kev_status: str
    known_ransomware_use: str
    epss_probability: float
    epss_percentile: float | None

    # RESOLUTION section data
    recommended_action: str
    kev_required_action: str
    kev_due_date: str
    patch_urls: list[str]
    reference_tags_grouped: dict[str, list[str]]
    cwe_mitigations: list[str]

    # ORIGIN section data
    cwe_details: list[dict[str, Any]]
    timeline: dict[str, str]

    # Metadata & timestamps
    published_date: str
    last_modified_date: str
    ingested_at: str
    source_freshness: dict[str, str]


# ── Report Input Change Detection & Hash ───────────────────────────────────────

def compute_report_data_hash(
    cve: dict[str, Any],
    kev: dict[str, Any],
    cwe_details: list[dict[str, Any]],
) -> str:
    """
    Compute a stable SHA-256 hash covering ALL report inputs:
    CVE core fields, CVSS metrics, EPSS data, KEV intelligence,
    version ranges, reference tags, and enriched CWE data.
    Ensures reports automatically invalidate and regenerate whenever any input changes.
    """
    key_dict = {
        # CVE technical data
        "cve_id": cve.get("cve_id"),
        "description": cve.get("description"),
        "cvss_base_score": cve.get("cvss_base_score"),
        "cvss_vector": cve.get("cvss_vector"),
        "severity": cve.get("severity"),
        "attack_vector": cve.get("attack_vector"),
        "epss_score": cve.get("epss_score"),
        "epss_percentile": cve.get("epss_percentile"),
        "in_kev": bool(cve.get("in_kev")),
        "priority_score": cve.get("priority_score"),
        "priority_label": cve.get("priority_label"),
        "cwe_ids": sorted(cve.get("cwe_ids") or []),
        "vendors": sorted(cve.get("vendors") or []),
        "products": sorted(cve.get("products") or []),
        "cpe_version_ranges": cve.get("cpe_version_ranges") or [],
        "reference_urls": sorted(cve.get("reference_urls") or []),
        "patch_references": sorted(cve.get("patch_references") or []),
        "reference_tags": cve.get("reference_tags") or {},
        "published_date": cve.get("published_date"),
        "last_modified_date": cve.get("last_modified_date"),
        # KEV Threat Intel
        "kev_vulnerability_name": kev.get("vulnerability_name"),
        "kev_short_desc": kev.get("short_description"),
        "kev_date_added": kev.get("date_added"),
        "kev_due_date": kev.get("due_date"),
        "kev_required_action": kev.get("required_action"),
        "kev_ransomware": kev.get("known_ransomware_use"),
        # CWE catalog details
        "cwes": [
            {
                "id": c.get("cwe_id"),
                "name": c.get("name"),
                "desc": c.get("description"),
                "mitigations": c.get("mitigations"),
            }
            for c in cwe_details
        ],
    }
    raw = json.dumps(key_dict, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ── Enriched Evidence Builder ─────────────────────────────────────────────────

async def build_report_evidence(cve_id: str) -> Optional[ReportEvidence]:
    """
    Construct the enriched ReportEvidence object for a CVE.
    Deterministic, pure-code; enforces the evidence-grounding principle.
    """
    cve = await get_cve(cve_id)
    if not cve:
        return None

    kev = await get_kev(cve_id) or {}

    # 1. WHY Data
    priority_label = cve.get("priority_label", "LOW")
    priority_score = float(cve.get("priority_score", 0.0))
    cvss_score = float(cve.get("cvss_base_score") or 0.0)
    epss_score = float(cve.get("epss_score") or 0.0)
    in_kev_bool = bool(cve.get("in_kev"))

    # Compute dynamic score breakdown
    cvss_norm = cvss_score / 10.0
    cvss_contrib = round(cvss_norm * CVSS_WEIGHT, 4)
    epss_contrib = round(epss_score * EPSS_WEIGHT, 4)
    kev_contrib = round((1.0 if in_kev_bool else 0.0) * KEV_WEIGHT, 4)

    score_breakdown = [
        {
            "component": "Technical Severity (CVSS v3.1)",
            "raw_value": f"{cvss_score:.1f} / 10.0",
            "weight": f"{int(CVSS_WEIGHT * 100)}%",
            "contribution": f"{cvss_contrib:.3f}",
            "source": "[NVD]",
        },
        {
            "component": "Exploitation Likelihood (EPSS)",
            "raw_value": f"{epss_score * 100:.2f}%",
            "weight": f"{int(EPSS_WEIGHT * 100)}%",
            "contribution": f"{epss_contrib:.3f}",
            "source": "[EPSS]",
        },
        {
            "component": "Active Threat Intel (CISA KEV)",
            "raw_value": "Weaponized (In KEV)" if in_kev_bool else "Not in KEV",
            "weight": f"{int(KEV_WEIGHT * 100)}%",
            "contribution": f"{kev_contrib:.3f}",
            "source": "[KEV]",
        },
    ]

    score_formula = (
        f"Priority Score = ({cvss_norm:.3f} × {CVSS_WEIGHT}) + "
        f"({epss_score:.4f} × {EPSS_WEIGHT}) + "
        f"({1.0 if in_kev_bool else 0.0} × {KEV_WEIGHT}) = {priority_score:.3f}"
    )
    scoring_version = "PhantomPatch Triangulation Model v2.0"

    reasons = cve.get("reasons") or []
    if not reasons:
        reasons = [f"Classified as {priority_label} based on technical and threat signals."]

    # 2. WHAT Data
    description = cve.get("description") or NOT_STATED
    cvss_decoded = decode_cvss_vector(cve.get("cvss_vector"))
    kev_vuln_name = kev.get("vulnerability_name") or NOT_STATED
    kev_short_desc = kev.get("short_description") or NOT_STATED

    # 3. WHERE Data
    vendors = cve.get("vendors") or []
    products = cve.get("products") or []
    affected_cpes = cve.get("affected_cpes") or []
    version_ranges = cve.get("cpe_version_ranges") or []
    attack_vector = cve.get("attack_vector") or cvss_decoded.get("attack_vector") or NOT_STATED

    # 4. HOW Data
    kev_status = (
        "CONFIRMED WEAPONIZATION (Cataloged in CISA Known Exploited Vulnerabilities)"
        if in_kev_bool
        else "Not listed in CISA Known Exploited Vulnerabilities (KEV)"
    )
    known_ransomware = (
        kev.get("known_ransomware_use")
        or ("Known ransomware campaign use: Not reported in available threat intelligence" if in_kev_bool else NOT_STATED)
    )
    epss_percentile = cve.get("epss_percentile")

    # 5. RESOLUTION Data
    recommended_action = RECOMMENDED_ACTIONS.get(priority_label, RECOMMENDED_ACTIONS.get("LOW", NOT_STATED))
    kev_required_action = kev.get("required_action") or (
        "Mandatory patching mandated by CISA BOD 22-01" if in_kev_bool else NOT_STATED
    )
    kev_due_date = kev.get("due_date") or ("Immediate federal compliance deadline" if in_kev_bool else NOT_STATED)
    patch_urls = cve.get("patch_references") or []
    ref_tags_grouped = cve.get("reference_tags") or {}

    # 6. ORIGIN Data (CWE Mapping + Timeline)
    cwe_ids = cve.get("cwe_ids") or []
    cwe_details = []
    cwe_mitigations = []
    for cid in cwe_ids:
        info = await get_or_fetch_cwe(cid)
        cwe_details.append(info)
        cwe_mitigations.extend(info.get("mitigations", []))

    # Remove duplicates from CWE mitigations
    cwe_mitigations = list(dict.fromkeys(cwe_mitigations))
    if not cwe_mitigations:
        cwe_mitigations = [NOT_STATED]

    # Calculate data hash covering ALL report inputs
    data_hash = compute_report_data_hash(cve, kev, cwe_details)

    # Timeline
    pub_date = cve.get("published_date") or NOT_STATED
    mod_date = cve.get("last_modified_date") or pub_date
    kev_date_added = kev.get("date_added") or (NOT_STATED if in_kev_bool else "Not in KEV")
    target_summary = f"{', '.join(vendors[:2])} - {', '.join(products[:2])}" if vendors or products else NOT_STATED

    timeline = {
        "Published Date": pub_date,
        "Last Modified Date": mod_date,
        "CISA KEV Addition": kev_date_added,
        "Remediation Due Date": kev_due_date,
        "Target Affected Component": target_summary,
    }

    # Query true synchronization state from DB
    sync_states_raw = await get_all_sync_states()
    sync_map = {s["source"]: s.get("last_success_at") for s in sync_states_raw}
    nvd_fresh = sync_map.get("nvd") or mod_date or "Live Feed"
    kev_fresh = sync_map.get("kev") or (kev_date_added if in_kev_bool else "Continuous Polling")
    epss_fresh = sync_map.get("epss") or (cve.get("ingested_at") or "Daily Scoring Cycle")
    cwe_fresh = cwe_details[0].get("fetched_at", "Weekly Cache") if cwe_details else "Weekly Cache"

    source_freshness = {
        "NVD (NIST CVE Feed)": str(nvd_fresh),
        "CISA KEV Threat Intel": str(kev_fresh),
        "FIRST.org EPSS Feed": str(epss_fresh),
        "MITRE CWE Catalog": str(cwe_fresh),
    }

    return ReportEvidence(
        cve_id=cve_id,
        data_hash=data_hash,
        priority_label=priority_label,
        priority_score=priority_score,
        score_breakdown=score_breakdown,
        score_formula=score_formula,
        scoring_version=scoring_version,
        reasons=reasons,
        description=description,
        cvss_base_score=cvss_score if cvss_score > 0 else None,
        cvss_severity=cve.get("severity", "UNKNOWN"),
        cvss_decoded=cvss_decoded,
        kev_vulnerability_name=kev_vuln_name,
        kev_short_description=kev_short_desc,
        vendors=vendors,
        products=products,
        affected_cpes=affected_cpes,
        version_ranges=version_ranges,
        attack_vector=attack_vector,
        in_kev=in_kev_bool,
        kev_status=kev_status,
        known_ransomware_use=known_ransomware,
        epss_probability=epss_score,
        epss_percentile=epss_percentile,
        recommended_action=recommended_action,
        kev_required_action=kev_required_action,
        kev_due_date=kev_due_date,
        patch_urls=patch_urls,
        reference_tags_grouped=ref_tags_grouped,
        cwe_mitigations=cwe_mitigations,
        cwe_details=cwe_details,
        timeline=timeline,
        published_date=pub_date,
        last_modified_date=mod_date,
        ingested_at=cve.get("ingested_at") or datetime.now(timezone.utc).isoformat(),
        source_freshness=source_freshness,
    )


def verbalize_report_evidence(evidence: ReportEvidence) -> list[str]:
    """Convert ReportEvidence into grounded fact sentences for the verifier."""
    sents: list[str] = [
        f"This vulnerability is identified as {evidence.cve_id}.",
        f"The priority label is {evidence.priority_label} with priority score {evidence.priority_score:.3f}.",
        f"The description is: {evidence.description}.",
        f"The recommended action is: {evidence.recommended_action}.",
    ]
    if evidence.cvss_base_score is not None:
        sents.append(f"The CVSS base score is {evidence.cvss_base_score} ({evidence.cvss_severity}).")
    if evidence.cvss_decoded.get("summary") and evidence.cvss_decoded["summary"] != NOT_STATED:
        sents.append(f"CVSS metrics: {evidence.cvss_decoded['summary']}.")
    if evidence.attack_vector and evidence.attack_vector != NOT_STATED:
        sents.append(f"The attack vector is {evidence.attack_vector}.")

    if evidence.in_kev:
        sents.append("This vulnerability is cataloged in CISA Known Exploited Vulnerabilities.")
        sents.append("Listed in CISA Known Exploited Vulnerabilities.")
        if evidence.kev_vulnerability_name and evidence.kev_vulnerability_name != NOT_STATED:
            sents.append(f"KEV vulnerability name: {evidence.kev_vulnerability_name}.")
        if evidence.kev_short_description and evidence.kev_short_description != NOT_STATED:
            sents.append(f"KEV description: {evidence.kev_short_description}.")
        if evidence.kev_required_action and evidence.kev_required_action != NOT_STATED:
            sents.append(f"KEV required action: {evidence.kev_required_action}.")
        if evidence.kev_due_date and evidence.kev_due_date != NOT_STATED:
            sents.append(f"Remediation due date: {evidence.kev_due_date}.")
        if evidence.known_ransomware_use and evidence.known_ransomware_use != NOT_STATED:
            sents.append(f"Known ransomware campaign use: {evidence.known_ransomware_use}.")
    else:
        sents.append("This vulnerability is not cataloged in CISA KEV.")
        sents.append("This vulnerability is not listed in the CISA KEV catalog.")
        sents.append("Not listed in CISA Known Exploited Vulnerabilities.")
        sents.append("Not listed in CISA Known Exploited Vulnerabilities (KEV).")
        sents.append("No known ransomware campaign use reported in available evidence.")
        sents.append("There is no current cataloging in CISA Known Exploited Vulnerabilities.")

    sents.append(f"The EPSS exploitation probability is {evidence.epss_probability:.4f} ({evidence.epss_probability * 100:.2f}%).")
    if evidence.epss_percentile is not None:
        sents.append(f"The EPSS percentile is {evidence.epss_percentile:.4f} ({evidence.epss_percentile * 100:.1f}%).")

    if evidence.vendors:
        sents.append(f"Affected vendors: {', '.join(evidence.vendors)}.")
    if evidence.products:
        sents.append(f"Affected products: {', '.join(evidence.products)}.")
    for vr in evidence.version_ranges[:5]:
        sents.append(f"Affected version range: {vr.get('vendor')} {vr.get('product')} criteria {vr.get('criteria')}.")

    for cwe in evidence.cwe_details:
        sents.append(f"Weakness root cause: {cwe.get('cwe_id')} {cwe.get('name')}.")
        if cwe.get("description") and cwe["description"] != NOT_STATED:
            sents.append(f"Weakness description: {cwe['description']}.")

    for url in evidence.patch_urls:
        sents.append(f"Authoritative patch reference URL: {url}.")

    return sents

