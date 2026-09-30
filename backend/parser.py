"""
parser.py — Flatten raw NVD CVE JSON into clean structured records.
"""
from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def _extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """Return (base_score, vector_string, severity) preferring CVSSv3.1 > v3.0 > v2."""
    # Try CVSSv3.1
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            cv = primary.get("cvssData", {})
            return (
                cv.get("baseScore"),
                cv.get("vectorString"),
                cv.get("baseSeverity"),
            )
    # Fallback: CVSSv2
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cv = primary.get("cvssData", {})
        sev = primary.get("baseSeverity") or cv.get("baseSeverity")
        return (cv.get("baseScore"), cv.get("vectorString"), sev)
    return None, None, None


def _extract_cwe_ids(weaknesses: list[dict]) -> list[str]:
    ids: list[str] = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                ids.append(val)
    return list(set(ids))


def _extract_cpes(configurations: list[dict]) -> list[str]:
    cpes: list[str] = []
    for node_group in configurations:
        for node in node_group.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if criteria:
                    cpes.append(criteria)
    return list(set(cpes))


def _extract_vendors_from_cpes(cpes: list[str]) -> list[str]:
    """
    Parse vendor/product from CPE 2.3 strings.
    Format: cpe:2.3:a:<vendor>:<product>:...
    """
    vendors: set[str] = set()
    for cpe in cpes:
        parts = cpe.split(":")
        # cpe:2.3:type:vendor:product:...
        if len(parts) >= 5:
            vendor = parts[3]
            if vendor and vendor != "*":
                vendors.add(vendor.replace("_", " ").title())
    return list(vendors)


def parse_cve(
    raw: dict[str, Any],
    epss_score: float = 0.0,
    in_kev: bool = False,
) -> dict[str, Any]:
    """Flatten one raw NVD CVE dict into a clean record."""
    cve_id: str = raw.get("id", "")

    # Description (English preferred)
    descriptions = raw.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "",
    )

    # CVSS
    metrics = raw.get("metrics", {})
    cvss_base_score, cvss_vector, severity = _extract_cvss(metrics)

    # CWE
    cwe_ids = _extract_cwe_ids(raw.get("weaknesses", []))

    # CPEs / affected products
    affected_cpes = _extract_cpes(raw.get("configurations", []))
    vendors = _extract_vendors_from_cpes(affected_cpes)

    # References
    references = [r.get("url", "") for r in raw.get("references", []) if r.get("url")]

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_base_score": cvss_base_score,
        "cvss_vector": cvss_vector,
        "severity": (severity or "UNKNOWN").upper(),
        "cwe_ids": json.dumps(cwe_ids),
        "published_date": raw.get("published", ""),
        "last_modified_date": raw.get("lastModified", ""),
        "affected_cpes": json.dumps(affected_cpes),
        "vendors": json.dumps(vendors),
        "reference_urls": json.dumps(references),
        "epss_score": epss_score,
        "in_kev": in_kev,
    }
