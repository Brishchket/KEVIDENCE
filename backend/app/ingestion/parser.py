"""
parser.py — Flatten raw NVD CVE JSON into clean structured records.

Extracts: cve_id, description, CVSS v3.x (score, severity, vector, attack_vector),
CWE IDs, affected vendor/product (from CPE), reference URLs tagged Patch/Vendor Advisory.
Never crashes on missing or malformed fields — logs every failure with a reason.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

_ATTACK_VECTOR_MAP = {
    "N": "NETWORK",
    "A": "ADJACENT_NETWORK",
    "L": "LOCAL",
    "P": "PHYSICAL",
}


def _extract_cvss(
    metrics: dict[str, Any],
) -> tuple[float | None, str | None, str | None, str | None, str | None]:
    """Return (base_score, vector_string, severity, attack_vector, version) preferring CVSSv4.0 > v3.1 > v3.0."""
    for key, version_str in [("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")]:
        entries = metrics.get(key, [])
        if entries:
            primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            cv = primary.get("cvssData", {})
            vector = cv.get("vectorString", "")
            # Extract attack vector from vector string: e.g. CVSS:3.1/AV:N/...
            attack_vector = cv.get("attackVector")
            if not attack_vector and vector:
                match = re.search(r"AV:([NALP])", vector)
                if match:
                    attack_vector = _ATTACK_VECTOR_MAP.get(match.group(1))
            
            # v4.0 sometimes doesn't have baseSeverity directly under cvssData, check both
            severity = cv.get("baseSeverity") or primary.get("baseSeverity")

            return (
                cv.get("baseScore"),
                vector,
                severity,
                attack_vector,
                version_str,
            )
    # Fallback: CVSSv2 (don't extract attack_vector for v2)
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cv = primary.get("cvssData", {})
        sev = primary.get("baseSeverity") or cv.get("baseSeverity")
        return (cv.get("baseScore"), cv.get("vectorString"), sev, None, "2.0")
    return None, None, None, None, None


def _extract_cwe_ids(weaknesses: list[dict]) -> list[str]:
    ids: list[str] = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                ids.append(val)
    return sorted(set(ids))


def _extract_cpes(configurations: list[dict]) -> list[str]:
    cpes, _ = _extract_cpes_and_versions(configurations)
    return cpes


def _extract_cpes_and_versions(configurations: list[dict]) -> tuple[list[str], list[dict[str, Any]]]:
    """Extract CPE criteria strings and detailed version ranges."""
    cpes: list[str] = []
    version_ranges: list[dict[str, Any]] = []
    seen_ranges: set[str] = set()

    for node_group in configurations:
        for node in node_group.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if criteria:
                    cpes.append(criteria)
                v_start_inc = match.get("versionStartIncluding")
                v_start_exc = match.get("versionStartExcluding")
                v_end_inc = match.get("versionEndIncluding")
                v_end_exc = match.get("versionEndExcluding")
                vulnerable = match.get("vulnerable", True)

                key = f"{criteria}|{v_start_inc}|{v_start_exc}|{v_end_inc}|{v_end_exc}"
                if key not in seen_ranges:
                    seen_ranges.add(key)
                    vendor, product = _parse_cpe(criteria) if criteria else (None, None)
                    version_ranges.append({
                        "criteria": criteria,
                        "vendor": vendor,
                        "product": product,
                        "version_start_including": v_start_inc,
                        "version_start_excluding": v_start_exc,
                        "version_end_including": v_end_inc,
                        "version_end_excluding": v_end_exc,
                        "vulnerable": vulnerable,
                    })
    return list(set(cpes)), version_ranges


def _parse_cpe(cpe: str) -> tuple[str | None, str | None]:
    """Parse vendor and product from a CPE 2.3 string."""
    parts = cpe.split(":")
    if len(parts) >= 5:
        vendor = parts[3] if parts[3] != "*" else None
        product = parts[4] if parts[4] != "*" else None
        if vendor:
            vendor = vendor.replace("_", " ").title()
        if product:
            product = product.replace("_", " ").title()
        return vendor, product
    return None, None


def _extract_vendors_products(cpes: list[str]) -> tuple[list[str], list[str]]:
    """Extract unique vendors and products from CPE strings."""
    vendors: set[str] = set()
    products: set[str] = set()
    for cpe in cpes:
        vendor, product = _parse_cpe(cpe)
        if vendor:
            vendors.add(vendor)
        if product:
            products.add(product)
    return sorted(vendors), sorted(products)


def _extract_patch_references(references: list[dict]) -> tuple[list[str], list[str]]:
    all_urls, patch_urls, _ = _extract_references_with_tags(references)
    return all_urls, patch_urls


def _extract_references_with_tags(references: list[dict]) -> tuple[list[str], list[str], dict[str, list[str]]]:
    """
    Separate references into general URLs, patch/advisory URLs,
    and grouped by NVD tag (Patch, Vendor Advisory, Mitigation, Exploit, Third Party Advisory).
    """
    all_urls: list[str] = []
    patch_urls: list[str] = []
    tagged_refs: dict[str, list[str]] = {}
    patch_tags = {"Patch", "Vendor Advisory", "Mitigation"}

    for ref in references:
        url = ref.get("url", "")
        if not url:
            continue
        all_urls.append(url)
        tags = ref.get("tags", [])
        if not tags:
            tagged_refs.setdefault("Other", []).append(url)
        else:
            for tag in tags:
                tagged_refs.setdefault(tag, []).append(url)
        if set(tags) & patch_tags:
            patch_urls.append(url)

    return all_urls, patch_urls, tagged_refs


def parse_cve(
    raw: dict[str, Any],
    epss_data: dict[str, float] | None = None,
    kev_record: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """
    Flatten one raw NVD CVE dict into a clean record.
    Returns None if the CVE cannot be parsed at all (missing cve_id).

    epss_data: {probability, percentile} or None
    kev_record: full KEV record or None
    """
    cve_id: str = raw.get("id", "")
    if not cve_id:
        logger.warning("Skipping CVE with no ID")
        return None

    try:
        # Description (English preferred)
        descriptions = raw.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )

        # CVSS
        metrics = raw.get("metrics", {})
        cvss_base_score, cvss_vector, severity, attack_vector, cvss_version = _extract_cvss(metrics)

        # CWE
        cwe_ids = _extract_cwe_ids(raw.get("weaknesses", []))

        # CPEs / affected products and version ranges
        affected_cpes, cpe_version_ranges = _extract_cpes_and_versions(raw.get("configurations", []))
        vendors, products = _extract_vendors_products(affected_cpes)

        # References
        all_refs, patch_refs, ref_tags = _extract_references_with_tags(raw.get("references", []))

        # EPSS
        epss_score = 0.0
        epss_percentile = None
        if epss_data:
            epss_score = epss_data.get("probability", 0.0)
            epss_percentile = epss_data.get("percentile")

        # KEV
        in_kev = kev_record is not None

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_base_score": cvss_base_score,
            "cvss_vector": cvss_vector,
            "cvss_version": cvss_version,
            "severity": (severity or "UNKNOWN").upper(),
            "attack_vector": attack_vector,
            "cwe_ids": json.dumps(cwe_ids),
            "published_date": raw.get("published", ""),
            "last_modified_date": raw.get("lastModified", ""),
            "affected_cpes": json.dumps(affected_cpes),
            "cpe_version_ranges": json.dumps(cpe_version_ranges),
            "vendors": json.dumps(vendors),
            "products": json.dumps(products),
            "reference_urls": json.dumps(all_refs),
            "patch_references": json.dumps(patch_refs),
            "reference_tags": json.dumps(ref_tags),
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "in_kev": in_kev,
        }
    except Exception as exc:
        logger.error("Failed to parse %s: %s", cve_id, exc)
        return None

