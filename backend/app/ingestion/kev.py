"""
kev.py — Download CISA KEV catalog and return full records.
Catalog URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
from __future__ import annotations

import logging
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from app.config import KEV_URL

logger = logging.getLogger(__name__)


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=2, max=30))
async def _download_kev(client: httpx.AsyncClient) -> dict[str, Any]:
    resp = await client.get(KEV_URL, timeout=60)
    resp.raise_for_status()
    return resp.json()


async def fetch_kev_catalog() -> dict[str, dict[str, Any]]:
    """
    Download the CISA KEV catalog and return a dict mapping CVE-ID -> full record.
    Each record has: cve_id, vendor_project, product, vulnerability_name,
    date_added, due_date, required_action, known_ransomware_use, short_description.
    """
    async with httpx.AsyncClient(follow_redirects=True, timeout=60) as client:
        try:
            data = await _download_kev(client)
            vulnerabilities = data.get("vulnerabilities", [])
            catalog: dict[str, dict[str, Any]] = {}
            for v in vulnerabilities:
                cve_id = v.get("cveID", "")
                if cve_id:
                    catalog[cve_id] = {
                        "cve_id": cve_id,
                        "vendor_project": v.get("vendorProject"),
                        "product": v.get("product"),
                        "vulnerability_name": v.get("vulnerabilityName"),
                        "date_added": v.get("dateAdded"),
                        "due_date": v.get("dueDate"),
                        "required_action": v.get("requiredAction"),
                        "known_ransomware_use": v.get("knownRansomwareCampaignUse"),
                        "short_description": v.get("shortDescription"),
                    }
            logger.info("KEV catalog fetched: %d entries", len(catalog))
            return catalog
        except httpx.HTTPError as exc:
            logger.error("KEV fetch error: %s", exc)
            return {}


async def fetch_kev_ids() -> set[str]:
    """Convenience: just return the set of CVE IDs in KEV."""
    catalog = await fetch_kev_catalog()
    return set(catalog.keys())
