"""
kev_client.py — Download CISA KEV catalog and return a set of CVE IDs.
Catalog URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
import logging

import httpx

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def fetch_kev_ids() -> set[str]:
    """
    Download the CISA KEV catalog and return a set of CVE IDs present in it.
    """
    async with httpx.AsyncClient(follow_redirects=True, timeout=60) as client:
        try:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            kev_ids = {v.get("cveID", "") for v in vulnerabilities if v.get("cveID")}
            logger.info("KEV catalog fetched: %d entries", len(kev_ids))
            return kev_ids
        except httpx.HTTPError as exc:
            logger.error("KEV fetch error: %s", exc)
            return set()
