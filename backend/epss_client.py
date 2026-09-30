"""
epss_client.py — Batch-fetch EPSS scores from FIRST.org API.
Endpoint: https://api.first.org/data/v1/epss?cve=CVE-XXXX,...
"""
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

EPSS_BASE = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100  # API supports up to 100 CVEs per request


async def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """
    Return a dict mapping CVE-ID -> EPSS score (0.0–1.0).
    Missing CVEs are not included in the result.
    """
    if not cve_ids:
        return {}

    scores: dict[str, float] = {}

    async with httpx.AsyncClient(follow_redirects=True, timeout=60) as client:
        for i in range(0, len(cve_ids), BATCH_SIZE):
            batch = cve_ids[i : i + BATCH_SIZE]
            params = {"cve": ",".join(batch)}
            logger.info("EPSS fetch batch %d/%d", i // BATCH_SIZE + 1, -(-len(cve_ids) // BATCH_SIZE))

            try:
                resp = await client.get(EPSS_BASE, params=params)
                resp.raise_for_status()
                data: dict[str, Any] = resp.json()
                for item in data.get("data", []):
                    cve_id = item.get("cve", "")
                    epss = float(item.get("epss", 0.0))
                    if cve_id:
                        scores[cve_id] = epss
            except httpx.HTTPError as exc:
                logger.error("EPSS fetch error: %s", exc)

    return scores
