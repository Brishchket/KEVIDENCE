"""
nvd_client.py — NVD REST API v2.0 client with rate-limit backoff.
Rate limit: 5 requests / 30 seconds (public key-less).
"""
import asyncio
import logging
from datetime import datetime
from typing import Any, AsyncGenerator

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_fixed,
)

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 100
# Public rate limit window
_RATE_LIMIT_DELAY = 6.5  # seconds between requests (~5 req/30 s)


class NVDRateLimitError(Exception):
    pass


@retry(
    retry=retry_if_exception_type(NVDRateLimitError),
    stop=stop_after_attempt(6),
    wait=wait_fixed(35),
)
async def _fetch_page(
    client: httpx.AsyncClient,
    params: dict[str, Any],
) -> dict[str, Any]:
    resp = await client.get(NVD_BASE, params=params, timeout=60)
    if resp.status_code == 403 or resp.status_code == 429:
        logger.warning("NVD rate limit hit — retrying after 35 s")
        raise NVDRateLimitError("Rate limited")
    resp.raise_for_status()
    return resp.json()


async def fetch_cves(
    start_date: datetime,
    end_date: datetime,
) -> AsyncGenerator[dict[str, Any], None]:
    """Yield raw CVE item dicts for the given date range."""
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params_base: dict[str, Any] = {
        "pubStartDate": start_date.strftime(fmt),
        "pubEndDate": end_date.strftime(fmt),
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex": 0,
    }

    async with httpx.AsyncClient(follow_redirects=True) as client:
        start_index = 0
        total_results = None

        while True:
            params = {**params_base, "startIndex": start_index}
            logger.info("NVD fetch: startIndex=%d", start_index)
            data = await _fetch_page(client, params)

            if total_results is None:
                total_results = data.get("totalResults", 0)
                logger.info("NVD total results: %d", total_results)

            vulnerabilities = data.get("vulnerabilities", [])
            for item in vulnerabilities:
                yield item.get("cve", {})

            start_index += len(vulnerabilities)
            if start_index >= total_results or not vulnerabilities:
                break

            # Respect rate limit between pages
            await asyncio.sleep(_RATE_LIMIT_DELAY)
