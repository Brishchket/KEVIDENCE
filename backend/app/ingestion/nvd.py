"""
nvd.py — NVD REST API v2.0 client with rate-limit backoff and chunked date windows.

Rate limits:
  - Without API key: 5 requests / 30 seconds
  - With API key: 50 requests / 30 seconds
NVD caps date ranges so we chunk into windows.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, AsyncGenerator

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.config import (
    NVD_API_KEY,
    NVD_BASE_URL,
    NVD_DATE_WINDOW_DAYS,
    NVD_RATE_LIMIT_DELAY,
    NVD_RESULTS_PER_PAGE,
)

logger = logging.getLogger(__name__)


class NVDRateLimitError(Exception):
    pass


@retry(
    retry=retry_if_exception_type(NVDRateLimitError),
    stop=stop_after_attempt(6),
    wait=wait_exponential(multiplier=10, min=10, max=120),
)
async def _fetch_page(
    client: httpx.AsyncClient,
    params: dict[str, Any],
) -> dict[str, Any]:
    """Fetch one page from the NVD API with retry on rate limit."""
    resp = await client.get(NVD_BASE_URL, params=params, timeout=60)
    if resp.status_code in (403, 429):
        logger.warning("NVD rate limit hit (HTTP %d) — retrying with backoff", resp.status_code)
        raise NVDRateLimitError(f"Rate limited (HTTP {resp.status_code})")
    resp.raise_for_status()
    return resp.json()


def _chunk_date_range(
    start: datetime, end: datetime, window_days: int = NVD_DATE_WINDOW_DAYS
) -> list[tuple[datetime, datetime]]:
    """Split a date range into chunks of window_days."""
    chunks: list[tuple[datetime, datetime]] = []
    current = start
    while current < end:
        chunk_end = min(current + timedelta(days=window_days), end)
        chunks.append((current, chunk_end))
        current = chunk_end
    return chunks


async def fetch_cves(
    start_date: datetime,
    end_date: datetime,
) -> AsyncGenerator[dict[str, Any], None]:
    """
    Yield raw CVE item dicts for the given date range.
    Handles pagination and chunked date windows.
    """
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    headers: dict[str, str] = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
        logger.info("Using NVD API key for faster rate limit")

    chunks = _chunk_date_range(start_date, end_date)
    logger.info("NVD fetch: %d date chunks covering %s to %s",
                len(chunks), start_date.date(), end_date.date())

    async with httpx.AsyncClient(follow_redirects=True, headers=headers) as client:
        for chunk_idx, (chunk_start, chunk_end) in enumerate(chunks):
            logger.info("NVD chunk %d/%d: %s -> %s",
                        chunk_idx + 1, len(chunks), chunk_start.date(), chunk_end.date())

            start_index = 0
            total_results = None

            while True:
                params: dict[str, Any] = {
                    "pubStartDate": chunk_start.strftime(fmt),
                    "pubEndDate": chunk_end.strftime(fmt),
                    "resultsPerPage": NVD_RESULTS_PER_PAGE,
                    "startIndex": start_index,
                }

                logger.info("NVD fetch: startIndex=%d", start_index)
                data = await _fetch_page(client, params)

                if total_results is None:
                    total_results = data.get("totalResults", 0)
                    logger.info("NVD chunk total results: %d", total_results)

                vulnerabilities = data.get("vulnerabilities", [])
                for item in vulnerabilities:
                    yield item.get("cve", {})

                start_index += len(vulnerabilities)
                if start_index >= total_results or not vulnerabilities:
                    break

                # Respect rate limit between pages
                await asyncio.sleep(NVD_RATE_LIMIT_DELAY)

            # Small pause between chunks
            if chunk_idx < len(chunks) - 1:
                await asyncio.sleep(NVD_RATE_LIMIT_DELAY)
