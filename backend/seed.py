"""
seed.py — Bootstrap the database with the last 7 days of NVD CVEs.
Run once: python seed.py
"""
import asyncio
import logging
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, ".")

from pipeline import run_pipeline
from storage import init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger(__name__)


async def main():
    await init_db()
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=7)
    logger.info("Seeding database: %s -> %s", start_date.date(), end_date.date())
    result = await run_pipeline(start_date, end_date)
    logger.info("Seed complete: %s", result)


if __name__ == "__main__":
    asyncio.run(main())
