"""
main.py — FastAPI application for PhantomPatch.

Mounts all routers, configures CORS, seeds demo data on startup.
"""
from __future__ import annotations

import json
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.db import has_data, init_db
from app.routers import cves, ingest, survey

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


async def _seed_demo_data() -> None:
    """Seed demo data from fixtures if DB is empty so UI is never blank."""
    fixtures_path = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "demo_cves.json"
    if not fixtures_path.exists():
        logger.info("No demo fixtures found at %s, skipping seed", fixtures_path)
        return

    logger.info("Seeding demo data from %s", fixtures_path)
    from app.db import upsert_cve
    from app.scoring.scorer import prioritize

    with open(fixtures_path) as f:
        demo_cves = json.load(f)

    for cve_data in demo_cves:
        scored = prioritize(cve_data)
        await upsert_cve(scored)

    logger.info("Seeded %d demo CVEs", len(demo_cves))


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    if not await has_data():
        await _seed_demo_data()
    yield


app = FastAPI(
    title="PhantomPatch API",
    description="Evidence-Grounded Vulnerability Risk Narrative Engine",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routers
app.include_router(cves.router)
app.include_router(ingest.router)
app.include_router(survey.router)


@app.get("/health")
async def health():
    return {"status": "ok"}
