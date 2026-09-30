"""
config.py — Centralised configuration loaded from environment / .env file.

All weights, thresholds and provider settings live here so they're
easy to tune without touching code.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv

# Load .env from project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_dotenv_path = _PROJECT_ROOT / ".env"
if _dotenv_path.exists():
    load_dotenv(_dotenv_path)

# ── Paths ────────────────────────────────────────────────────────────────────

DB_PATH: str = os.getenv("PHANTOMPATCH_DB", str(Path(__file__).resolve().parent.parent / "phantompatch.db"))

# ── NVD ──────────────────────────────────────────────────────────────────────

NVD_API_KEY: str | None = os.getenv("NVD_API_KEY") or None
NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE: int = 100
# With API key: 50 req/30s → ~0.6s delay; without: 5 req/30s → ~6.5s delay
NVD_RATE_LIMIT_DELAY: float = 0.7 if NVD_API_KEY else 6.5
NVD_DATE_WINDOW_DAYS: int = 120  # NVD caps date range per request

# ── EPSS ─────────────────────────────────────────────────────────────────────

EPSS_BASE_URL: str = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE: int = 100

# ── KEV ──────────────────────────────────────────────────────────────────────

KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ── Scoring ──────────────────────────────────────────────────────────────────

CVSS_WEIGHT: float = float(os.getenv("CVSS_WEIGHT", "0.3"))
EPSS_WEIGHT: float = float(os.getenv("EPSS_WEIGHT", "0.3"))
KEV_WEIGHT: float = float(os.getenv("KEV_WEIGHT", "0.4"))
CVSS_MAX: float = 10.0

THRESHOLD_CRITICAL: float = float(os.getenv("THRESHOLD_CRITICAL", "0.75"))
THRESHOLD_HIGH: float = float(os.getenv("THRESHOLD_HIGH", "0.50"))
THRESHOLD_MEDIUM: float = float(os.getenv("THRESHOLD_MEDIUM", "0.25"))

# ── LLM ──────────────────────────────────────────────────────────────────────

LLM_PROVIDER: Literal["gemini", "openai", "anthropic", "mock"] = os.getenv("LLM_PROVIDER", "mock")  # type: ignore[assignment]
LLM_TEMPERATURE: float = 0.2

GEMINI_API_KEY: str | None = os.getenv("GEMINI_API_KEY") or None
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

OPENAI_API_KEY: str | None = os.getenv("OPENAI_API_KEY") or None
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

ANTHROPIC_API_KEY: str | None = os.getenv("ANTHROPIC_API_KEY") or None
ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

# ── Verifier ─────────────────────────────────────────────────────────────────

SIMILARITY_THRESHOLD: float = float(os.getenv("SIMILARITY_THRESHOLD", "0.60"))
RETRY_BELOW: float = float(os.getenv("RETRY_BELOW", "0.95"))
MAX_RETRIES: int = int(os.getenv("MAX_RETRIES", "2"))
CONFIDENCE_HIGH: float = float(os.getenv("CONFIDENCE_HIGH", "0.95"))
CONFIDENCE_MEDIUM: float = float(os.getenv("CONFIDENCE_MEDIUM", "0.80"))
STRICT_FACTS: bool = os.getenv("STRICT_FACTS", "true").lower() in ("true", "1", "yes")
EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"

# ── Recommended actions by priority ──────────────────────────────────────────

RECOMMENDED_ACTIONS: dict[str, str] = {
    "CRITICAL": "Patch immediately or apply vendor-recommended mitigations within 24 hours.",
    "HIGH": "Prioritize patching within the next 7 days; apply mitigations if a patch is not yet available.",
    "MEDIUM": "Schedule patching within the next 30 days as part of regular maintenance.",
    "LOW": "Monitor for changes; patch during the next scheduled maintenance window.",
}
