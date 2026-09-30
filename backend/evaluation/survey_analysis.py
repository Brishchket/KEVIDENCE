"""
survey_analysis.py — Analyze survey responses.

Computes mean and SD of Likert ratings per condition.
Checks for >= 10 raters and mean >= 4.0 targets.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
from pathlib import Path
from typing import Any

from app.config import LLM_PROVIDER

logger = logging.getLogger(__name__)


async def run_survey_analysis() -> dict[str, Any]:
    """Analyze survey responses from the database."""
    from app.db import get_survey_responses, init_db

    await init_db()

    responses = await get_survey_responses()

    if not responses:
        return {
            "status": "SKIPPED: needs survey responses",
            "note": "Recruit >= 10 raters to complete the survey, then re-run",
            "provider": LLM_PROVIDER,
        }

    provider = LLM_PROVIDER
    is_mock = provider == "mock"

    # Group by condition
    conditions: dict[str, list[int]] = {}
    rater_ids: set[str] = set()

    for r in responses:
        condition = r.get("condition", "unknown")
        rating = r.get("clarity_rating", 0)
        rater_id = r.get("rater_id", "")

        if condition not in conditions:
            conditions[condition] = []
        conditions[condition].append(rating)
        rater_ids.add(rater_id)

    n_raters = len(rater_ids)

    # Compute stats per condition
    condition_stats: dict[str, dict] = {}
    for cond, ratings in conditions.items():
        n = len(ratings)
        mean = sum(ratings) / n if n > 0 else 0
        variance = sum((r - mean) ** 2 for r in ratings) / n if n > 0 else 0
        sd = math.sqrt(variance)
        condition_stats[cond] = {
            "n_responses": n,
            "mean": round(mean, 2),
            "sd": round(sd, 2),
        }

    # Would-act analysis
    would_act_count = sum(1 for r in responses if r.get("would_act") == 1)
    would_not_act_count = sum(1 for r in responses if r.get("would_act") == 0)
    total_act_responses = would_act_count + would_not_act_count

    # Overall
    all_ratings = [r.get("clarity_rating", 0) for r in responses]
    overall_mean = sum(all_ratings) / len(all_ratings) if all_ratings else 0

    return {
        "provider": provider,
        "note": "PIPELINE TEST ONLY, not reportable" if is_mock else "",
        "n_raters": n_raters,
        "n_responses": len(responses),
        "conditions": condition_stats,
        "overall_mean_clarity": round(overall_mean, 2),
        "would_act_rate": round(would_act_count / total_act_responses, 4) if total_act_responses > 0 else None,
        "targets": {
            "min_raters": 10,
            "min_mean_clarity": 4.0,
        },
        "pass_fail": {
            "raters": "PASS" if n_raters >= 10 else f"PENDING ({n_raters}/10 raters)",
            "mean_clarity": "PASS" if overall_mean >= 4.0 else f"PENDING (mean={overall_mean:.2f})",
        },
    }


def main():
    results = asyncio.run(run_survey_analysis())
    output_dir = Path(__file__).resolve().parent / "results"
    output_dir.mkdir(exist_ok=True)
    with open(output_dir / "survey_analysis.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
