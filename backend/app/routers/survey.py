"""
survey.py — Survey API endpoints for blinded user evaluation.
"""
from __future__ import annotations

import hashlib
import random
from typing import Optional

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from app.db import get_narratives, get_survey_responses, insert_survey_response, query
from app.schemas import SurveyItem, SurveyResponseInput

router = APIRouter(prefix="/api", tags=["survey"])


@router.get("/survey/items")
async def get_survey_items(
    count: int = Query(10, ge=1, le=50),
    seed: Optional[int] = Query(None),
):
    """
    Get blinded, randomized survey items.
    Each item shows a narrative with a blinded condition label (A/B/C).
    """
    # Get CVEs that have narratives
    rows = await query(
        "SELECT DISTINCT cve_id FROM narratives ORDER BY cve_id LIMIT ?",
        (count,),
    )

    items: list[dict] = []
    condition_map = {"manager": "A", "analyst": "B", "it_admin": "C"}

    for row in rows:
        cve_id = row["cve_id"]
        narratives = await get_narratives(cve_id)
        for n in narratives:
            audience = n.get("audience", "manager")
            condition = condition_map.get(audience, "A")
            item_id = hashlib.md5(f"{cve_id}:{audience}".encode()).hexdigest()[:12]
            items.append({
                "item_id": item_id,
                "cve_id": cve_id,
                "condition": condition,
                "narrative_text": n.get("narrative_text", ""),
            })

    # Randomize order
    rng = random.Random(seed)
    rng.shuffle(items)

    return {"items": items[:count * 3], "total": len(items)}


@router.post("/survey/responses")
async def submit_survey_response(body: SurveyResponseInput):
    """Submit a survey response."""
    row_id = await insert_survey_response({
        "item_id": body.item_id,
        "cve_id": body.cve_id,
        "condition": body.condition,
        "rater_id": body.rater_id,
        "clarity_rating": body.clarity_rating,
        "would_act": body.would_act,
    })
    return {"status": "recorded", "id": row_id}


@router.get("/survey/export.csv")
async def export_survey_csv():
    """Export survey responses as CSV."""
    import csv
    import io

    responses = await get_survey_responses()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "id", "item_id", "cve_id", "condition", "rater_id",
        "clarity_rating", "would_act", "created_at",
    ])
    writer.writeheader()
    for r in responses:
        writer.writerow(r)

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=survey_responses.csv"},
    )


@router.get("/evaluation/summary")
async def evaluation_summary():
    """Get the latest evaluation results."""
    from app.db import get_latest_eval

    baseline = await get_latest_eval("baseline_comparison")
    priority = await get_latest_eval("priority_eval")
    verifier = await get_latest_eval("verifier_validation")
    survey = await get_latest_eval("survey_analysis")

    return {
        "baseline_comparison": baseline["results"] if baseline else {"status": "not yet run"},
        "priority_eval": priority["results"] if priority else {"status": "not yet run"},
        "verifier_validation": verifier["results"] if verifier else {"status": "not yet run"},
        "survey_analysis": survey["results"] if survey else {"status": "not yet run"},
    }
