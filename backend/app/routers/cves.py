"""
cves.py — CVE-related API endpoints.
"""
from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app.db import get_cve, get_cves, get_kev, get_narratives, scalar
from app.evidence.builder import build_evidence
from app.narrative.generator import generate_narrative, get_llm_client
from app.schemas import Evidence

router = APIRouter(prefix="/api", tags=["cves"])


@router.get("/cves")
async def list_cves(
    priority: Optional[str] = Query(None, description="Filter by priority label"),
    in_kev: Optional[bool] = Query(None, description="Filter by KEV status"),
    min_epss: Optional[float] = Query(None, description="Minimum EPSS score"),
    search: Optional[str] = Query(None, description="Search CVE ID or description"),
    sort: str = Query("priority_score", description="Sort field"),
    order: str = Query("desc", description="Sort order: asc or desc"),
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    rows, total = await get_cves(
        priority=priority,
        in_kev=in_kev,
        min_epss=min_epss,
        search=search,
        sort_by=sort,
        sort_dir=order,
        limit=limit,
        offset=offset,
    )
    return {"total": total, "offset": offset, "limit": limit, "items": rows}


@router.get("/cves/{cve_id}")
async def get_cve_detail(cve_id: str):
    evidence = await build_evidence(cve_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    return evidence.model_dump()


@router.post("/cves/{cve_id}/narratives")
async def create_narrative(
    cve_id: str,
    audience: str = Query("manager", regex="^(manager|analyst|it_admin)$"),
    regenerate: bool = Query(False),
    provider: Optional[str] = Query(None),
):
    evidence = await build_evidence(cve_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    llm_client = get_llm_client(provider)
    record = await generate_narrative(evidence, audience, llm_client, regenerate=regenerate)
    return record.model_dump()


@router.get("/cves/{cve_id}/narratives")
async def get_cve_narratives(cve_id: str):
    narratives = await get_narratives(cve_id)
    if not narratives:
        raise HTTPException(status_code=404, detail=f"No narratives for {cve_id}")
    return {"cve_id": cve_id, "narratives": narratives}


@router.get("/stats")
async def get_stats():
    total = await scalar("SELECT COUNT(*) FROM cves")
    critical = await scalar("SELECT COUNT(*) FROM cves WHERE priority_label='CRITICAL'")
    high = await scalar("SELECT COUNT(*) FROM cves WHERE priority_label='HIGH'")
    medium = await scalar("SELECT COUNT(*) FROM cves WHERE priority_label='MEDIUM'")
    low = await scalar("SELECT COUNT(*) FROM cves WHERE priority_label='LOW'")
    kev_count = await scalar("SELECT COUNT(*) FROM cves WHERE in_kev = 1")
    mean_epss = await scalar("SELECT AVG(epss_score) FROM cves WHERE epss_score > 0", default=0.0)
    mean_faith = await scalar(
        "SELECT AVG(faithfulness_score) FROM narratives WHERE faithfulness_score > 0",
        default=0.0,
    )

    # Parse rate from last pipeline run
    from app.db import query
    runs = await query(
        "SELECT parse_rate FROM pipeline_runs WHERE status='COMPLETE' ORDER BY id DESC LIMIT 1"
    )
    parse_rate = runs[0]["parse_rate"] if runs else 0.0

    return {
        "total_cves": total,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "kev_count": kev_count,
        "mean_epss": round(float(mean_epss), 4),
        "mean_faithfulness": round(float(mean_faith), 4),
        "parse_rate": parse_rate,
    }


@router.get("/compare/{cve_id}")
async def compare_narratives(cve_id: str):
    """Compare raw CVE text, generic LLM baseline, and PhantomPatch narrative."""
    cve = await get_cve(cve_id)
    if cve is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    # Get PhantomPatch narrative
    narratives = await get_narratives(cve_id)
    manager_narrative = next(
        (n for n in narratives if n.get("audience") == "manager"), None
    )

    result = {
        "cve_id": cve_id,
        "raw_description": cve.get("description"),
        "generic_llm_narrative": None,
        "phantompatch_narrative": manager_narrative.get("narrative_text") if manager_narrative else None,
        "raw_flesch": None,
        "generic_flesch": None,
        "phantompatch_flesch": None,
        "raw_unsupported_rate": None,
        "generic_unsupported_rate": None,
        "phantompatch_unsupported_rate": None,
    }

    # Compute Flesch scores
    try:
        import textstat
        if result["raw_description"]:
            result["raw_flesch"] = round(textstat.flesch_reading_ease(result["raw_description"]), 1)
        if result["phantompatch_narrative"]:
            result["phantompatch_flesch"] = round(textstat.flesch_reading_ease(result["phantompatch_narrative"]), 1)
    except ImportError:
        pass

    # Get unsupported rate from verification
    if manager_narrative and manager_narrative.get("verification"):
        v = manager_narrative["verification"]
        total = v.get("total_count", 0)
        supported = v.get("supported_count", 0)
        if total > 0:
            result["phantompatch_unsupported_rate"] = round((total - supported) / total, 4)

    return result
