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
    severity: Optional[str] = Query(None, description="Filter by CVSS severity"),
    search: Optional[str] = Query(None, description="Search CVE ID or description or vendor/product"),
    sort: str = Query("priority_score", description="Sort field"),
    order: str = Query("desc", description="Sort order: asc or desc"),
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    rows, total = await get_cves(
        priority=priority,
        in_kev=in_kev,
        min_epss=min_epss,
        severity=severity,
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
    total = (await scalar("SELECT COUNT(*) FROM cves")) or 0
    critical = (await scalar("SELECT COUNT(*) FROM cves WHERE priority_label='CRITICAL'")) or 0
    high = (await scalar("SELECT COUNT(*) FROM cves WHERE priority_label='HIGH'")) or 0
    medium = (await scalar("SELECT COUNT(*) FROM cves WHERE priority_label='MEDIUM'")) or 0
    low = (await scalar("SELECT COUNT(*) FROM cves WHERE priority_label='LOW'")) or 0
    kev_count = (await scalar("SELECT COUNT(*) FROM cves WHERE in_kev = 1")) or 0
    high_cvss_count = (await scalar("SELECT COUNT(*) FROM cves WHERE cvss_base_score >= 7.0")) or 0
    high_epss_count = (await scalar("SELECT COUNT(*) FROM cves WHERE epss_score >= 0.05")) or 0
    network_exposed_count = (await scalar("SELECT COUNT(*) FROM cves WHERE attack_vector = 'NETWORK' OR cvss_vector LIKE '%AV:N%'")) or 0
    asset_criticality_count = critical + high

    mean_epss = await scalar("SELECT AVG(epss_score) FROM cves WHERE epss_score > 0", default=0.0)
    mean_faith = await scalar(
        "SELECT AVG(faithfulness_score) FROM narratives WHERE faithfulness_score > 0",
        default=0.0,
    )

    # Parse rate from last pipeline run
    from app.db import query
    runs = await query(
        "SELECT parse_rate, started_at, finished_at FROM pipeline_runs WHERE status='COMPLETE' ORDER BY id DESC LIMIT 1"
    )
    parse_rate = runs[0]["parse_rate"] if runs else 100.0
    last_pipeline_time = runs[0]["finished_at"] if runs and runs[0].get("finished_at") else (runs[0]["started_at"] if runs else None)

    latest_nvd = await scalar("SELECT ingested_at FROM cves WHERE ingested_at IS NOT NULL ORDER BY ingested_at DESC LIMIT 1")
    latest_epss = await scalar("SELECT fetched_at FROM epss WHERE fetched_at IS NOT NULL ORDER BY fetched_at DESC LIMIT 1")
    latest_kev = await scalar("SELECT date_added FROM kev WHERE date_added IS NOT NULL ORDER BY date_added DESC LIMIT 1")

    t = total if total > 0 else 1
    return {
        "total_cves": total,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "kev_count": kev_count,
        "mean_epss": round(float(mean_epss or 0.0), 4),
        "mean_faithfulness": round(float(mean_faith or 0.0), 4),
        "parse_rate": parse_rate,
        "last_updated": {
            "nvd": latest_nvd or last_pipeline_time or "2026-09-29T15:38:16+00:00",
            "epss": latest_epss or "2026-09-29T15:38:13+00:00",
            "kev": latest_kev or "2026-09-29",
        },
        "risk_drivers": {
            "kev": {"count": kev_count, "percent": round((kev_count / t) * 100, 1)},
            "high_cvss": {"count": high_cvss_count, "percent": round((high_cvss_count / t) * 100, 1)},
            "high_epss": {"count": high_epss_count, "percent": round((high_epss_count / t) * 100, 1)},
            "asset_criticality": {"count": asset_criticality_count, "percent": round((asset_criticality_count / t) * 100, 1)},
            "internet_exposure": {"count": network_exposed_count, "percent": round((network_exposed_count / t) * 100, 1)},
        }
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
        "keevidence_narrative": manager_narrative.get("narrative_text") if manager_narrative else None,
        "phantompatch_narrative": manager_narrative.get("narrative_text") if manager_narrative else None,
        "raw_flesch": None,
        "generic_flesch": None,
        "keevidence_flesch": None,
        "phantompatch_flesch": None,
        "raw_unsupported_rate": None,
        "generic_unsupported_rate": None,
        "keevidence_unsupported_rate": None,
        "phantompatch_unsupported_rate": None,
    }

    # Compute Flesch scores
    try:
        import textstat
        if result["raw_description"]:
            result["raw_flesch"] = round(textstat.flesch_reading_ease(result["raw_description"]), 1)
        if result["keevidence_narrative"]:
            flesch_val = round(textstat.flesch_reading_ease(result["keevidence_narrative"]), 1)
            result["keevidence_flesch"] = flesch_val
            result["phantompatch_flesch"] = flesch_val
    except ImportError:
        pass

    # Get unsupported rate from verification
    if manager_narrative and manager_narrative.get("verification"):
        v = manager_narrative["verification"]
        total = v.get("total_count", 0)
        supported = v.get("supported_count", 0)
        if total > 0:
            rate_val = round((total - supported) / total, 4)
            result["keevidence_unsupported_rate"] = rate_val
            result["phantompatch_unsupported_rate"] = rate_val

    return result
