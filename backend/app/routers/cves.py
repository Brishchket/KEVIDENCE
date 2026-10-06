"""
cves.py — CVE-related API endpoints.
"""
from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app.db import get_cve, get_cves, get_kev, get_narratives, query
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
    metrics = await query(
        """
        SELECT
            COUNT(*) AS total,
            COALESCE(SUM(priority_label = 'CRITICAL'), 0) AS critical,
            COALESCE(SUM(priority_label = 'HIGH'), 0) AS high,
            COALESCE(SUM(priority_label = 'MEDIUM'), 0) AS medium,
            COALESCE(SUM(priority_label = 'LOW'), 0) AS low,
            COALESCE(SUM(in_kev = 1), 0) AS kev_count,
            COALESCE(SUM(cvss_base_score >= 7.0), 0) AS high_cvss_count,
            COALESCE(SUM(epss_score >= 0.05), 0) AS high_epss_count,
            COALESCE(SUM(attack_vector = 'NETWORK' OR cvss_vector LIKE '%AV:N%'), 0)
                AS network_exposed_count,
            COALESCE(AVG(CASE WHEN epss_score > 0 THEN epss_score END), 0.0)
                AS mean_epss,
            COALESCE((
                SELECT AVG(faithfulness_score)
                FROM narratives
                WHERE faithfulness_score > 0
            ), 0.0) AS mean_faith,
            COALESCE((
                SELECT parse_rate
                FROM pipeline_runs
                WHERE status = 'COMPLETE'
                ORDER BY id DESC LIMIT 1
            ), 100.0) AS parse_rate,
            COALESCE(
                (SELECT last_success_at FROM sync_state WHERE source = 'nvd'),
                (SELECT ingested_at FROM cves WHERE ingested_at IS NOT NULL
                 ORDER BY ingested_at DESC LIMIT 1)
            ) AS latest_nvd,
            COALESCE(
                (SELECT last_success_at FROM sync_state WHERE source = 'epss'),
                (SELECT fetched_at FROM epss WHERE fetched_at IS NOT NULL
                 ORDER BY fetched_at DESC LIMIT 1)
            ) AS latest_epss,
            COALESCE(
                (SELECT last_success_at FROM sync_state WHERE source = 'kev'),
                (SELECT date_added FROM kev WHERE date_added IS NOT NULL
                 ORDER BY date_added DESC LIMIT 1)
            ) AS latest_kev
        FROM cves
        """
    )
    stats = metrics[0]
    total = stats["total"] or 0
    critical = stats["critical"] or 0
    high = stats["high"] or 0
    medium = stats["medium"] or 0
    low = stats["low"] or 0
    kev_count = stats["kev_count"] or 0
    high_cvss_count = stats["high_cvss_count"] or 0
    high_epss_count = stats["high_epss_count"] or 0
    network_exposed_count = stats["network_exposed_count"] or 0
    asset_criticality_count = critical + high
    mean_epss = stats["mean_epss"]
    mean_faith = stats["mean_faith"]
    parse_rate = stats["parse_rate"]
    latest_nvd = stats["latest_nvd"]
    latest_epss = stats["latest_epss"]
    latest_kev = stats["latest_kev"]

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
            "nvd": latest_nvd,
            "epss": latest_epss,
            "kev": latest_kev,
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
