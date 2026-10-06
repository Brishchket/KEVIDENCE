"""
reports.py — API endpoints for vulnerability report generation and PDF downloads.

Endpoints:
  GET /api/cves/{cve_id}/report.pdf     — Download PDF advisory
  GET /api/cves/{cve_id}/report         — JSON structured report preview
  GET /api/reports/summary.pdf?top=10   — Top-N portfolio summary PDF
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Response

from app.db import get_cve
from app.reporting.pdf_renderer import render_portfolio_summary_pdf
from app.reporting.report_generator import (
    generate_vulnerability_report,
    get_or_create_report_pdf,
    warm_top_report_pdf_cache,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/cves/{cve_id}/report")
async def get_cve_report_json(
    cve_id: str,
    regenerate: bool = Query(False, description="Force re-generation and cache refresh"),
    provider: Optional[str] = Query(None, description="LLM provider override (e.g. gemini, mock)"),
):
    """Retrieve structured JSON vulnerability report for on-page preview."""
    cve = await get_cve(cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail=f"Vulnerability {cve_id} not found")

    report = await generate_vulnerability_report(
        cve_id=cve_id,
        provider=provider,
        regenerate=regenerate,
    )
    if not report:
        raise HTTPException(status_code=500, detail="Failed to compile vulnerability report")

    return report


@router.get("/cves/{cve_id}/report.pdf")
async def download_cve_report_pdf(
    cve_id: str,
    regenerate: bool = Query(False, description="Force re-generation and cache refresh"),
    provider: Optional[str] = Query(None, description="LLM provider override"),
):
    """Download publication-quality PDF vulnerability advisory."""
    cve = await get_cve(cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail=f"Vulnerability {cve_id} not found")

    try:
        _, pdf_bytes = await get_or_create_report_pdf(
            cve_id=cve_id,
            provider=provider,
            regenerate=regenerate,
        )
    except LookupError:
        raise HTTPException(status_code=404, detail=f"Vulnerability {cve_id} not found")
    except Exception as exc:
        logger.exception("Failed to compile or retrieve PDF for %s", cve_id)
        raise HTTPException(status_code=500, detail=f"PDF report error: {exc}")

    filename = f"kevidence-{cve_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )


@router.get("/reports/summary.pdf")
async def download_portfolio_summary_pdf(
    top: int = Query(10, ge=1, le=50, description="Number of top-priority CVEs to include in portfolio"),
    provider: Optional[str] = Query(None, description="LLM provider override"),
):
    """Download executive portfolio summary PDF covering top-N prioritised vulnerabilities."""
    try:
        reports = await warm_top_report_pdf_cache(
            top_n=top,
            buffer=10,
            provider=provider,
        )
    except Exception as exc:
        logger.exception("Failed to warm top-CVE report PDFs")
        raise HTTPException(status_code=500, detail=f"Failed to compile portfolio reports: {exc}")

    if not reports:
        raise HTTPException(status_code=404, detail="No vulnerability records found in database")

    try:
        pdf_bytes = render_portfolio_summary_pdf(reports)
    except Exception as exc:
        logger.error("Failed to render portfolio PDF: %s", exc)
        raise HTTPException(status_code=500, detail=f"Portfolio PDF rendering error: {exc}")

    filename = f"kevidence-portfolio-top{top}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )
