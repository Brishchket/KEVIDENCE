"""
builder.py — Build an Evidence object from a DB record + KEV/EPSS tables.

The Evidence model is the single source of truth passed to the LLM and verifier.
reasons[] and recommended_action are produced by code from templates.
Null fields stay null. Data is never invented.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

from app.config import RECOMMENDED_ACTIONS
from app.db import get_cve, get_epss, get_kev
from app.schemas import (
    AffectedDetail,
    CVSSDetail,
    EPSSDetail,
    Evidence,
    KEVDetail,
    PriorityBreakdown,
    PriorityDetail,
)

logger = logging.getLogger(__name__)


def _safe_json_loads(val: Any, default: Any = None) -> Any:
    """Safely parse JSON strings, returning default on failure."""
    if val is None:
        return default
    if isinstance(val, (list, dict)):
        return val
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return default


def _build_recommended_action(
    priority_label: str,
    affected: AffectedDetail,
    kev: KEVDetail,
    patch_references: list[str],
) -> str:
    """Add CVE-specific remediation context to the priority-based action."""
    action_parts = [
        RECOMMENDED_ACTIONS.get(priority_label, RECOMMENDED_ACTIONS["LOW"]).rstrip().rstrip(".")
    ]

    if kev.in_kev and kev.required_action:
        action_parts.append(f"CISA KEV requires {kev.required_action.rstrip().rstrip('.')}")
        if kev.due_date:
            action_parts.append(f"complete remediation by {kev.due_date}")
    elif kev.in_kev and kev.due_date:
        action_parts.append(f"CISA KEV remediation is due by {kev.due_date}")

    if patch_references:
        product = f" for {affected.product}" if affected.product else ""
        action_parts.append(f"review vendor remediation guidance{product}: {patch_references[0]}")
    elif affected.product:
        target = affected.product
        if affected.vendor:
            target = f"{affected.vendor} {target}"
        action_parts.append(
            f"confirm whether {target} is deployed and, if affected, follow vendor guidance"
        )

    return "; ".join(action_parts) + "."


async def build_evidence(cve_id: str) -> Optional[Evidence]:
    """
    Build an Evidence object for the given CVE ID by combining
    data from the cves, kev, and epss tables.
    Returns None if the CVE is not found.
    """
    cve_row = await get_cve(cve_id)
    if not cve_row:
        logger.warning("CVE %s not found in database", cve_id)
        return None

    kev_row = await get_kev(cve_id)
    epss_row = await get_epss(cve_id)

    # Build sub-models
    cvss = CVSSDetail(
        score=cve_row.get("cvss_base_score"),
        severity=cve_row.get("severity") if cve_row.get("severity") != "UNKNOWN" else None,
        vector=cve_row.get("cvss_vector"),
        attack_vector=cve_row.get("attack_vector"),
    )

    epss = EPSSDetail(
        probability=epss_row["probability"] if epss_row else cve_row.get("epss_score"),
        percentile=epss_row["percentile"] if epss_row else cve_row.get("epss_percentile"),
    )

    kev = KEVDetail(
        in_kev=bool(cve_row.get("in_kev")),
        date_added=kev_row["date_added"] if kev_row else None,
        due_date=kev_row["due_date"] if kev_row else None,
        required_action=kev_row["required_action"] if kev_row else None,
        known_ransomware_use=kev_row["known_ransomware_use"] if kev_row else None,
    )

    # Affected vendor/product — take the first of each
    vendors = cve_row.get("vendors", [])
    products = cve_row.get("products", [])
    if isinstance(vendors, str):
        vendors = _safe_json_loads(vendors, [])
    if isinstance(products, str):
        products = _safe_json_loads(products, [])

    affected = AffectedDetail(
        vendor=vendors[0] if vendors else None,
        product=products[0] if products else None,
    )

    # Priority
    breakdown_raw = cve_row.get("priority_breakdown", {})
    if isinstance(breakdown_raw, str):
        breakdown_raw = _safe_json_loads(breakdown_raw, {})

    priority = PriorityDetail(
        score=cve_row.get("priority_score", 0.0),
        label=cve_row.get("priority_label", "LOW"),
        breakdown=PriorityBreakdown(
            cvss_contribution=breakdown_raw.get("cvss_contribution", 0.0),
            epss_contribution=breakdown_raw.get("epss_contribution", 0.0),
            kev_contribution=breakdown_raw.get("kev_contribution", 0.0),
        ),
        missing_signals=cve_row.get("missing_signals", []),
    )

    # CWE
    cwe_ids = cve_row.get("cwe_ids", [])
    if isinstance(cwe_ids, str):
        cwe_ids = _safe_json_loads(cwe_ids, [])

    # Reasons (already computed by scorer)
    reasons = cve_row.get("reasons", [])
    if isinstance(reasons, str):
        reasons = _safe_json_loads(reasons, [])

    # Recommended action with CVE-specific remediation context
    priority_label = cve_row.get("priority_label", "LOW")

    # Patch references
    patch_refs = cve_row.get("patch_references", [])
    if isinstance(patch_refs, str):
        patch_refs = _safe_json_loads(patch_refs, [])

    recommended_action = _build_recommended_action(
        priority_label, affected, kev, patch_refs
    )

    return Evidence(
        cve_id=cve_id,
        description=cve_row.get("description"),
        cvss=cvss,
        cwe=cwe_ids,
        epss=epss,
        kev=kev,
        affected=affected,
        priority=priority,
        reasons=reasons,
        recommended_action=recommended_action,
        patch_references=patch_refs,
        published_date=cve_row.get("published_date"),
        modified_date=cve_row.get("last_modified_date"),
    )


def build_evidence_from_record(cve_row: dict, kev_row: dict | None = None,
                                epss_row: dict | None = None) -> Evidence:
    """
    Build Evidence synchronously from pre-fetched records.
    Useful for batch operations and tests.
    """
    cvss = CVSSDetail(
        score=cve_row.get("cvss_base_score"),
        severity=cve_row.get("severity") if cve_row.get("severity") != "UNKNOWN" else None,
        vector=cve_row.get("cvss_vector"),
        attack_vector=cve_row.get("attack_vector"),
    )

    epss_prob = epss_row["probability"] if epss_row else cve_row.get("epss_score", 0.0)
    epss_pctl = epss_row["percentile"] if epss_row else cve_row.get("epss_percentile")
    epss = EPSSDetail(probability=epss_prob, percentile=epss_pctl)

    kev = KEVDetail(
        in_kev=bool(cve_row.get("in_kev")),
        date_added=kev_row["date_added"] if kev_row else None,
        due_date=kev_row["due_date"] if kev_row else None,
        required_action=kev_row["required_action"] if kev_row else None,
        known_ransomware_use=kev_row["known_ransomware_use"] if kev_row else None,
    )

    vendors = cve_row.get("vendors", [])
    products = cve_row.get("products", [])
    if isinstance(vendors, str):
        vendors = _safe_json_loads(vendors, [])
    if isinstance(products, str):
        products = _safe_json_loads(products, [])

    affected = AffectedDetail(
        vendor=vendors[0] if vendors else None,
        product=products[0] if products else None,
    )

    breakdown_raw = cve_row.get("priority_breakdown", {})
    if isinstance(breakdown_raw, str):
        breakdown_raw = _safe_json_loads(breakdown_raw, {})

    priority = PriorityDetail(
        score=cve_row.get("priority_score", 0.0),
        label=cve_row.get("priority_label", "LOW"),
        breakdown=PriorityBreakdown(
            cvss_contribution=breakdown_raw.get("cvss_contribution", 0.0),
            epss_contribution=breakdown_raw.get("epss_contribution", 0.0),
            kev_contribution=breakdown_raw.get("kev_contribution", 0.0),
        ),
        missing_signals=cve_row.get("missing_signals", []) if isinstance(cve_row.get("missing_signals"), list) else _safe_json_loads(cve_row.get("missing_signals"), []),
    )

    cwe_ids = cve_row.get("cwe_ids", [])
    if isinstance(cwe_ids, str):
        cwe_ids = _safe_json_loads(cwe_ids, [])

    reasons = cve_row.get("reasons", [])
    if isinstance(reasons, str):
        reasons = _safe_json_loads(reasons, [])

    priority_label = cve_row.get("priority_label", "LOW")

    patch_refs = cve_row.get("patch_references", [])
    if isinstance(patch_refs, str):
        patch_refs = _safe_json_loads(patch_refs, [])

    recommended_action = _build_recommended_action(
        priority_label, affected, kev, patch_refs
    )

    return Evidence(
        cve_id=cve_row.get("cve_id", ""),
        description=cve_row.get("description"),
        cvss=cvss,
        cwe=cwe_ids,
        epss=epss,
        kev=kev,
        affected=affected,
        priority=priority,
        reasons=reasons,
        recommended_action=recommended_action,
        patch_references=patch_refs,
        published_date=cve_row.get("published_date"),
        modified_date=cve_row.get("last_modified_date"),
    )
