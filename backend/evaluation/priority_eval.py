"""
priority_eval.py — KEV recall@N for different ranking strategies.

Compares:
  1. PhantomPatch composite score (CVSS + EPSS + KEV)
  2. CVSS-only ranking
  3. EPSS-only ranking
  4. KEV-ablated ranking (CVSS + EPSS only, renormalized)

Note: Because KEV is 40% of the PhantomPatch score, KEV recall on the
full score is partly circular. The KEV-ablated ranking addresses this.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from app.config import CVSS_MAX, CVSS_WEIGHT, EPSS_WEIGHT, KEV_WEIGHT, LLM_PROVIDER

logger = logging.getLogger(__name__)


def _recall_at_n(ranked_ids: list[str], kev_ids: set[str], n: int) -> float:
    """Compute recall@N: fraction of KEV CVEs in the top N of the ranked list."""
    if not kev_ids or n <= 0:
        return 0.0
    top_n = set(ranked_ids[:n])
    hits = top_n & kev_ids
    return round(len(hits) / len(kev_ids), 4) if kev_ids else 0.0


async def run_priority_eval() -> dict[str, Any]:
    """Run the priority ranking evaluation."""
    from app.db import get_cves, init_db

    await init_db()

    # Get all CVEs
    cves, total = await get_cves(sort_by="priority_score", sort_dir="DESC",
                                  limit=10000, offset=0)
    if not cves:
        return {"status": "no data"}

    provider = LLM_PROVIDER
    is_mock = provider == "mock"

    # Identify KEV CVEs
    kev_ids = {c["cve_id"] for c in cves if c.get("in_kev")}

    # Ranking 1: PhantomPatch composite score (already sorted)
    pp_ranked = [c["cve_id"] for c in cves]

    # Ranking 2: CVSS-only
    cvss_sorted = sorted(cves, key=lambda c: c.get("cvss_base_score") or 0, reverse=True)
    cvss_ranked = [c["cve_id"] for c in cvss_sorted]

    # Ranking 3: EPSS-only
    epss_sorted = sorted(cves, key=lambda c: c.get("epss_score") or 0, reverse=True)
    epss_ranked = [c["cve_id"] for c in epss_sorted]

    # Ranking 4: KEV-ablated (CVSS + EPSS only, renormalized)
    # Renormalize: new_weight_cvss = CVSS_WEIGHT / (CVSS_WEIGHT + EPSS_WEIGHT)
    renorm_cvss = CVSS_WEIGHT / (CVSS_WEIGHT + EPSS_WEIGHT) if (CVSS_WEIGHT + EPSS_WEIGHT) > 0 else 0.5
    renorm_epss = EPSS_WEIGHT / (CVSS_WEIGHT + EPSS_WEIGHT) if (CVSS_WEIGHT + EPSS_WEIGHT) > 0 else 0.5

    def _ablated_score(c: dict) -> float:
        cvss = (c.get("cvss_base_score") or 0) / CVSS_MAX
        epss = c.get("epss_score") or 0
        return renorm_cvss * cvss + renorm_epss * epss

    ablated_sorted = sorted(cves, key=_ablated_score, reverse=True)
    ablated_ranked = [c["cve_id"] for c in ablated_sorted]

    # Compute recall@N for each ranking
    ns = [25, 50, 100]
    results: dict[str, Any] = {
        "provider": provider,
        "model": "N/A (scoring only)",
        "note": "PIPELINE TEST ONLY, not reportable" if is_mock else "",
        "total_cves": len(cves),
        "total_kev": len(kev_ids),
        "rankings": {},
    }

    for name, ranked in [
        ("phantompatch", pp_ranked),
        ("cvss_only", cvss_ranked),
        ("epss_only", epss_ranked),
        ("kev_ablated", ablated_ranked),
    ]:
        recall = {}
        for n in ns:
            if n <= len(ranked):
                recall[f"recall@{n}"] = _recall_at_n(ranked, kev_ids, n)
        results["rankings"][name] = recall

    results["circularity_note"] = (
        "KEV recall on the PhantomPatch score is partly circular because KEV "
        "accounts for 40% of the score. The kev_ablated ranking removes this "
        "component and uses only CVSS + EPSS (renormalized) for a fairer comparison."
    )

    return results


def main():
    results = asyncio.run(run_priority_eval())
    output_dir = Path(__file__).resolve().parent / "results"
    output_dir.mkdir(exist_ok=True)
    with open(output_dir / "priority_eval.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
