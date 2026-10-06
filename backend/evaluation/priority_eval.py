"""
priority_eval.py — Time-correct KEV prediction and recall@N evaluation.

Evaluates how well a scoring model predicts future KEV additions.
Snapshots history at date T and checks KEV additions in (T, T+90].
Also computes general recall@N and precision/workload metrics.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.config import CVSS_MAX, CVSS_WEIGHT, EPSS_WEIGHT, KEV_WEIGHT, LLM_PROVIDER
from app.scoring.scorer import prioritize, get_scoring_model

logger = logging.getLogger(__name__)


def _recall_at_n(ranked_ids: list[str], kev_ids: set[str], n: int) -> float:
    """Compute recall@N: fraction of KEV CVEs in the top N of the ranked list."""
    if not kev_ids or n <= 0:
        return 0.0
    top_n = set(ranked_ids[:n])
    hits = top_n & kev_ids
    return round(len(hits) / len(kev_ids), 4) if kev_ids else 0.0


def _precision_recall_workload(cves: list[dict], threshold: float, target_cves: set[str]) -> dict[str, float]:
    """Compute Precision, Recall, and Workload for CVEs scored >= threshold."""
    if not target_cves:
        return {"precision": 0.0, "recall": 0.0, "workload": 0.0}

    flagged = {c["cve_id"] for c in cves if c["priority_score"] >= threshold}
    
    true_positives = flagged & target_cves
    
    precision = len(true_positives) / len(flagged) if flagged else 0.0
    recall = len(true_positives) / len(target_cves)
    workload = len(flagged) / len(cves) if cves else 0.0
    
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "workload": round(workload, 4),
    }


async def run_priority_eval() -> dict[str, Any]:
    """Run the priority ranking evaluation."""
    from app.db import get_cves, init_db, query

    await init_db()

    # Get all CVEs
    cves, total = await get_cves(sort_by="priority_score", sort_dir="DESC",
                                  limit=10000, offset=0)
    if not cves:
        return {"status": "no data"}

    provider = LLM_PROVIDER
    is_mock = provider == "mock"

    # Time-correct evaluation logic
    # Find all KEV CVEs with date_added
    kev_data = await query("SELECT cve_id, date_added FROM kev WHERE date_added IS NOT NULL")
    kev_additions = {row["cve_id"]: datetime.fromisoformat(row["date_added"].replace('Z', '+00:00')).date() for row in kev_data}
    
    # We will pick a snapshot date T: 90 days ago.
    today = datetime.now(timezone.utc).date()
    snapshot_date = today - timedelta(days=90)
    
    # Target: CVEs added to KEV in (T, T+90]
    future_kev_cves = {
        cve_id for cve_id, d_added in kev_additions.items()
        if snapshot_date < d_added <= today
    }
    
    # For scoring at time T, we must pretend in_kev = False for the future KEV additions
    # (because they weren't in KEV at time T).
    snapshot_records = []
    for c in cves:
        rec = dict(c)
        if rec["cve_id"] in future_kev_cves:
            rec["in_kev"] = False
        snapshot_records.append(rec)
    
    # Evaluate models
    models_to_test = ["weighted_v1", "vmc_chain_v1"]
    
    results = {
        "provider": provider,
        "note": "Time-correct forward prediction (T to T+90 days)",
        "snapshot_date": str(snapshot_date),
        "total_cves": len(cves),
        "target_future_kev_additions": len(future_kev_cves),
        "rankings": {},
        "predictive_metrics": {},
    }
    
    all_kev_ids = {c["cve_id"] for c in cves if c.get("in_kev")}

    for model_name in models_to_test:
        model = get_scoring_model(model_name)
        
        # Standard Recall@N (using current data, full KEV)
        scored_current = [model.score(c) for c in cves]
        scored_current.sort(key=lambda x: x["priority_score"], reverse=True)
        ranked_ids = [c["cve_id"] for c in scored_current]
        
        recall = {}
        for n in [25, 50, 100]:
            if n <= len(ranked_ids):
                recall[f"recall@{n}"] = _recall_at_n(ranked_ids, all_kev_ids, n)
        
        results["rankings"][model_name] = recall
        
        # Predictive Metrics (Time-correct at T, predicting T+90)
        scored_snapshot = [model.score(c) for c in snapshot_records]
        
        results["predictive_metrics"][model_name] = {
             "threshold_0.75": _precision_recall_workload(scored_snapshot, 0.75, future_kev_cves),
             "threshold_0.50": _precision_recall_workload(scored_snapshot, 0.50, future_kev_cves),
             "threshold_0.25": _precision_recall_workload(scored_snapshot, 0.25, future_kev_cves),
        }

    return results


def main():
    results = asyncio.run(run_priority_eval())
    output_dir = Path(__file__).resolve().parent / "results"
    output_dir.mkdir(exist_ok=True)
    with open(output_dir / "priority_eval.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(json.dumps(results, indent=2, default=str))

    # Write to docs/EVALUATION.md as requested
    docs_dir = Path(__file__).resolve().parent.parent / "docs"
    docs_dir.mkdir(exist_ok=True)
    eval_md = docs_dir / "EVALUATION.md"
    
    md_content = f"# Time-Correct Priority Evaluation\n\nGenerated on: {datetime.now(timezone.utc).date()}\n\n"
    md_content += f"Snapshot Date (T): {results.get('snapshot_date')}\n"
    md_content += f"Target (Future KEV Additions T to T+90): {results.get('target_future_kev_additions')}\n\n"
    
    md_content += "## Predictive Metrics (Predicting KEV Additions)\n\n"
    for model_name, metrics in results.get("predictive_metrics", {}).items():
        md_content += f"### {model_name}\n"
        for thresh, vals in metrics.items():
             md_content += f"- **{thresh}**: Precision: {vals['precision']:.3f}, Recall: {vals['recall']:.3f}, Workload: {vals['workload']:.3f}\n"
        md_content += "\n"
        
    md_content += "## Recall@N (Current KEV)\n\n"
    for model_name, metrics in results.get("rankings", {}).items():
        md_content += f"### {model_name}\n"
        for k, v in metrics.items():
             md_content += f"- **{k}**: {v:.3f}\n"
        md_content += "\n"
        
    with open(eval_md, "w") as f:
        f.write(md_content)


if __name__ == "__main__":
    main()
