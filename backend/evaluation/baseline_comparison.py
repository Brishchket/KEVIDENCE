"""
baseline_comparison.py — Compare PhantomPatch narratives against baselines.

Three conditions:
  1. Raw NVD description (no processing)
  2. Generic LLM (simple prompt, no evidence constraint, no verifier)
  3. PhantomPatch manager narrative (evidence-constrained + verified)

Metrics: Flesch Reading Ease, unsupported-claim rate, evidence coverage, traceability.
Targets: Flesch >= 60, unsupported <= 5%.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _flesch_score(text: str) -> float | None:
    """Compute Flesch Reading Ease score."""
    try:
        import textstat
        return round(textstat.flesch_reading_ease(text), 1)
    except ImportError:
        logger.warning("textstat not installed, skipping Flesch score")
        return None
    except Exception:
        return None


def _evidence_coverage(narrative: str, evidence_facts: dict) -> float:
    """Fraction of key evidence facts reflected in the narrative."""
    facts_to_check = []
    if evidence_facts.get("cvss_score"):
        facts_to_check.append(str(evidence_facts["cvss_score"]))
    if evidence_facts.get("epss_probability"):
        facts_to_check.append(str(round(evidence_facts["epss_probability"], 2)))
    if evidence_facts.get("in_kev"):
        facts_to_check.append("KEV")
    if evidence_facts.get("priority_label"):
        facts_to_check.append(evidence_facts["priority_label"])
    if evidence_facts.get("product"):
        facts_to_check.append(evidence_facts["product"])

    if not facts_to_check:
        return 0.0

    found = sum(1 for f in facts_to_check if f.lower() in narrative.lower())
    return round(found / len(facts_to_check), 4)


async def run_baseline_comparison(top_n: int = 50) -> dict[str, Any]:
    """Run the baseline comparison evaluation."""
    from app.db import get_cves, init_db, get_narratives
    from app.evidence.builder import build_evidence
    from app.evidence.verbalizer import verbalize
    from app.verification.verifier import verify_narrative
    from app.config import LLM_PROVIDER

    await init_db()

    cves, total = await get_cves(sort_by="priority_score", sort_dir="DESC",
                                  limit=top_n, offset=0)
    if not cves:
        return {"status": "no data", "note": "Run ingestion first"}

    provider = LLM_PROVIDER
    is_mock = provider == "mock"

    results = {
        "provider": provider,
        "model": "mock-template-v1" if is_mock else provider,
        "note": "PIPELINE TEST ONLY, not reportable" if is_mock else "",
        "n_cves": len(cves),
        "raw": {"flesch_scores": [], "unsupported_rates": [], "coverage": []},
        "phantompatch": {"flesch_scores": [], "unsupported_rates": [], "coverage": []},
    }

    for cve in cves:
        cve_id = cve["cve_id"]
        evidence = await build_evidence(cve_id)
        if evidence is None:
            continue

        ev_sents = verbalize(evidence)
        raw_desc = cve.get("description", "")

        # Evidence facts for coverage check
        ev_facts = {
            "cvss_score": evidence.cvss.score,
            "epss_probability": evidence.epss.probability,
            "in_kev": evidence.kev.in_kev,
            "priority_label": evidence.priority.label,
            "product": evidence.affected.product,
        }

        # Condition 1: Raw description
        if raw_desc:
            results["raw"]["flesch_scores"].append(_flesch_score(raw_desc))
            raw_verify = verify_narrative(raw_desc, ev_sents, evidence)
            unsupported = 1 - raw_verify.faithfulness_score if raw_verify.total_count > 0 else 1.0
            results["raw"]["unsupported_rates"].append(round(unsupported, 4))
            results["raw"]["coverage"].append(_evidence_coverage(raw_desc, ev_facts))

        # Condition 3: PhantomPatch narrative (from DB)
        narratives = await get_narratives(cve_id)
        manager = next((n for n in narratives if n.get("audience") == "manager"), None)
        if manager:
            text = manager.get("narrative_text", "")
            results["phantompatch"]["flesch_scores"].append(_flesch_score(text))
            v = manager.get("verification", {})
            total_count = v.get("total_count", 0)
            supported_count = v.get("supported_count", 0)
            unsupported = (total_count - supported_count) / total_count if total_count > 0 else 1.0
            results["phantompatch"]["unsupported_rates"].append(round(unsupported, 4))
            results["phantompatch"]["coverage"].append(_evidence_coverage(text, ev_facts))

    # Compute averages
    for condition in ("raw", "phantompatch"):
        data = results[condition]
        flesch = [f for f in data["flesch_scores"] if f is not None]
        data["mean_flesch"] = round(sum(flesch) / len(flesch), 1) if flesch else None
        unsup = data["unsupported_rates"]
        data["mean_unsupported"] = round(sum(unsup) / len(unsup), 4) if unsup else None
        cov = data["coverage"]
        data["mean_coverage"] = round(sum(cov) / len(cov), 4) if cov else None

    # Targets
    results["targets"] = {
        "flesch_min": 60,
        "unsupported_max": 0.05,
    }
    pp = results["phantompatch"]
    results["pass_fail"] = {
        "flesch": "PASS" if pp.get("mean_flesch") and pp["mean_flesch"] >= 60 else "PENDING" if pp.get("mean_flesch") is None else "FAIL",
        "unsupported": "PASS" if pp.get("mean_unsupported") is not None and pp["mean_unsupported"] <= 0.05 else "PENDING" if pp.get("mean_unsupported") is None else "FAIL",
    }

    return results


def main():
    results = asyncio.run(run_baseline_comparison())
    output_dir = Path(__file__).resolve().parent / "results"
    output_dir.mkdir(exist_ok=True)
    with open(output_dir / "baseline_comparison.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
