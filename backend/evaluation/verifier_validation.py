"""
verifier_validation.py — Validate the faithfulness verifier.

Two modes:
  export: Write ~50 real narrative sentences to labeling/verifier_labels.csv
          with an empty human_label column for manual annotation.
  score:  Read the filled file and compute agreement, precision, recall, F1
          vs. the >= 85% target, plus a threshold sweep (0.50-0.70).

Also generates a synthetic adversarial set as a sanity check.
"""
from __future__ import annotations

import asyncio
import csv
import json
import logging
import random
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from app.config import LLM_PROVIDER, SIMILARITY_THRESHOLD


async def export_labels(output_dir: Path | None = None) -> dict[str, Any]:
    """
    Export ~50 real narrative sentences for human labeling.
    Stratified: mix of supported and flagged sentences.
    """
    from app.db import init_db, get_cves, get_narratives

    await init_db()

    cves, _ = await get_cves(sort_by="priority_score", sort_dir="DESC",
                              limit=100, offset=0)

    sentences_data: list[dict] = []

    for cve in cves:
        narratives = await get_narratives(cve["cve_id"])
        for n in narratives:
            verification = n.get("verification", {})
            for sent in verification.get("sentences", []):
                sentences_data.append({
                    "cve_id": cve["cve_id"],
                    "audience": n.get("audience", ""),
                    "sentence": sent.get("text", ""),
                    "auto_supported": "yes" if sent.get("supported") else "no",
                    "max_similarity": sent.get("max_similarity", 0),
                    "matched_evidence": sent.get("matched_evidence_sentence", ""),
                    "human_label": "",  # To be filled by humans
                })

    # Stratified sample: ~25 supported + ~25 flagged
    supported = [s for s in sentences_data if s["auto_supported"] == "yes"]
    flagged = [s for s in sentences_data if s["auto_supported"] == "no"]

    random.seed(42)
    sample = (
        random.sample(supported, min(25, len(supported)))
        + random.sample(flagged, min(25, len(flagged)))
    )
    random.shuffle(sample)

    if output_dir is None:
        output_dir = Path(__file__).resolve().parent / "labeling"
    output_dir.mkdir(parents=True, exist_ok=True)

    csv_path = output_dir / "verifier_labels.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "cve_id", "audience", "sentence", "auto_supported",
            "max_similarity", "matched_evidence", "human_label",
        ])
        writer.writeheader()
        writer.writerows(sample)

    return {
        "exported": len(sample),
        "supported_count": len([s for s in sample if s["auto_supported"] == "yes"]),
        "flagged_count": len([s for s in sample if s["auto_supported"] == "no"]),
        "path": str(csv_path),
        "note": "Fill the human_label column with 'supported' or 'unsupported'",
    }


async def score_labels(labels_path: Path | None = None) -> dict[str, Any]:
    """
    Score the verifier against human labels.
    Computes agreement, precision, recall, F1.
    Also does a threshold sweep (0.50-0.70).
    """
    if labels_path is None:
        labels_path = Path(__file__).resolve().parent / "labeling" / "verifier_labels.csv"

    if not labels_path.exists():
        return {
            "status": "SKIPPED: needs human labels",
            "note": f"Label the file at {labels_path} then re-run",
        }

    rows = []
    with open(labels_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Check if human labels are filled
    labeled = [r for r in rows if r.get("human_label", "").strip()]
    if not labeled:
        return {
            "status": "SKIPPED: needs human labels",
            "note": "human_label column is empty — fill it first",
        }

    # Compute metrics
    tp = fp = fn = tn = 0
    for r in labeled:
        auto = r["auto_supported"].strip().lower() == "yes"
        human = r["human_label"].strip().lower() in ("supported", "yes", "1", "true")
        if auto and human:
            tp += 1
        elif auto and not human:
            fp += 1
        elif not auto and human:
            fn += 1
        else:
            tn += 1

    total = tp + fp + fn + tn
    agreement = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    result: dict[str, Any] = {
        "n_labeled": len(labeled),
        "agreement": round(agreement, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "target_f1": 0.85,
        "f1_pass": f1 >= 0.85,
    }

    # Threshold sweep
    thresholds = [round(t, 2) for t in [0.50, 0.55, 0.60, 0.65, 0.70]]
    sweep: list[dict] = []
    for thresh in thresholds:
        t_tp = t_fp = t_fn = t_tn = 0
        for r in labeled:
            sim = float(r.get("max_similarity", 0))
            auto_at_thresh = sim >= thresh
            human = r["human_label"].strip().lower() in ("supported", "yes", "1", "true")
            if auto_at_thresh and human:
                t_tp += 1
            elif auto_at_thresh and not human:
                t_fp += 1
            elif not auto_at_thresh and human:
                t_fn += 1
            else:
                t_tn += 1
        t_total = t_tp + t_fp + t_fn + t_tn
        t_prec = t_tp / (t_tp + t_fp) if (t_tp + t_fp) > 0 else 0
        t_rec = t_tp / (t_tp + t_fn) if (t_tp + t_fn) > 0 else 0
        t_f1 = 2 * t_prec * t_rec / (t_prec + t_rec) if (t_prec + t_rec) > 0 else 0
        sweep.append({
            "threshold": thresh,
            "precision": round(t_prec, 4),
            "recall": round(t_rec, 4),
            "f1": round(t_f1, 4),
        })

    result["threshold_sweep"] = sweep
    best = max(sweep, key=lambda x: x["f1"])
    result["recommended_threshold"] = best["threshold"]

    return result


async def run_synthetic_adversarial() -> dict[str, Any]:
    """
    Generate synthetic adversarial sentences and verify the verifier catches them.
    Clearly labeled as synthetic — not a substitute for human labels.
    """
    from app.schemas import Evidence, CVSSDetail, EPSSDetail, KEVDetail, PriorityDetail, PriorityBreakdown, AffectedDetail
    from app.evidence.verbalizer import verbalize
    from app.verification.verifier import verify_narrative

    evidence = Evidence(
        cve_id="CVE-2024-SYNTH",
        description="Buffer overflow in TestApp allows remote code execution.",
        cvss=CVSSDetail(score=9.8, severity="CRITICAL",
                        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        attack_vector="NETWORK"),
        cwe=["CWE-787"],
        epss=EPSSDetail(probability=0.93, percentile=0.99),
        kev=KEVDetail(in_kev=True, date_added="2024-01-15",
                      required_action="Apply updates"),
        affected=AffectedDetail(vendor="TestCorp", product="TestApp"),
        priority=PriorityDetail(score=0.919, label="CRITICAL",
                                breakdown=PriorityBreakdown(cvss_contribution=0.294,
                                                            epss_contribution=0.279,
                                                            kev_contribution=0.4)),
        reasons=["Listed in CISA KEV"],
        recommended_action="Patch immediately.",
    )
    ev_sents = verbalize(evidence)

    # Adversarial: false claims, wrong numbers
    adversarial_sentences = [
        "CVE-2024-SYNTH has a CVSS score of 7.5.",  # Wrong number
        "This vulnerability was exploited by APT29 against government agencies.",  # Fabricated
        "The EPSS probability is 0.12, indicating low risk.",  # Wrong number
        "A patch was released on 2024-06-30.",  # Wrong date
        "The vulnerability affects Microsoft Windows Server 2022.",  # Wrong product
    ]

    results = []
    for sent in adversarial_sentences:
        v = verify_narrative(sent, ev_sents, evidence, threshold=0.60, strict_facts=True)
        caught = v.faithfulness_score < 1.0
        results.append({
            "sentence": sent,
            "faithfulness": v.faithfulness_score,
            "caught": caught,
        })

    caught_count = sum(1 for r in results if r["caught"])
    return {
        "label": "SYNTHETIC — sanity check only, not a substitute for human labels",
        "total": len(adversarial_sentences),
        "caught": caught_count,
        "catch_rate": round(caught_count / len(adversarial_sentences), 4),
        "details": results,
    }


async def run_verifier_validation() -> dict[str, Any]:
    """Run all verifier validation steps."""
    result: dict[str, Any] = {
        "provider": LLM_PROVIDER,
        "note": "PIPELINE TEST ONLY, not reportable" if LLM_PROVIDER == "mock" else "",
    }

    # Export labels
    export_result = await export_labels()
    result["export"] = export_result

    # Score (if labels exist)
    score_result = await score_labels()
    result["scoring"] = score_result

    # Synthetic adversarial
    synth_result = await run_synthetic_adversarial()
    result["synthetic_adversarial"] = synth_result

    return result


def main():
    import sys
    results = asyncio.run(run_verifier_validation())
    output_dir = Path(__file__).resolve().parent / "results"
    output_dir.mkdir(exist_ok=True)
    with open(output_dir / "verifier_validation.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
