"""
run_all.py — Run all evaluation scripts and print summary.

Prints clear "SKIPPED: needs human labels/responses" messages where needed.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


async def run_all():
    """Run all evaluations and produce a summary."""
    from app.db import init_db, insert_eval_run
    from app.config import LLM_PROVIDER

    await init_db()

    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(exist_ok=True)

    summary: dict = {}

    # a) Baseline comparison
    print("\n" + "=" * 60)
    print("EVALUATION: Baseline Comparison")
    print("=" * 60)
    try:
        from evaluation.baseline_comparison import run_baseline_comparison
        baseline = await run_baseline_comparison()
        summary["baseline_comparison"] = baseline
        await insert_eval_run("baseline_comparison", LLM_PROVIDER, "", baseline)
        print(json.dumps(baseline, indent=2, default=str))
    except Exception as exc:
        msg = f"FAILED: {exc}"
        summary["baseline_comparison"] = {"status": msg}
        print(msg)

    # b) Priority evaluation
    print("\n" + "=" * 60)
    print("EVALUATION: Priority Ranking (KEV Recall)")
    print("=" * 60)
    try:
        from evaluation.priority_eval import run_priority_eval
        priority = await run_priority_eval()
        summary["priority_eval"] = priority
        await insert_eval_run("priority_eval", LLM_PROVIDER, "", priority)
        print(json.dumps(priority, indent=2, default=str))
    except Exception as exc:
        msg = f"FAILED: {exc}"
        summary["priority_eval"] = {"status": msg}
        print(msg)

    # c) Verifier validation
    print("\n" + "=" * 60)
    print("EVALUATION: Verifier Validation")
    print("=" * 60)
    try:
        from evaluation.verifier_validation import run_verifier_validation
        verifier = await run_verifier_validation()
        summary["verifier_validation"] = verifier
        await insert_eval_run("verifier_validation", LLM_PROVIDER, "", verifier)
        print(json.dumps(verifier, indent=2, default=str))
    except Exception as exc:
        msg = f"FAILED: {exc}"
        summary["verifier_validation"] = {"status": msg}
        print(msg)

    # d) Survey analysis
    print("\n" + "=" * 60)
    print("EVALUATION: Survey Analysis")
    print("=" * 60)
    try:
        from evaluation.survey_analysis import run_survey_analysis
        survey = await run_survey_analysis()
        summary["survey_analysis"] = survey
        await insert_eval_run("survey_analysis", LLM_PROVIDER, "", survey)
        print(json.dumps(survey, indent=2, default=str))
    except Exception as exc:
        msg = f"FAILED: {exc}"
        summary["survey_analysis"] = {"status": msg}
        print(msg)

    # Write summary
    with open(results_dir / "summary.json", "w") as f:
        json.dump(summary, f, indent=2, default=str)

    # Write summary.md
    with open(results_dir / "summary.md", "w") as f:
        f.write("# PhantomPatch Evaluation Summary\n\n")
        f.write(f"**Provider:** {LLM_PROVIDER}\n\n")

        for section, data in summary.items():
            f.write(f"## {section.replace('_', ' ').title()}\n\n")
            if isinstance(data, dict):
                status = data.get("status") or data.get("pass_fail", {})
                if "SKIPPED" in str(status):
                    f.write(f"**{status}**\n\n")
                else:
                    f.write(f"```json\n{json.dumps(data, indent=2, default=str)}\n```\n\n")
            f.write("---\n\n")

    print("\n" + "=" * 60)
    print("EVALUATION COMPLETE")
    print(f"Results saved to: {results_dir}")
    print("=" * 60)


def main():
    asyncio.run(run_all())


if __name__ == "__main__":
    main()
