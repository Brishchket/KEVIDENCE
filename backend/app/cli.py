"""
cli.py — Command-line interface for PhantomPatch.

Usage:
    python -m app.cli ingest --target 600
    python -m app.cli narrate --top-n 50 --audiences all
    python -m app.cli evaluate
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from datetime import datetime, timedelta, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("phantompatch")


async def cmd_ingest(args: argparse.Namespace) -> None:
    """Run the ingestion pipeline."""
    from app.ingestion.pipeline import run_pipeline

    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=args.days)

    logger.info("Starting ingestion: target=%d CVEs, date range=%s to %s",
                args.target, start_date.date(), end_date.date())

    result = await run_pipeline(
        start_date=start_date,
        end_date=end_date,
        target=args.target,
    )

    print("\n" + "=" * 60)
    print("INGESTION REPORT")
    print("=" * 60)
    print(f"  Run ID:          {result['run_id']}")
    print(f"  CVEs fetched:    {result['cves_fetched']}")
    print(f"  Inserted:        {result['inserted']}")
    print(f"  Updated:         {result['updated']}")
    print(f"  Parse failures:  {result['parse_failures']}")
    print(f"  Parse rate:      {result['parse_rate']:.1f}%")
    print("=" * 60)


async def cmd_narrate(args: argparse.Namespace) -> None:
    """Generate narratives for top-priority CVEs."""
    from app.db import get_cves, init_db
    from app.evidence.builder import build_evidence
    from app.narrative.generator import generate_narrative, get_llm_client

    await init_db()

    # Get top-N CVEs by priority
    cves, total = await get_cves(
        sort_by="priority_score",
        sort_dir="DESC",
        limit=args.top_n,
        offset=0,
    )

    if not cves:
        print("No CVEs found. Run ingestion first: python -m app.cli ingest")
        return

    audiences = ["manager", "analyst", "it_admin"] if args.audiences == "all" else [args.audiences]
    llm_client = get_llm_client(args.provider)

    print(f"\nGenerating narratives for {len(cves)} CVEs × {len(audiences)} audiences")
    print(f"Provider: {llm_client.provider_name} ({llm_client.model_name})")
    print("=" * 60)

    success = 0
    total_faith = 0.0

    for i, cve in enumerate(cves):
        cve_id = cve["cve_id"]
        evidence = await build_evidence(cve_id)
        if evidence is None:
            logger.warning("Skipping %s: evidence not found", cve_id)
            continue

        from app.db import get_narratives
        for audience in audiences:
            existing = await get_narratives(cve_id)
            if any(n["audience"] == audience for n in existing):
                logger.info("Skipping %s (%s): already generated", cve_id, audience)
                continue
            
            record = await generate_narrative(evidence, audience, llm_client)
            status = "✓" if record.confidence in ("HIGH", "MEDIUM") else "✗"
            print(f"  [{i+1}/{len(cves)}] {cve_id} ({audience}): "
                  f"faithfulness={record.faithfulness_score:.3f} "
                  f"confidence={record.confidence} {status}")
            success += 1
            total_faith += record.faithfulness_score

    avg_faith = total_faith / success if success > 0 else 0
    print("\n" + "=" * 60)
    print("NARRATIVE GENERATION REPORT")
    print("=" * 60)
    print(f"  Narratives generated: {success}")
    print(f"  Average faithfulness: {avg_faith:.3f}")
    print(f"  Provider: {llm_client.provider_name} ({llm_client.model_name})")
    print("=" * 60)


async def cmd_evaluate(args: argparse.Namespace) -> None:
    """Run evaluation harness."""
    print("Running evaluation harness...")
    try:
        from evaluation.run_all import run_all
        await run_all()
    except ImportError:
        # Fallback: run as subprocess
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "evaluation.run_all"],
            cwd=str(__import__("pathlib").Path(__file__).resolve().parent.parent),
        )
        sys.exit(result.returncode)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="phantompatch",
        description="PhantomPatch: Evidence-Grounded Vulnerability Risk Narrative Engine",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Ingest command
    ingest_parser = subparsers.add_parser("ingest", help="Ingest CVE data from NVD + EPSS + KEV")
    ingest_parser.add_argument("--target", type=int, default=600,
                               help="Target number of CVEs to ingest (default: 600)")
    ingest_parser.add_argument("--days", type=int, default=30,
                               help="Number of days back to fetch (default: 30)")

    # Narrate command
    narrate_parser = subparsers.add_parser("narrate", help="Generate narratives for CVEs")
    narrate_parser.add_argument("--top-n", type=int, default=50,
                                help="Number of top-priority CVEs to narrate (default: 50)")
    narrate_parser.add_argument("--audiences", type=str, default="all",
                                choices=["all", "manager", "analyst", "it_admin"],
                                help="Audience(s) to generate for (default: all)")
    narrate_parser.add_argument("--provider", type=str, default=None,
                                help="LLM provider override (default: from config)")

    # Evaluate command
    subparsers.add_parser("evaluate", help="Run evaluation harness")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    if args.command == "ingest":
        asyncio.run(cmd_ingest(args))
    elif args.command == "narrate":
        asyncio.run(cmd_narrate(args))
    elif args.command == "evaluate":
        asyncio.run(cmd_evaluate(args))


if __name__ == "__main__":
    main()
