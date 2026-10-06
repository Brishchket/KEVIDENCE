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
            if not args.force and any(n["audience"] == audience for n in existing):
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


async def cmd_watch(args: argparse.Namespace) -> None:
    """Run the realtime supervisor standalone (continuous polling)."""
    from app.db import init_db
    from app.ingestion.realtime import start_supervisor, stop_supervisor

    await init_db()

    logger.info("Starting realtime supervisor (Ctrl+C to stop)...")
    await start_supervisor()

    try:
        # Keep running until interrupted
        while True:
            await asyncio.sleep(60)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        logger.info("Shutting down supervisor...")
        await stop_supervisor()
        logger.info("Supervisor stopped.")


async def cmd_report(args: argparse.Namespace) -> None:
    """Generate vulnerability advisory PDF report(s) into backend/reports/."""
    from pathlib import Path
    from app.db import init_db
    from app.reporting.pdf_renderer import render_portfolio_summary_pdf
    from app.reporting.report_generator import (
        get_or_create_report_pdf,
        warm_top_report_pdf_cache,
    )

    await init_db()

    # Destination directory: backend/reports/
    reports_dir = Path(__file__).resolve().parent.parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    if args.cve:
        cve_id = args.cve.strip().upper()
        print(f"Generating advisory report for {cve_id}...")
        try:
            report, pdf_bytes = await get_or_create_report_pdf(
                cve_id,
                provider=args.provider,
                regenerate=args.force,
            )
        except LookupError:
            print(f"Error: CVE {cve_id} not found in database.")
            return

        out_path = reports_dir / f"kevidence-{cve_id}.pdf"
        out_path.write_bytes(pdf_bytes)
        print(f"Successfully generated advisory PDF: {out_path}")
        print(f"   Priority: {report.get('score_breakdown', [{}])[0].get('raw_value', 'Classified')}")
        print(f"   Faithfulness: {report.get('verification', {}).get('faithfulness_score', 1.0) * 100:.1f}%")

    elif args.top_n:
        top_n = args.top_n
        print(f"Generating portfolio summary report for top {top_n} prioritised CVEs...")
        reports = await warm_top_report_pdf_cache(
            top_n=top_n,
            buffer=10,
            provider=args.provider,
            regenerate=args.force,
        )
        if not reports:
            print("Error: No CVEs found in database.")
            return

        pdf_bytes = render_portfolio_summary_pdf(reports)
        out_path = reports_dir / f"kevidence-portfolio-top{top_n}.pdf"
        out_path.write_bytes(pdf_bytes)
        print(f"Successfully generated portfolio summary PDF: {out_path}")
        print(f"   Total advisories included: {len(reports)}")
    else:
        print("Please specify either --cve CVE-XXXX-YYYY or --top-n <number>.")


async def cmd_rescore(args: argparse.Namespace) -> None:
    """Recalculate priority scores for all CVEs in the database."""
    from app.db import init_db, query, execute, log_event
    from app.scoring.scorer import prioritize, get_scoring_model

    await init_db()

    model = get_scoring_model(args.model)
    print(f"Rescoring all CVEs using model: {model.name} (v{model.version})...")

    # Fetch all CVEs
    cves = await query("SELECT * FROM cves")
    if not cves:
        print("No CVEs found.")
        return

    updated_count = 0
    priority_changes = 0

    for record in cves:
        # We need to pass the raw data in, but db might have deserialized some stuff.
        # prioritize doesn't modify the input so we can just pass it.
        # But we must ensure missing signals etc aren't stringified if it expects lists.
        # Actually, query() does not automatically deserialize in the generic helper,
        # but the db schema implies it's fine. We'll simulate a clean dict.
        
        # Extract inputs for prioritize
        input_record = {
            "cve_id": record["cve_id"],
            "cvss_base_score": record["cvss_base_score"],
            "epss_score": record["epss_score"],
            "epss_percentile": record["epss_percentile"],
            "in_kev": record["in_kev"] == 1,
        }
        
        old_label = record["priority_label"]
        new_record = prioritize(input_record, model_name=model.name)
        new_label = new_record["priority_label"]

        if old_label != new_label:
            priority_changes += 1
            await log_event(
                "PRIORITY_CHANGE", 
                record["cve_id"], 
                f"Priority: {old_label} -> {new_label} (model: {model.name})"
            )

        # Update db
        import json
        await execute(
            """
            UPDATE cves SET
                priority_score = ?,
                priority_label = ?,
                priority_breakdown = ?,
                missing_signals = ?,
                reasons = ?,
                score_model = ?,
                score_version = ?
            WHERE cve_id = ?
            """,
            (
                new_record["priority_score"],
                new_record["priority_label"],
                json.dumps(new_record["priority_breakdown"]),
                json.dumps(new_record["missing_signals"]),
                json.dumps(new_record["reasons"]),
                new_record["score_model"],
                new_record["score_version"],
                record["cve_id"],
            )
        )
        updated_count += 1

    print(f"Rescored {updated_count} CVEs. Priority label changes: {priority_changes}.")


async def cmd_compare_models(args: argparse.Namespace) -> None:
    """Compare two scoring models on all CVEs in the DB."""
    from app.db import init_db, query
    from app.scoring.scorer import prioritize, get_scoring_model

    await init_db()

    model_a = get_scoring_model(args.a)
    model_b = get_scoring_model(args.b)
    
    print(f"Comparing {model_a.name} vs {model_b.name}...")

    cves = await query("SELECT * FROM cves")
    if not cves:
         print("No CVEs found.")
         return

    differences = 0
    tier_shifts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for record in cves:
        input_record = {
            "cve_id": record["cve_id"],
            "cvss_base_score": record["cvss_base_score"],
            "epss_score": record["epss_score"],
            "epss_percentile": record["epss_percentile"],
            "in_kev": record["in_kev"] == 1,
        }

        res_a = prioritize(input_record, model_name=model_a.name)
        res_b = prioritize(input_record, model_name=model_b.name)

        if res_a["priority_label"] != res_b["priority_label"]:
            differences += 1
            tier_shifts[res_b["priority_label"]] += 1
            if args.verbose:
                print(f"{record['cve_id']}: {res_a['priority_label']} ({res_a['priority_score']:.2f}) -> {res_b['priority_label']} ({res_b['priority_score']:.2f})")

    print("\n" + "=" * 60)
    print("MODEL COMPARISON REPORT")
    print("=" * 60)
    print(f"  Total CVEs:        {len(cves)}")
    print(f"  Total differences: {differences} ({(differences/len(cves))*100:.1f}%)")
    print(f"  New tiers in {model_b.name}:")
    for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"    {tier}: {tier_shifts[tier]}")
    print("=" * 60)


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
    narrate_parser.add_argument("--force", action="store_true",
                                help="Regenerate and overwrite existing narratives")

    # Evaluate command
    subparsers.add_parser("evaluate", help="Run evaluation harness")

    # Watch command
    subparsers.add_parser("watch", help="Run realtime supervisor (continuous polling)")

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate downloadable PDF vulnerability advisory reports")
    report_parser.add_argument("--cve", type=str, default=None,
                               help="Generate PDF report for a single CVE ID (e.g. CVE-2024-1234)")
    report_parser.add_argument("--top-n", type=int, default=None,
                               help="Generate portfolio summary PDF for top N CVEs")
    report_parser.add_argument("--provider", type=str, default=None,
                               help="LLM provider override (default: from config)")
    report_parser.add_argument("--force", action="store_true",
                               help="Force regeneration bypassing cache")

    # Rescore command
    rescore_parser = subparsers.add_parser("rescore", help="Recalculate priority scores")
    rescore_parser.add_argument("--model", type=str, default=None,
                                help="Scoring model to use (default: from config)")

    # Compare models command
    compare_parser = subparsers.add_parser("compare-models", help="Compare two scoring models")
    compare_parser.add_argument("--a", type=str, required=True, help="Baseline model (e.g. weighted_v1)")
    compare_parser.add_argument("--b", type=str, required=True, help="New model (e.g. vmc_chain_v1)")
    compare_parser.add_argument("--verbose", "-v", action="store_true", help="Print individual CVE differences")

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
    elif args.command == "watch":
        asyncio.run(cmd_watch(args))
    elif args.command == "report":
        asyncio.run(cmd_report(args))
    elif args.command == "rescore":
        asyncio.run(cmd_rescore(args))
    elif args.command == "compare-models":
        asyncio.run(cmd_compare_models(args))


if __name__ == "__main__":
    main()
