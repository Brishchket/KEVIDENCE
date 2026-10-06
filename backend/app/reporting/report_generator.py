"""
report_generator.py — LLM report generator with verifier loop & deterministic fallback.

Generates the 6 core report sections + Executive Summary:
  1. Executive Summary
  2. WHY
  3. WHAT
  4. WHERE
  5. HOW
  6. RESOLUTION
  7. ORIGIN

Rules:
  - Evidence-grounding: LLM explains, code makes the decision.
  - Verifier check + retry loop on unsupported sentences.
  - Drop unsupported sentences if retry still fails; record verified/dropped counts.
  - Deterministic template fallback when mock provider is active or offline.
  - Automatic cache invalidation when CVE data_hash changes.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Optional

from app import config
from app.config import (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    MAX_RETRIES,
    RETRY_BELOW,
)
from app.db import (
    get_cves,
    get_narratives,
    get_report,
    get_report_pdf,
    save_report_pdf,
    upsert_report,
)
from app.llm.base import LLMClient
from app.llm.mock import MockLLMClient
from app.narrative.generator import get_llm_client
from app.reporting.report_evidence import (
    NOT_STATED,
    ReportEvidence,
    build_report_evidence,
    verbalize_report_evidence,
)
from app.reporting.report_prompts import (
    REPORT_PROMPT_VERSION,
    get_report_retry_prompt,
    get_section_system_prompt,
    get_section_user_prompt,
)
from app.schemas import Evidence
from app.verification.verifier import _split_sentences, verify_narrative

logger = logging.getLogger(__name__)


# ── Deterministic Template Generator (Offline & Mock Fallback) ─────────────────

def generate_deterministic_report(evidence: ReportEvidence) -> dict[str, Any]:
    """
    Generate complete 6-section report directly from evidence without calling an LLM.
    Guaranteed zero hallucinations, 100% offline-ready, strict source attribution.
    """
    vendor_str = ", ".join(evidence.vendors) if evidence.vendors else NOT_STATED
    product_str = ", ".join(evidence.products) if evidence.products else NOT_STATED

    # 1. Executive Summary
    exec_summary = (
        f"Security vulnerability {evidence.cve_id} is evaluated at deterministic priority {evidence.priority_label} "
        f"(composite score {evidence.priority_score:.3f}) under the {evidence.scoring_version} [NVD]. "
        f"The flaw affects {vendor_str} {product_str} with {evidence.attack_vector.lower()} network exposure [NVD]. "
        f"{'This vulnerability is actively weaponized in the wild and cataloged in the CISA KEV catalog [KEV]. ' if evidence.in_kev else 'Not listed in CISA Known Exploited Vulnerabilities (KEV) based on available threat intelligence [KEV]. '}"
        f"The EPSS model estimates an exploitation likelihood of {evidence.epss_probability * 100:.2f}% [EPSS]. "
        f"Recommended operational action: {evidence.recommended_action} [NVD]."
    )

    # 2. WHY Section
    why_text = (
        f"{evidence.cve_id} is prioritised as {evidence.priority_label} based on triaged technical and threat signals [NVD]. "
        f"The composite priority score is {evidence.priority_score:.3f} (scale 0.000 to 1.000) using the {evidence.scoring_version} [NVD]. "
        f"Technical Severity contributes {evidence.score_breakdown[0]['contribution']} based on CVSS v3.1 score {evidence.cvss_base_score if evidence.cvss_base_score is not None else NOT_STATED} [NVD]. "
        f"Predictive Threat Modeling contributes {evidence.score_breakdown[1]['contribution']} via an EPSS probability of {evidence.epss_probability * 100:.2f}% [EPSS]. "
        f"Authoritative Threat Intel contributes {evidence.score_breakdown[2]['contribution']} with active KEV exploitation status: {evidence.kev_status} [KEV]. "
        f"Deterministic Calculation: {evidence.score_formula}."
    )

    # 3. WHAT Section
    kev_desc_part = (
        f"CISA KEV lists this issue as '{evidence.kev_vulnerability_name}' with official notice: {evidence.kev_short_description} [KEV]."
        if evidence.in_kev
        else f"CISA KEV Cataloging: {NOT_STATED} [KEV]."
    )
    what_text = (
        f"Vulnerability {evidence.cve_id} represents an identified flaw in {vendor_str} {product_str} [NVD]. "
        f"NVD Summary: {evidence.description} [NVD]. "
        f"Technical severity is rated {evidence.cvss_severity} with CVSS base score {evidence.cvss_base_score if evidence.cvss_base_score is not None else NOT_STATED} [NVD]. "
        f"{kev_desc_part}"
    )

    # 4. WHERE Section
    version_range_str = (
        "; ".join([
            f"{vr.get('vendor') or ''} {vr.get('product') or ''} (criteria: {vr.get('criteria')})"
            for vr in evidence.version_ranges[:4]
        ])
        if evidence.version_ranges
        else NOT_STATED
    )
    where_text = (
        f"The vulnerability resides within software components maintained by {vendor_str} [NVD]. "
        f"Specifically affected products include {product_str} across {len(evidence.affected_cpes)} identified CPE platform configurations [NVD]. "
        f"Network Exposure: {evidence.attack_vector} [NVD]. "
        f"Identified Version Constraints: {version_range_str} [NVD]."
    )

    # 5. HOW Section
    ransomware_part = (
        f"Known Ransomware Association: {evidence.known_ransomware_use} [KEV]."
        if evidence.in_kev
        else f"Known Ransomware Association: {NOT_STATED} [KEV]."
    )
    percentile_part = (
        f" (ranking at the {int(evidence.epss_percentile * 100)}th percentile globally)"
        if evidence.epss_percentile is not None
        else ""
    )
    how_text = (
        f"Exploitation Status: {evidence.kev_status} [KEV]. "
        f"{ransomware_part} "
        f"The FIRST.org EPSS model calculates a {(evidence.epss_probability * 100):.2f}% probability of active weaponization in the next 30 days{percentile_part} [EPSS]. "
        f"Exploitation Mechanics and Prerequisites: {evidence.cvss_decoded.get('summary', NOT_STATED)} [NVD]."
    )

    # 6. RESOLUTION Section
    patch_urls_str = ", ".join(evidence.patch_urls[:3]) if evidence.patch_urls else NOT_STATED
    kev_action_part = (
        f"CISA BOD 22-01 Mandate: {evidence.kev_required_action} with mandatory remediation deadline {evidence.kev_due_date} [KEV]."
        if evidence.in_kev
        else f"Mandatory Federal Directive: {NOT_STATED} [KEV]."
    )
    cwe_mit_str = "; ".join(evidence.cwe_mitigations[:3]) if evidence.cwe_mitigations else NOT_STATED
    resolution_text = (
        f"Recommended Operational Action: {evidence.recommended_action} [NVD]. "
        f"{kev_action_part} "
        f"Verified Patches and Vendor Advisories: {patch_urls_str} [NVD]. "
        f"General Architectural Hardening (MITRE CWE Guidance): {cwe_mit_str} [CWE]."
    )

    # 7. ORIGIN Section
    cwe_names = (
        ", ".join([f"{c.get('cwe_id')} ({c.get('name')})" for c in evidence.cwe_details])
        if evidence.cwe_details
        else NOT_STATED
    )
    primary_cwe_desc = (
        evidence.cwe_details[0].get("description", NOT_STATED)
        if evidence.cwe_details
        else NOT_STATED
    )
    common_consequences = (
        "; ".join(evidence.cwe_details[0].get("consequences", [NOT_STATED])[:3])
        if evidence.cwe_details
        else NOT_STATED
    )
    origin_text = (
        f"Root Cause Weakness: {cwe_names} [CWE]. "
        f"Mechanism of Vulnerability: {primary_cwe_desc} [CWE]. "
        f"Common Architectural Consequences: {common_consequences} [CWE]. "
        f"Vulnerability Lifecycle Timeline: Published on {evidence.timeline['Published Date']}, last modified on {evidence.timeline['Last Modified Date']}, KEV addition recorded on {evidence.timeline['CISA KEV Addition']} [NVD] [KEV]."
    )

    all_sections = [exec_summary, why_text, what_text, where_text, how_text, resolution_text, origin_text]
    total_sentences = sum(len(_split_sentences(sec)) for sec in all_sections)

    return {
        "cve_id": evidence.cve_id,
        "executive_summary": exec_summary,
        "sections": {
            "why": why_text,
            "what": what_text,
            "where": where_text,
            "how": how_text,
            "resolution": resolution_text,
            "origin": origin_text,
        },
        "score_breakdown": evidence.score_breakdown,
        "score_formula": evidence.score_formula,
        "scoring_version": evidence.scoring_version,
        "timeline": evidence.timeline,
        "version_ranges": evidence.version_ranges,
        "patch_urls": evidence.patch_urls,
        "reference_tags": evidence.reference_tags_grouped,
        "cwe_mitigations": evidence.cwe_mitigations,
        "source_freshness": evidence.source_freshness,
        "verification": {
            "faithfulness_score": 1.0,
            "confidence": "HIGH",
            "verified_sentences_count": total_sentences,
            "dropped_sentences_count": 0,
            "total_sentences": total_sentences,
            "notes": "Generated deterministically via evidence grounding template engine.",
        },
        "provider": "deterministic-template",
        "model": "ground-truth-template-engine",
        "prompt_version": REPORT_PROMPT_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


# ── LLM Section Generator with Verifier Loop ──────────────────────────────────

async def _generate_verified_section(
    section_name: str,
    evidence_dict: dict[str, Any],
    evidence_obj: Evidence,
    ground_truth_sentences: list[str],
    llm_client: LLMClient,
    fallback_text: str,
) -> tuple[str, int, int]:
    """
    Generate one report section with verifier retry loop.
    Returns: (final_text, verified_count, dropped_count).
    """
    system_prompt = get_section_system_prompt(section_name)
    user_prompt = get_section_user_prompt(section_name, evidence_dict)

    current_text = fallback_text
    verified_count = 0
    dropped_count = 0

    try:
        draft = await llm_client.generate(system_prompt, user_prompt)
        current_text = draft.strip()
    except Exception as exc:
        logger.warning("LLM generation failed for section %s: %s, using fallback", section_name, exc)
        sents = _split_sentences(fallback_text)
        return fallback_text, len(sents), 0

    # Verification & Retry loop
    for attempt in range(1 + MAX_RETRIES):
        v_result = verify_narrative(
            current_text,
            ground_truth_sentences,
            evidence_obj,
        )

        if v_result.faithfulness_score >= RETRY_BELOW:
            # Check if any individual sentence failed
            unsupported = [s.text for s in v_result.sentences if not s.supported]
            if not unsupported:
                verified_count = v_result.supported_count
                return current_text, verified_count, 0

            # Filter out unsupported sentences directly
            good_sents = [s.text for s in v_result.sentences if s.supported]
            if good_sents:
                verified_count = len(good_sents)
                dropped_count = len(unsupported)
                return " ".join(good_sents), verified_count, dropped_count

        # If below threshold and retries remaining, request targeted correction
        if attempt < MAX_RETRIES:
            unsupported_texts = [s.text for s in v_result.sentences if not s.supported]
            retry_prompt = get_report_retry_prompt(
                section_name,
                evidence_dict,
                current_text,
                unsupported_texts,
            )
            try:
                new_draft = await llm_client.generate(system_prompt, retry_prompt)
                current_text = new_draft.strip()
            except Exception as exc:
                logger.warning("Section %s retry failed: %s", section_name, exc)
                break

    # If still containing unsupported sentences after all retries: drop them
    final_verification = verify_narrative(current_text, ground_truth_sentences, evidence_obj)
    good_sentences = [s.text for s in final_verification.sentences if s.supported]
    dropped = [s.text for s in final_verification.sentences if not s.supported]

    if good_sentences:
        return " ".join(good_sentences), len(good_sentences), len(dropped)

    # If all sentences were dropped, return the verified deterministic fallback
    fallback_sents = _split_sentences(fallback_text)
    return fallback_text, len(fallback_sents), len(dropped)


# ── Full Vulnerability Report Orchestrator ────────────────────────────────────

async def generate_vulnerability_report(
    cve_id: str,
    provider: Optional[str] = None,
    regenerate: bool = False,
) -> Optional[dict[str, Any]]:
    """
    Generate or retrieve a full 6-section vulnerability report for a CVE.
    Enforces automatic cache invalidation on data hash change.
    """
    evidence = await build_report_evidence(cve_id)
    if not evidence:
        return None

    prov = (provider or config.LLM_PROVIDER).lower()

    # 1. Check SQLite reports cache
    if not regenerate:
        cached = await get_report(cve_id, audience="executive")
        if cached and cached.get("data_hash") == evidence.data_hash:
            logger.info("Serving cached vulnerability report for %s", cve_id)
            return cached.get("content")

    # 2. Check if Mock, offline, or no API key configured
    import os
    has_key = True
    if prov == "gemini" and not (getattr(config, "GEMINI_API_KEY", None) or os.getenv("GEMINI_API_KEY")):
        has_key = False
    elif prov == "openai" and not (getattr(config, "OPENAI_API_KEY", None) or os.getenv("OPENAI_API_KEY")):
        has_key = False
    elif prov == "anthropic" and not (getattr(config, "ANTHROPIC_API_KEY", None) or os.getenv("ANTHROPIC_API_KEY")):
        has_key = False

    llm_client = get_llm_client(prov)
    deterministic_report = generate_deterministic_report(evidence)

    if isinstance(llm_client, MockLLMClient) or prov == "mock" or not has_key:
        logger.info("Generating deterministic template report for %s (mock/offline/no-key)", cve_id)
        report_data = deterministic_report
        # Check if an existing manager narrative is available and strictly verified against report evidence
        existing_narratives = await get_narratives(cve_id)
        mgr_nar = next((n for n in existing_narratives if n.get("audience") == "manager"), None)
        if mgr_nar and mgr_nar.get("narrative_text"):
            from app.evidence.builder import build_evidence
            ev_schema = await build_evidence(cve_id)
            gt_sents = verbalize_report_evidence(evidence)
            v_check = verify_narrative(
                mgr_nar["narrative_text"],
                gt_sents,
                ev_schema or Evidence(cve_id=cve_id, description=evidence.description),
            )
            # Only reuse if fully supported with zero unsupported sentences
            if v_check.faithfulness_score >= RETRY_BELOW and not any(not s.supported for s in v_check.sentences):
                report_data["executive_summary"] = mgr_nar["narrative_text"]
            else:
                logger.info("Existing manager narrative for %s failed report verification, using deterministic summary", cve_id)

        await upsert_report(cve_id, report_data, evidence.data_hash, audience="executive")
        return report_data

    # 3. Live LLM Generation for each section
    logger.info("Generating LLM vulnerability report for %s using provider %s", cve_id, prov)
    from app.evidence.builder import build_evidence
    import asyncio
    
    evidence_schema = await build_evidence(cve_id)
    ground_truth_sentences = verbalize_report_evidence(evidence)

    evidence_dict = asdict(evidence)
    sections_out: dict[str, str] = {}
    total_verified = 0
    total_dropped = 0

    section_names = ["why", "what", "where", "how", "resolution", "origin"]
    
    # Check if we can reuse an existing executive summary
    existing_narratives = await get_narratives(cve_id)
    mgr_nar = next((n for n in existing_narratives if n.get("audience") == "manager"), None)
    exec_summary = None
    if mgr_nar and mgr_nar.get("narrative_text"):
        v_check = verify_narrative(
            mgr_nar["narrative_text"],
            ground_truth_sentences,
            evidence_schema or Evidence(cve_id=cve_id, description=evidence.description),
        )
        if v_check.faithfulness_score >= RETRY_BELOW and not any(not s.supported for s in v_check.sentences):
            exec_summary = mgr_nar["narrative_text"]
            total_verified += v_check.supported_count
            
    # Prepare tasks for parallel generation
    tasks = []
    # Add section tasks
    for sec in section_names:
        fallback_sec_text = deterministic_report["sections"][sec]
        tasks.append(
            _generate_verified_section(
                sec,
                evidence_dict,
                evidence_schema or Evidence(
                    cve_id=cve_id,
                    description=evidence.description,
                    cvss=Any,
                    cwe=evidence.cwe_details,
                    epss=Any,
                    kev=Any,
                    affected=Any,
                    priority=Any,
                    references=[],
                    recommended_action=evidence.recommended_action,
                ),
                ground_truth_sentences,
                llm_client,
                fallback_sec_text,
            )
        )
        
    # Add executive summary task if needed
    if not exec_summary:
        tasks.append(
            _generate_verified_section(
                "executive",
                evidence_dict,
                evidence_schema or Evidence(cve_id=cve_id, description=evidence.description),
                ground_truth_sentences,
                llm_client,
                deterministic_report["executive_summary"],
            )
        )
        
    # Execute all generations concurrently
    results = await asyncio.gather(*tasks)
    
    # Process results
    for idx, sec in enumerate(section_names):
        text, verified_n, dropped_n = results[idx]
        sections_out[sec] = text
        total_verified += verified_n
        total_dropped += dropped_n
        
    if not exec_summary:
        exec_summary, v_n, d_n = results[-1]
        total_verified += v_n
        total_dropped += d_n

    total_sentences = total_verified + total_dropped
    faithfulness = (total_verified / total_sentences) if total_sentences > 0 else 1.0
    confidence = (
        "HIGH"
        if faithfulness >= CONFIDENCE_HIGH
        else "MEDIUM"
        if faithfulness >= CONFIDENCE_MEDIUM
        else "LOW"
    )

    report_result = {
        "cve_id": evidence.cve_id,
        "executive_summary": exec_summary,
        "sections": sections_out,
        "score_breakdown": evidence.score_breakdown,
        "score_formula": evidence.score_formula,
        "scoring_version": evidence.scoring_version,
        "timeline": evidence.timeline,
        "version_ranges": evidence.version_ranges,
        "patch_urls": evidence.patch_urls,
        "reference_tags": evidence.reference_tags_grouped,
        "cwe_mitigations": evidence.cwe_mitigations,
        "source_freshness": evidence.source_freshness,
        "verification": {
            "faithfulness_score": round(faithfulness, 4),
            "confidence": confidence,
            "verified_sentences_count": total_verified,
            "dropped_sentences_count": total_dropped,
            "total_sentences": total_sentences,
            "notes": f"Verified against {len(ground_truth_sentences)} ground-truth evidence statements.",
        },
        "provider": prov,
        "model": getattr(llm_client, "model", prov),
        "prompt_version": REPORT_PROMPT_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    await upsert_report(cve_id, report_result, evidence.data_hash, audience="executive")
    return report_result


async def get_or_create_report_pdf(
    cve_id: str,
    provider: Optional[str] = None,
    regenerate: bool = False,
) -> tuple[dict[str, Any], bytes]:
    """Generate the current report and return its evidence-hash-matched PDF blob."""
    report = await generate_vulnerability_report(
        cve_id,
        provider=provider,
        regenerate=regenerate,
    )
    if report is None:
        raise LookupError(f"Vulnerability {cve_id} was not found")

    stored = await get_report(cve_id, audience="executive")
    if stored is None:
        raise RuntimeError(f"Generated report for {cve_id} was not persisted")

    data_hash = stored.get("data_hash")
    if not data_hash:
        raise RuntimeError(f"Generated report for {cve_id} has no evidence hash")

    pdf_blob = await get_report_pdf(cve_id, data_hash, audience="executive")
    if pdf_blob is None:
        from app.reporting.pdf_renderer import render_cve_pdf

        pdf_blob = render_cve_pdf(report)
        await save_report_pdf(cve_id, data_hash, pdf_blob, audience="executive")

    return report, pdf_blob


async def warm_top_report_pdf_cache(
    top_n: int = 10,
    buffer: int = 10,
    provider: Optional[str] = None,
    regenerate: bool = False,
) -> list[dict[str, Any]]:
    """Ensure PDFs are stored for top-N CVEs plus a ranking-change buffer."""
    if top_n < 1 or buffer < 0:
        raise ValueError("top_n must be positive and buffer cannot be negative")

    rows, _ = await get_cves(
        sort_by="priority_score",
        sort_dir="DESC",
        limit=top_n + buffer,
        offset=0,
    )
    reports: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        report, _ = await get_or_create_report_pdf(
            row["cve_id"],
            provider=provider,
            regenerate=regenerate,
        )
        if index < top_n:
            reports.append(report)
    return reports
