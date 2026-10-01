"""
generator.py — Narrative generation pipeline.

Combines: LLM generation → verification → retry loop → confidence labeling.
The risk decision is made by code (evidence + scorer), not the LLM.
The LLM only explains, and the verifier checks it.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from app.config import (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    LLM_PROVIDER,
    MAX_RETRIES,
    RETRY_BELOW,
)
from app.db import upsert_narrative
from app.evidence.verbalizer import verbalize
from app.llm.base import LLMClient
from app.llm.mock import MockLLMClient
from app.llm.prompts import (
    PROMPT_VERSION,
    get_retry_prompt,
    get_system_prompt,
    get_user_prompt,
    normalize_audience,
)
from app.schemas import Evidence, NarrativeRecord, VerificationResult
from app.verification.verifier import verify_narrative

logger = logging.getLogger(__name__)


def get_llm_client(provider: Optional[str] = None) -> LLMClient:
    """Factory: create the LLM client based on config or override."""
    p = (provider or LLM_PROVIDER).lower()
    if p == "mock":
        return MockLLMClient()
    elif p == "gemini":
        from app.llm.gemini import GeminiClient
        return GeminiClient()
    elif p == "openai":
        from app.llm.openai import OpenAIClient
        return OpenAIClient()
    elif p == "anthropic":
        from app.llm.anthropic import AnthropicClient
        return AnthropicClient()
    else:
        logger.warning("Unknown LLM provider '%s', falling back to mock", p)
        return MockLLMClient()


def _confidence_label(faithfulness_score: float) -> str:
    """Derive confidence label from faithfulness score only."""
    if faithfulness_score >= CONFIDENCE_HIGH:
        return "HIGH"
    elif faithfulness_score >= CONFIDENCE_MEDIUM:
        return "MEDIUM"
    else:
        return "LOW"


async def generate_narrative(
    evidence: Evidence,
    audience: str,
    llm_client: Optional[LLMClient] = None,
    regenerate: bool = False,
) -> NarrativeRecord:
    """
    Generate a narrative for a CVE and audience, with verification and retry.

    1. Generate narrative from LLM (or mock)
    2. Verify against evidence
    3. If faithfulness < RETRY_BELOW, retry with flagged sentences (up to MAX_RETRIES)
    4. Assign confidence label from faithfulness score
    5. Cache in SQLite

    Returns the NarrativeRecord with verification details.
    """
    if llm_client is None:
        llm_client = get_llm_client()

    audience_key = normalize_audience(audience)

    evidence_json = evidence.model_dump_json(indent=2)
    evidence_sentences = verbalize(evidence)

    system_prompt = get_system_prompt(audience_key)
    user_prompt = get_user_prompt(audience_key, evidence_json)

    best_narrative: Optional[str] = None
    best_verification: Optional[VerificationResult] = None
    best_faithfulness = 0.0
    attempt_count = 0

    for attempt in range(1 + MAX_RETRIES):
        attempt_count = attempt + 1
        logger.info("Generating %s narrative for %s (attempt %d)",
                     audience_key, evidence.cve_id, attempt_count)

        try:
            if attempt == 0:
                narrative_text = await llm_client.generate(system_prompt, user_prompt)
            else:
                # Retry with flagged sentences
                flagged = [s.text for s in best_verification.sentences if not s.supported] if best_verification else []
                retry_prompt = get_retry_prompt(
                    evidence_json,
                    flagged,
                    audience=audience_key,
                    previous_narrative=best_narrative,
                )
                narrative_text = await llm_client.generate(system_prompt, retry_prompt)
        except Exception as exc:
            logger.error("LLM generation failed for %s (%s): %s",
                         evidence.cve_id, audience_key, exc)
            narrative_text = f"Narrative generation failed: {exc}"

        # Verify
        verification = verify_narrative(narrative_text, evidence_sentences, evidence)
        faithfulness = verification.faithfulness_score

        logger.info("Verification: faithfulness=%.3f (attempt %d)", faithfulness, attempt_count)

        # Keep the best attempt
        if faithfulness > best_faithfulness:
            best_narrative = narrative_text
            best_verification = verification
            best_faithfulness = faithfulness

        # If good enough, stop retrying
        if faithfulness >= RETRY_BELOW:
            logger.info("Faithfulness %.3f >= %.3f threshold, accepted", faithfulness, RETRY_BELOW)
            break
        else:
            logger.info("Faithfulness %.3f < %.3f, %s",
                         faithfulness, RETRY_BELOW,
                         "retrying..." if attempt < MAX_RETRIES else "giving up")

    confidence = _confidence_label(best_faithfulness)

    record = NarrativeRecord(
        cve_id=evidence.cve_id,
        audience=audience_key,
        narrative_text=best_narrative or "",
        prompt_version=PROMPT_VERSION,
        provider=llm_client.provider_name,
        model=llm_client.model_name,
        verification=best_verification,
        confidence=confidence,
        faithfulness_score=best_faithfulness,
        attempt_count=attempt_count,
    )

    # Cache to DB
    await upsert_narrative({
        "cve_id": record.cve_id,
        "audience": record.audience,
        "narrative_text": record.narrative_text,
        "prompt_version": record.prompt_version,
        "provider": record.provider,
        "model": record.model,
        "verification": record.verification.model_dump() if record.verification else {},
        "confidence": record.confidence,
        "faithfulness_score": record.faithfulness_score,
        "attempt_count": record.attempt_count,
    })

    return record


async def generate_all_audiences(
    evidence: Evidence,
    llm_client: Optional[LLMClient] = None,
    audiences: Optional[list[str]] = None,
) -> list[NarrativeRecord]:
    """Generate narratives for all (or specified) audiences."""
    if audiences is None:
        audiences = ["manager", "analyst", "it_admin"]

    results = []
    for audience in audiences:
        record = await generate_narrative(evidence, audience, llm_client)
        results.append(record)

    return results
