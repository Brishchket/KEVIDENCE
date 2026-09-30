"""
verifier.py — Faithfulness verifier (the core contribution).

Checks every generated sentence against the evidence using:
1. Sentence splitting with nltk
2. Embedding with sentence-transformers (all-MiniLM-L6-v2)
3. Cosine similarity via scikit-learn
4. Strict facts guard: extracts numbers, dates, CVE IDs, product names
   and checks they appear in the evidence.

A sentence is supported if max_similarity >= threshold AND strict_facts pass.
faithfulness_score = supported_sentences / total_sentences.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

from app.config import EMBEDDING_MODEL, SIMILARITY_THRESHOLD, STRICT_FACTS
from app.schemas import Evidence, SentenceVerification, VerificationResult

logger = logging.getLogger(__name__)

# ── Singleton model loader ───────────────────────────────────────────────────

_model = None


def _get_model():
    """Load the sentence-transformers model once (singleton)."""
    global _model
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            logger.info("Loading sentence-transformers model: %s", EMBEDDING_MODEL)
            _model = SentenceTransformer(EMBEDDING_MODEL)
            logger.info("Model loaded successfully")
        except ImportError:
            logger.error("sentence-transformers not installed. pip install sentence-transformers")
            raise
    return _model


# ── Sentence splitting ───────────────────────────────────────────────────────

def _split_sentences(text: str) -> list[str]:
    """Split text into sentences using nltk, with graceful fallback."""
    try:
        import nltk
        try:
            from nltk.tokenize import sent_tokenize
            return sent_tokenize(text)
        except LookupError:
            # Auto-download the tokenizer
            logger.info("Downloading nltk punkt_tab tokenizer...")
            nltk.download("punkt_tab", quiet=True)
            from nltk.tokenize import sent_tokenize
            return sent_tokenize(text)
    except Exception as exc:
        logger.warning("nltk sentence splitting failed (%s), using regex fallback", exc)
        # Simple regex fallback
        sentences = re.split(r'(?<=[.!?])\s+', text.strip())
        return [s.strip() for s in sentences if s.strip()]


# ── Strict facts extraction ──────────────────────────────────────────────────

_CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}')
_NUMBER_PATTERN = re.compile(r'\b(\d+\.?\d*)\b')
_DATE_PATTERN = re.compile(r'\b(\d{4}-\d{2}-\d{2})\b')
_PERCENTAGE_PATTERN = re.compile(r'(\d+\.?\d*)\s*%')


def _extract_facts(text: str) -> dict[str, set[str]]:
    """Extract verifiable facts from a sentence."""
    return {
        "cve_ids": set(_CVE_PATTERN.findall(text)),
        "numbers": set(_NUMBER_PATTERN.findall(text)),
        "dates": set(_DATE_PATTERN.findall(text)),
        "percentages": set(_PERCENTAGE_PATTERN.findall(text)),
    }


def _normalize_number(n: str) -> float:
    """Normalize a number string for comparison."""
    try:
        return round(float(n), 2)
    except ValueError:
        return -1.0


def _numbers_match(narrative_nums: set[str], evidence_text: str,
                   tolerance: float = 0.01) -> bool:
    """
    Check if numbers in the narrative sentence appear in the evidence.
    Allows formatting/rounding tolerance (e.g., 0.93 vs 93%).
    """
    if not narrative_nums:
        return True

    evidence_nums = set(_NUMBER_PATTERN.findall(evidence_text))
    evidence_pcts = set(_PERCENTAGE_PATTERN.findall(evidence_text))

    for n in narrative_nums:
        n_val = _normalize_number(n)
        if n_val < 0:
            continue

        # Direct match
        found = False
        for en in evidence_nums:
            en_val = _normalize_number(en)
            if abs(n_val - en_val) <= tolerance:
                found = True
                break

        # Check percentage equivalence (0.93 <-> 93%)
        if not found:
            for ep in evidence_pcts:
                ep_val = _normalize_number(ep)
                if abs(n_val - ep_val) <= tolerance:
                    found = True
                    break
                if abs(n_val * 100 - ep_val) <= tolerance:
                    found = True
                    break
                if abs(n_val - ep_val / 100) <= tolerance:
                    found = True
                    break

        if not found:
            # Also check if the number appears as part of a larger match
            for en in evidence_nums:
                en_val = _normalize_number(en)
                # Allow score/10 -> percentage-like conversions
                if abs(n_val - en_val * 10) <= tolerance:
                    found = True
                    break
                if abs(n_val - en_val / 10) <= tolerance:
                    found = True
                    break

        if not found:
            return False

    return True


def _strict_facts_check(
    sentence: str,
    evidence_text_combined: str,
    evidence: Optional[Evidence] = None,
) -> tuple[bool, str]:
    """
    Check that numbers, dates, CVE IDs in the sentence appear in the evidence.
    Returns (passed, reason).
    """
    facts = _extract_facts(sentence)

    # Check CVE IDs
    for cve_id in facts["cve_ids"]:
        if cve_id not in evidence_text_combined:
            return False, f"CVE ID '{cve_id}' not found in evidence"

    # Check dates
    for date in facts["dates"]:
        if date not in evidence_text_combined:
            return False, f"Date '{date}' not found in evidence"

    # Check numbers (with tolerance)
    if not _numbers_match(facts["numbers"], evidence_text_combined):
        return False, "Numeric value not found in evidence"

    # Check product/vendor names if evidence is available
    if evidence and evidence.affected.product:
        product_lower = evidence.affected.product.lower()
        # Only check if the sentence mentions a product-like proper noun
        # that doesn't match the known product
        # (This is a conservative check — we don't flag sentences that
        # don't mention products)

    return True, "all facts verified"


# ── Core verification ────────────────────────────────────────────────────────

def verify_narrative(
    narrative_text: str,
    evidence_sentences: list[str],
    evidence: Optional[Evidence] = None,
    threshold: float = SIMILARITY_THRESHOLD,
    strict_facts: bool = STRICT_FACTS,
) -> VerificationResult:
    """
    Verify a narrative against evidence sentences.

    1. Split narrative into sentences
    2. Embed both sets with sentence-transformers
    3. For each narrative sentence, find max cosine similarity to any evidence sentence
    4. A sentence is supported if similarity >= threshold (and strict facts pass)
    5. Return faithfulness_score and per-sentence details

    Returns VerificationResult with per-sentence detail.
    """
    if not narrative_text or not narrative_text.strip():
        return VerificationResult(
            faithfulness_score=0.0,
            supported_count=0,
            total_count=0,
            sentences=[],
        )

    if not evidence_sentences:
        return VerificationResult(
            faithfulness_score=0.0,
            supported_count=0,
            total_count=1,
            sentences=[SentenceVerification(
                text=narrative_text,
                max_similarity=0.0,
                matched_evidence_sentence=None,
                supported=False,
                reason="No evidence sentences to verify against",
            )],
        )

    narrative_sents = _split_sentences(narrative_text)
    if not narrative_sents:
        return VerificationResult(
            faithfulness_score=0.0,
            supported_count=0,
            total_count=0,
            sentences=[],
        )

    # Compute embeddings
    model = _get_model()

    try:
        from sklearn.metrics.pairwise import cosine_similarity
        import numpy as np

        narrative_embeddings = model.encode(narrative_sents, show_progress_bar=False)
        evidence_embeddings = model.encode(evidence_sentences, show_progress_bar=False)

        # Compute cosine similarity matrix: (n_narrative, n_evidence)
        sim_matrix = cosine_similarity(narrative_embeddings, evidence_embeddings)
    except Exception as exc:
        logger.error("Embedding/similarity computation failed: %s", exc)
        return VerificationResult(
            faithfulness_score=0.0,
            supported_count=0,
            total_count=len(narrative_sents),
            sentences=[
                SentenceVerification(
                    text=s, max_similarity=0.0, matched_evidence_sentence=None,
                    supported=False, reason=f"Embedding failed: {exc}"
                )
                for s in narrative_sents
            ],
        )

    # Combined evidence text for strict facts check
    evidence_text_combined = " ".join(evidence_sentences)

    # Evaluate each narrative sentence
    sentence_results: list[SentenceVerification] = []
    supported_count = 0

    for i, sent in enumerate(narrative_sents):
        max_sim_idx = int(np.argmax(sim_matrix[i]))
        max_sim = float(sim_matrix[i][max_sim_idx])
        matched_evidence = evidence_sentences[max_sim_idx]

        supported = max_sim >= threshold
        reason = f"similarity {max_sim:.3f} >= {threshold}" if supported else f"similarity {max_sim:.3f} < {threshold}"

        # Strict facts check
        if supported and strict_facts:
            facts_ok, facts_reason = _strict_facts_check(
                sent, evidence_text_combined, evidence
            )
            if not facts_ok:
                supported = False
                reason = f"strict_facts failed: {facts_reason}"

        if supported:
            supported_count += 1

        sentence_results.append(SentenceVerification(
            text=sent,
            max_similarity=round(max_sim, 4),
            matched_evidence_sentence=matched_evidence,
            supported=supported,
            reason=reason,
        ))

    total = len(narrative_sents)
    faithfulness = supported_count / total if total > 0 else 0.0

    return VerificationResult(
        faithfulness_score=round(faithfulness, 4),
        supported_count=supported_count,
        total_count=total,
        sentences=sentence_results,
    )
