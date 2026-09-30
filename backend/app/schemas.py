"""
schemas.py — Pydantic v2 models for PhantomPatch.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


# ── CVSS ─────────────────────────────────────────────────────────────────────
class CVSSDetail(BaseModel):
    score: Optional[float] = None
    severity: Optional[str] = None
    vector: Optional[str] = None
    attack_vector: Optional[str] = None


# ── EPSS ─────────────────────────────────────────────────────────────────────
class EPSSDetail(BaseModel):
    probability: Optional[float] = None
    percentile: Optional[float] = None


# ── KEV ──────────────────────────────────────────────────────────────────────
class KEVDetail(BaseModel):
    in_kev: bool = False
    date_added: Optional[str] = None
    due_date: Optional[str] = None
    required_action: Optional[str] = None
    known_ransomware_use: Optional[str] = None


# ── Affected ─────────────────────────────────────────────────────────────────
class AffectedDetail(BaseModel):
    vendor: Optional[str] = None
    product: Optional[str] = None


# ── Priority ─────────────────────────────────────────────────────────────────
class PriorityBreakdown(BaseModel):
    cvss_contribution: float = 0.0
    epss_contribution: float = 0.0
    kev_contribution: float = 0.0


class PriorityDetail(BaseModel):
    score: float = 0.0
    label: str = "LOW"
    breakdown: PriorityBreakdown = Field(default_factory=PriorityBreakdown)
    missing_signals: list[str] = Field(default_factory=list)


# ── Evidence (the core model) ────────────────────────────────────────────────
class Evidence(BaseModel):
    cve_id: str
    description: Optional[str] = None
    cvss: CVSSDetail = Field(default_factory=CVSSDetail)
    cwe: list[str] = Field(default_factory=list)
    epss: EPSSDetail = Field(default_factory=EPSSDetail)
    kev: KEVDetail = Field(default_factory=KEVDetail)
    affected: AffectedDetail = Field(default_factory=AffectedDetail)
    priority: PriorityDetail = Field(default_factory=PriorityDetail)
    reasons: list[str] = Field(default_factory=list)
    recommended_action: Optional[str] = None
    patch_references: list[str] = Field(default_factory=list)
    published_date: Optional[str] = None
    modified_date: Optional[str] = None


# ── Verification ─────────────────────────────────────────────────────────────
class SentenceVerification(BaseModel):
    text: str
    max_similarity: float = 0.0
    matched_evidence_sentence: Optional[str] = None
    supported: bool = False
    reason: str = ""


class VerificationResult(BaseModel):
    faithfulness_score: float = 0.0
    supported_count: int = 0
    total_count: int = 0
    sentences: list[SentenceVerification] = Field(default_factory=list)


# ── Narrative ────────────────────────────────────────────────────────────────
class NarrativeRecord(BaseModel):
    cve_id: str
    audience: str
    narrative_text: str
    prompt_version: str = "v1"
    provider: str = "mock"
    model: str = ""
    verification: Optional[VerificationResult] = None
    confidence: str = "LOW"
    faithfulness_score: float = 0.0
    attempt_count: int = 1
    created_at: Optional[str] = None


# ── API Response Models ──────────────────────────────────────────────────────
class HealthResponse(BaseModel):
    status: str = "ok"


class CVEListItem(BaseModel):
    cve_id: str
    description: Optional[str] = None
    cvss_base_score: Optional[float] = None
    severity: Optional[str] = None
    epss_score: Optional[float] = None
    in_kev: bool = False
    priority_score: float = 0.0
    priority_label: str = "LOW"
    published_date: Optional[str] = None
    vendors: list[str] = Field(default_factory=list)


class CVEListResponse(BaseModel):
    total: int = 0
    offset: int = 0
    limit: int = 20
    items: list[CVEListItem] = Field(default_factory=list)


class StatsResponse(BaseModel):
    total_cves: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    kev_count: int = 0
    mean_epss: float = 0.0
    mean_faithfulness: float = 0.0
    parse_rate: float = 0.0


class IngestStatusResponse(BaseModel):
    status: str = "idle"
    run_id: Optional[int] = None
    cves_fetched: int = 0
    inserted: int = 0
    updated: int = 0
    parse_failures: int = 0
    parse_rate: float = 0.0


class CompareResponse(BaseModel):
    cve_id: str
    raw_description: Optional[str] = None
    generic_llm_narrative: Optional[str] = None
    phantompatch_narrative: Optional[str] = None
    raw_flesch: Optional[float] = None
    generic_flesch: Optional[float] = None
    phantompatch_flesch: Optional[float] = None
    raw_unsupported_rate: Optional[float] = None
    generic_unsupported_rate: Optional[float] = None
    phantompatch_unsupported_rate: Optional[float] = None


class SurveyItem(BaseModel):
    item_id: str
    cve_id: str
    condition: str
    narrative_text: str


class SurveyResponseInput(BaseModel):
    item_id: str
    rater_id: str
    clarity_rating: int = Field(ge=1, le=5)
    would_act: Optional[bool] = None


class EvalSummaryResponse(BaseModel):
    metrics: dict = Field(default_factory=dict)
    targets: dict = Field(default_factory=dict)
    pass_fail: dict = Field(default_factory=dict)
