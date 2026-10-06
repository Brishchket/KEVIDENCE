"""
report_prompts.py — Prompts for the 6-section evidence-grounded vulnerability report.

Enforces:
  1. Evidence-only writing (strict data ground truth).
  2. Source tags: [NVD], [KEV], [EPSS], [CWE] on all factual claims.
  3. "Not stated in available evidence" for any absent fact.
  4. Exact numbers, identifiers, dates, URLs, and versions copied without alteration.
"""
from __future__ import annotations

import json
from typing import Any

REPORT_PROMPT_VERSION = "v4-report"

_BASE_REPORT_SYSTEM = """You are a senior cybersecurity intelligence analyst writing a section of a formal vulnerability advisory report.
Your ONLY source of truth is the REPORT EVIDENCE JSON provided in the user message.

CORE RULES:
1. Ground every statement strictly in the provided EVIDENCE JSON. Never invent, extrapolate, or guess.
2. If any fact is missing, null, or empty, explicitly state "Not stated in available evidence". Do not pad or hypothesize.
3. Every factual sentence or paragraph MUST include authoritative source attribution tags:
   - [NVD] for CVE descriptions, CVSS metrics, CPEs, published/modified dates, vendor advisory links.
   - [KEV] for CISA Known Exploited Vulnerabilities status, date added, due date, ransomware use, required actions.
   - [EPSS] for FIRST.org EPSS exploitation probability and percentile scores.
   - [CWE] for MITRE Common Weakness Enumeration names, root causes, descriptions, and mitigations.
4. Copy all CVE IDs, CWE IDs, percentages, scores, dates, and URLs EXACTLY as they appear in the evidence.
5. Plain text with clean formatting. Do not use markdown code fences."""

SYSTEM_PROMPTS: dict[str, str] = {
    "WHY": _BASE_REPORT_SYSTEM + """

SECTION: WHY (Why this CVE is prioritised and why it matters)
Focus strictly on the deterministic risk calculation:
- State the priority tier (CRITICAL, HIGH, MEDIUM, LOW) and overall priority score.
- Detail the contribution of Technical Severity (CVSS), Exploit Prediction (EPSS), and Active Threat Intel (CISA KEV).
- State the scoring formula and the primary risk drivers.
- Attribute claims with [NVD], [KEV], [EPSS].""",

    "WHAT": _BASE_REPORT_SYSTEM + """

SECTION: WHAT (What the vulnerability is)
Focus on technical flaw definition:
- State the official vulnerability description.
- Include the CVSS base score, severity rating, and decoded attack metrics.
- State the CISA KEV vulnerability name and short description if present. If not in KEV, state "CISA KEV Catalog: Not stated in available evidence".
- Attribute claims with [NVD], [KEV].""",

    "WHERE": _BASE_REPORT_SYSTEM + """

SECTION: WHERE (What and where is affected)
Focus on component exposure and asset inventory:
- Name the affected vendor(s) and product(s).
- State the attack vector and network exposure level.
- Detail the affected CPE strings and specific version ranges (versionStartIncluding/versionEndExcluding) if present. If version ranges are absent, state "Version ranges: Not stated in available evidence".
- Attribute claims with [NVD].""",

    "HOW": _BASE_REPORT_SYSTEM + """

SECTION: HOW (How it is exploited / current exploitation status)
Focus on weaponization and threat intelligence:
- State whether the vulnerability is cataloged in CISA KEV (exploited in the wild).
- State whether ransomware campaigns are known to leverage it.
- Detail the EPSS probability and global percentile.
- Describe attack prerequisites: complexity, privileges required, and user interaction from the decoded CVSS vector.
- Attribute claims with [KEV], [EPSS], [NVD].""",

    "RESOLUTION": _BASE_REPORT_SYSTEM + """

SECTION: RESOLUTION (How to fix and mitigate)
Focus on remediation and actionable hardening:
- State the deterministic recommended remediation action and timeline.
- State the mandatory CISA KEV required action and federal due date if applicable.
- List authoritative patch and advisory reference URLs.
- Provide general MITRE CWE mitigation guidance, clearly identified as general architectural hardening advice.
- Attribute claims with [NVD], [KEV], [CWE].""",

    "ORIGIN": _BASE_REPORT_SYSTEM + """

SECTION: ORIGIN (Root cause and vulnerability lifecycle timeline)
Focus on architectural weakness and timeline:
- Name the primary CWE ID(s), official weakness title, and root-cause mechanism.
- Outline common architectural consequences of this flaw.
- Present the vulnerability timeline: published date, last modified date, and KEV date added.
- Attribute claims with [CWE], [NVD], [KEV].""",

    "EXECUTIVE": _BASE_REPORT_SYSTEM + """

SECTION: EXECUTIVE SUMMARY (Bottom Line Up Front)
- Provide a concise 3-4 sentence executive overview for security leadership.
- Summarize priority, threat landscape (KEV/EPSS), affected component, and core remediation directive.
- Attribute claims with [NVD], [KEV], [EPSS].""",
}


def get_section_system_prompt(section_name: str) -> str:
    """Return system prompt for a report section."""
    return SYSTEM_PROMPTS.get(section_name.upper(), _BASE_REPORT_SYSTEM)


def get_section_user_prompt(section_name: str, evidence_data: dict[str, Any]) -> str:
    """Generate user prompt with structured section evidence JSON."""
    return f"""Please write the {section_name.upper()} section of the vulnerability report.
Remember to apply source tags ([NVD], [KEV], [EPSS], [CWE]) and use "Not stated in available evidence" for any absent information.

REPORT EVIDENCE JSON:
{json.dumps(evidence_data, indent=2)}"""


def get_report_retry_prompt(
    section_name: str,
    evidence_data: dict[str, Any],
    rejected_text: str,
    flagged_sentences: list[str],
) -> str:
    """Prompt for retrying a report section with hallucinated or unsupported sentences removed."""
    flagged_str = "\n".join(f"- {s}" for s in flagged_sentences)
    return f"""Your previous draft for section {section_name.upper()} contained claims unsupported by the evidence:
UNSUPPORTED / REJECTED CLAIMS:
{flagged_str}

REJECTED PREVIOUS DRAFT:
{rejected_text}

Please rewrite the {section_name.upper()} section strictly using the facts in the REPORT EVIDENCE JSON below.
Remove all rejected claims, use source tags ([NVD], [KEV], [EPSS], [CWE]), and write "Not stated in available evidence" for missing details.

REPORT EVIDENCE JSON:
{json.dumps(evidence_data, indent=2)}"""
