"""
verbalizer.py — Convert an Evidence object into a list of plain sentences.

Each sentence states one fact from the evidence. These sentences are used
by the faithfulness verifier as the ground-truth reference set.
"""
from __future__ import annotations

from app.schemas import Evidence


def verbalize(evidence: Evidence) -> list[str]:
    """
    Convert an Evidence object into a list of plain-English sentences,
    one per fact. Used by the verifier to check narrative faithfulness.
    """
    sentences: list[str] = []

    # CVE ID
    sentences.append(f"This vulnerability is identified as {evidence.cve_id}.")

    # Description
    if evidence.description:
        sentences.append(f"Description: {evidence.description}")

    # CVSS
    if evidence.cvss.score is not None:
        sev = evidence.cvss.severity or "unspecified severity"
        sentences.append(
            f"The CVSS base score is {evidence.cvss.score} ({sev})."
        )
    if evidence.cvss.vector:
        sentences.append(f"The CVSS vector string is {evidence.cvss.vector}.")
    if evidence.cvss.attack_vector:
        sentences.append(f"The attack vector is {evidence.cvss.attack_vector}.")

    # CWE
    for cwe in evidence.cwe:
        sentences.append(f"The vulnerability is classified as {cwe}.")

    # EPSS
    if evidence.epss.probability is not None and evidence.epss.probability > 0:
        pct = evidence.epss.probability * 100
        sentences.append(
            f"The EPSS probability is {evidence.epss.probability:.4f} ({pct:.1f}%)."
        )
    if evidence.epss.percentile is not None and evidence.epss.percentile > 0:
        sentences.append(
            f"The EPSS percentile is {evidence.epss.percentile:.4f} "
            f"({evidence.epss.percentile * 100:.1f}%)."
        )

    # KEV
    if evidence.kev.in_kev:
        sentences.append(
            "This vulnerability is listed in the CISA Known Exploited Vulnerabilities catalog."
        )
        if evidence.kev.date_added:
            sentences.append(f"It was added to the KEV catalog on {evidence.kev.date_added}.")
        if evidence.kev.due_date:
            sentences.append(f"The KEV remediation due date is {evidence.kev.due_date}.")
        if evidence.kev.required_action:
            sentences.append(f"The required action is: {evidence.kev.required_action}")
        if evidence.kev.known_ransomware_use:
            sentences.append(
                f"Known ransomware campaign use: {evidence.kev.known_ransomware_use}."
            )

    # Affected
    if evidence.affected.vendor:
        sentences.append(f"The affected vendor is {evidence.affected.vendor}.")
    if evidence.affected.product:
        sentences.append(f"The affected product is {evidence.affected.product}.")

    # Priority
    sentences.append(
        f"The PhantomPatch priority score is {evidence.priority.score:.4f} "
        f"(label: {evidence.priority.label})."
    )
    bd = evidence.priority.breakdown
    sentences.append(
        f"Score breakdown: CVSS contribution {bd.cvss_contribution:.4f}, "
        f"EPSS contribution {bd.epss_contribution:.4f}, "
        f"KEV contribution {bd.kev_contribution:.4f}."
    )

    # Reasons
    for reason in evidence.reasons:
        sentences.append(f"Reason: {reason}")

    # Recommended action
    if evidence.recommended_action:
        sentences.append(f"Recommended action: {evidence.recommended_action}")

    # Patch references
    for ref in evidence.patch_references:
        sentences.append(f"A patch or advisory is available at: {ref}")

    # Published date
    if evidence.published_date:
        sentences.append(f"The vulnerability was published on {evidence.published_date}.")

    return sentences
