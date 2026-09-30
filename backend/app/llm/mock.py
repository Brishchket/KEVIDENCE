"""
mock.py — Deterministic mock LLM provider for testing.

Template-based narratives that use evidence data directly.
Supports injecting an unsupported sentence for verifier testing.
"""
from __future__ import annotations

from app.llm.base import LLMClient
from app.schemas import Evidence


class MockLLMClient(LLMClient):
    """
    Deterministic template-based LLM for pipeline testing.
    No API key required. Produces evidence-grounded narratives from templates.
    """

    def __init__(self, inject_unsupported: bool = False):
        self._inject_unsupported = inject_unsupported

    @property
    def provider_name(self) -> str:
        return "mock"

    @property
    def model_name(self) -> str:
        return "mock-template-v1"

    async def generate(self, system: str, user: str) -> str:
        """
        Parse the evidence from the user prompt and generate a template narrative.
        Determines audience from the system prompt content.
        """
        import json

        # Extract evidence JSON from user prompt
        evidence_dict = {}
        try:
            # Find JSON block in the user prompt
            json_start = user.find("{")
            json_end = user.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                evidence_dict = json.loads(user[json_start:json_end])
        except (json.JSONDecodeError, ValueError):
            pass

        if not evidence_dict:
            return "Unable to generate narrative: no evidence data provided."

        # Determine audience from system prompt
        if "Business Manager" in system or "manager" in system.lower():
            return self._manager_narrative(evidence_dict)
        elif "Security Analyst" in system or "analyst" in system.lower():
            return self._analyst_narrative(evidence_dict)
        elif "IT Administrator" in system or "it_admin" in system.lower() or "admin" in system.lower():
            return self._it_admin_narrative(evidence_dict)
        else:
            return self._manager_narrative(evidence_dict)

    def _manager_narrative(self, ev: dict) -> str:
        cve_id = ev.get("cve_id", "Unknown CVE")
        priority = ev.get("priority", {})
        label = priority.get("label", "LOW")
        score = priority.get("score", 0)
        cvss = ev.get("cvss", {})
        cvss_score = cvss.get("score")
        epss = ev.get("epss", {})
        epss_prob = epss.get("probability")
        kev = ev.get("kev", {})
        recommended = ev.get("recommended_action", "Monitor for changes.")

        parts = [f"{cve_id} has been assessed as {label} priority with a score of {score:.4f}."]

        if cvss_score is not None:
            parts.append(f"The vulnerability has a severity score of {cvss_score} out of 10.")
        if epss_prob is not None and epss_prob > 0:
            parts.append(f"There is a {epss_prob:.2%} probability of exploitation in the next 30 days.")
        if kev.get("in_kev"):
            parts.append("This vulnerability is confirmed to be actively exploited in the wild.")
        parts.append(f"Recommended action: {recommended}")

        if self._inject_unsupported:
            parts.append("This vulnerability has been used by APT29 in attacks against government agencies.")

        return " ".join(parts)

    def _analyst_narrative(self, ev: dict) -> str:
        cve_id = ev.get("cve_id", "Unknown CVE")
        cvss = ev.get("cvss", {})
        cvss_score = cvss.get("score")
        vector = cvss.get("vector")
        attack_vector = cvss.get("attack_vector")
        cwe_list = ev.get("cwe", [])
        epss = ev.get("epss", {})
        epss_prob = epss.get("probability")
        epss_pctl = epss.get("percentile")
        kev = ev.get("kev", {})
        priority = ev.get("priority", {})
        label = priority.get("label", "LOW")

        parts = [f"{cve_id} is rated {label} priority."]

        if cvss_score is not None and vector:
            parts.append(f"CVSS base score is {cvss_score} with vector {vector}.")
        if attack_vector:
            parts.append(f"The attack vector is {attack_vector}.")
        if cwe_list:
            parts.append(f"Classified under {', '.join(cwe_list)}.")
        if epss_prob is not None and epss_prob > 0:
            pctl_str = f" (percentile: {epss_pctl:.4f})" if epss_pctl else ""
            parts.append(f"EPSS probability is {epss_prob:.4f}{pctl_str}.")
        if kev.get("in_kev"):
            date_str = f" on {kev['date_added']}" if kev.get("date_added") else ""
            ransomware = f" Known ransomware campaign use: {kev['known_ransomware_use']}." if kev.get("known_ransomware_use") else ""
            parts.append(f"Listed in CISA KEV catalog{date_str}.{ransomware}")

        if self._inject_unsupported:
            parts.append("The exploit code is publicly available on GitHub and has been weaponized.")

        return " ".join(parts)

    def _it_admin_narrative(self, ev: dict) -> str:
        cve_id = ev.get("cve_id", "Unknown CVE")
        affected = ev.get("affected", {})
        vendor = affected.get("vendor")
        product = affected.get("product")
        kev = ev.get("kev", {})
        patch_refs = ev.get("patch_references", [])
        recommended = ev.get("recommended_action", "Monitor for changes.")
        priority = ev.get("priority", {})
        label = priority.get("label", "LOW")

        parts = [f"{cve_id} requires attention at {label} priority level."]

        if vendor and product:
            parts.append(f"The affected product is {product} by {vendor}.")
        elif product:
            parts.append(f"The affected product is {product}.")
        elif vendor:
            parts.append(f"The affected vendor is {vendor}.")

        if kev.get("due_date"):
            parts.append(f"The KEV remediation due date is {kev['due_date']}.")
        if kev.get("required_action"):
            parts.append(f"Required action: {kev['required_action']}")

        if patch_refs:
            parts.append(f"A patch or advisory is available at: {patch_refs[0]}")

        parts.append(f"Recommended action: {recommended}")

        if self._inject_unsupported:
            parts.append("The patch has been confirmed to cause system instability in production environments.")

        return " ".join(parts)
