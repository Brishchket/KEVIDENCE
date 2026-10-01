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

    @staticmethod
    def _recommended_action(ev: dict) -> str:
        action_parts = [(ev.get("recommended_action") or "Monitor for changes.").rstrip().rstrip(".")]
        kev = ev.get("kev", {})
        if kev.get("in_kev"):
            required_action = kev.get("required_action")
            if required_action and required_action not in " ".join(action_parts):
                action_parts.append(f"CISA KEV requires {required_action.rstrip().rstrip('.')}")
            due_date = kev.get("due_date")
            if due_date and due_date not in " ".join(action_parts):
                action_parts.append(f"complete remediation by {due_date}")
        patch_references = ev.get("patch_references", [])
        if patch_references and patch_references[0] not in " ".join(action_parts):
            action_parts.append(f"vendor guidance: {patch_references[0]}")
        return "; ".join(action_parts) + "."

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
        affected = ev.get("affected", {})
        product = affected.get("product") or affected.get("vendor")
        epss = ev.get("epss", {})
        epss_prob = epss.get("probability")
        kev = ev.get("kev", {})
        recommended = self._recommended_action(ev)

        subject = f"{product} ({cve_id})" if product else cve_id
        parts = [f"{subject} is rated {label} priority by PhantomPatch."]
        if kev.get("in_kev"):
            parts.append("CISA lists this vulnerability among those known to be exploited, making remediation time-sensitive.")
        elif epss_prob is not None and epss_prob > 0:
            parts.append(f"The current estimate is a {epss_prob:.2%} chance of exploitation within 30 days.")
        if kev.get("due_date") and kev["due_date"] not in recommended:
            parts.append(f"The KEV remediation deadline is {kev['due_date']}.")
        parts.append(f"Next step: {recommended}")

        if self._inject_unsupported:
            parts.append("This vulnerability has been used by APT29 in attacks against government agencies.")

        return " ".join(parts)

    def _analyst_narrative(self, ev: dict) -> str:
        cve_id = ev.get("cve_id", "Unknown CVE")
        cvss = ev.get("cvss", {})
        cvss_score = cvss.get("score")
        severity = cvss.get("severity")
        attack_vector = cvss.get("attack_vector")
        cwe_list = ev.get("cwe", [])
        epss = ev.get("epss", {})
        epss_prob = epss.get("probability")
        epss_pctl = epss.get("percentile")
        kev = ev.get("kev", {})
        priority = ev.get("priority", {})
        label = priority.get("label", "LOW")
        description = ev.get("description")
        recommended = self._recommended_action(ev)

        parts = [f"{cve_id} is {label} priority."]

        if description:
            parts.append(f"Reported mechanism and impact: {description}")
        if cvss_score is not None:
            severity_text = f" ({severity})" if severity else ""
            vector_text = f"; attack vector {attack_vector}" if attack_vector else ""
            cwe_text = f"; weakness {', '.join(cwe_list)}" if cwe_list else ""
            parts.append(f"CVSS severity is {cvss_score}{severity_text}{vector_text}{cwe_text}.")
        elif cwe_list:
            parts.append(f"Weakness classification: {', '.join(cwe_list)}.")
        if epss_prob is not None and epss_prob > 0:
            pctl_str = f"; percentile {epss_pctl:.1%}" if epss_pctl is not None else ""
            parts.append(f"EPSS estimates {epss_prob:.2%} exploitation probability in 30 days{pctl_str}.")
        if kev.get("in_kev"):
            date_str = f" on {kev['date_added']}" if kev.get("date_added") else ""
            kev_sentence = f"CISA KEV confirms known exploitation{date_str}."
            if kev.get("known_ransomware_use"):
                kev_sentence = kev_sentence[:-1] + (
                    f"; known ransomware use: {kev['known_ransomware_use']}."
                )
            parts.append(kev_sentence)
        parts.append(f"Remediation: {recommended}")

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
        recommended = self._recommended_action(ev)
        priority = ev.get("priority", {})
        label = priority.get("label", "LOW")

        parts = [f"{cve_id} requires attention at {label} priority level."]

        if vendor and product:
            parts.append(f"The affected product is {product} by {vendor}.")
        elif product:
            parts.append(f"The affected product is {product}.")
        elif vendor:
            parts.append(f"The affected vendor is {vendor}.")

        if kev.get("due_date") and kev["due_date"] not in recommended:
            parts.append(f"The KEV remediation due date is {kev['due_date']}.")
        if kev.get("required_action") and kev["required_action"] not in recommended:
            parts.append(f"Required action: {kev['required_action']}.")

        if patch_refs and patch_refs[0] not in recommended:
            parts.append(f"A patch or advisory is available at: {patch_refs[0]}.")

        parts.append(f"Recommended action: {recommended}")

        if self._inject_unsupported:
            parts.append("The patch has been confirmed to cause system instability in production environments.")

        return " ".join(parts)
