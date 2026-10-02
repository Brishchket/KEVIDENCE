"use client";
import React, { useState } from "react";
import { fetcher } from "@/lib/api";
import { GeneratedBadge } from "./Badges";
import EvidenceDrawer, { ClaimEvidenceData, EvidenceSourceItem } from "./EvidenceDrawer";
import { Sparkles, RefreshCw, FileText, ExternalLink } from "lucide-react";

export type Sentence = {
  text: string;
  supported: boolean;
  max_similarity: number;
  reason: string;
  matched_evidence_sentence: string | null;
};

export type Narrative = {
  audience: string;
  narrative_text: string;
  confidence: string;
  faithfulness_score: number;
  verification?: {
    sentences?: Sentence[];
    supported_count?: number;
    total_count?: number;
    faithfulness_score?: number;
  };
};

interface NarrativeTabsProps {
  cveId: string;
  initialNarratives: Narrative[];
  evidenceData?: any;
}

export default function NarrativeTabs({ cveId, initialNarratives, evidenceData }: NarrativeTabsProps) {
  const [narratives, setNarratives] = useState<Narrative[]>(initialNarratives);
  const [activeTab, setActiveTab] = useState("manager");
  const [loading, setLoading] = useState(false);
  const [drawerData, setDrawerData] = useState<ClaimEvidenceData | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  // Role tabs without explanatory text (Change 2)
  const tabs = [
    { id: "manager", role: "Business Manager" },
    { id: "analyst", role: "Security Analyst" },
    { id: "it_admin", role: "IT Administrator" },
  ];

  const activeNarrative = narratives.find((n) => n.audience === activeTab);
  const currentTabInfo = tabs.find((t) => t.id === activeTab);

  const generate = async () => {
    setLoading(true);
    try {
      const newNarrative = await fetcher(`/cves/${cveId}/narratives?audience=${activeTab}&regenerate=true`, {
        method: "POST",
      });
      setNarratives((prev) => {
        const copy = [...prev];
        const idx = copy.findIndex((n) => n.audience === activeTab);
        if (idx >= 0) copy[idx] = newNarrative;
        else copy.push(newNarrative);
        return copy;
      });
    } catch (e) {
      alert("Failed to generate narrative from LLM engine.");
    }
    setLoading(false);
  };

  // Helper to construct structured source signals for a claim
  const buildSourcesForSentence = (sent: Sentence): EvidenceSourceItem[] => {
    const textLower = sent.text.toLowerCase();
    const sources: EvidenceSourceItem[] = [];

    // CVSS signal
    if (textLower.includes("cvss") || textLower.includes("severity") || textLower.includes("score") || textLower.includes("critical") || textLower.includes("high")) {
      sources.push({
        sourceName: "NVD (NIST CVSS v3.1)",
        field: "Base Score & Vector",
        value: `${evidenceData?.cvss?.score || "N/A"} (${evidenceData?.cvss?.severity || "Unrated"}) — ${evidenceData?.cvss?.vector || "N/A"}`,
        timestamp: evidenceData?.published_date,
        reliability: "Authoritative",
      });
    }

    // EPSS signal
    if (textLower.includes("epss") || textLower.includes("probability") || textLower.includes("exploit") || textLower.includes("likelihood") || textLower.includes("weapon")) {
      const prob = evidenceData?.epss?.probability !== undefined ? (evidenceData.epss.probability * 100).toFixed(2) + "%" : "0.00%";
      const pctl = evidenceData?.epss?.percentile ? ` (${(evidenceData.epss.percentile * 100).toFixed(0)}th percentile)` : "";
      sources.push({
        sourceName: "FIRST.Org EPSS Model",
        field: "Exploitation Likelihood",
        value: `${prob}${pctl}`,
        timestamp: "2026-09-29T15:38:13+00:00",
        reliability: "Predictive",
      });
    }

    // KEV signal
    if (textLower.includes("kev") || textLower.includes("known exploited") || textLower.includes("cisa") || textLower.includes("wild") || textLower.includes("ransomware") || evidenceData?.kev?.in_kev) {
      sources.push({
        sourceName: "CISA KEV Catalog",
        field: "Active Exploitation Status",
        value: evidenceData?.kev?.in_kev ? `YES (Added: ${evidenceData?.kev?.date_added || "Listed"})` : "NO (Not in KEV Catalog)",
        timestamp: "2026-09-29T00:00:00+00:00",
        reliability: "Federal Mandate",
      });
    }

    // Product / Vendor signal
    if (textLower.includes("product") || textLower.includes("vendor") || textLower.includes("software") || textLower.includes("affect") || textLower.includes("system") || textLower.includes("version")) {
      sources.push({
        sourceName: "NVD CPE Inventory",
        field: "Affected Component",
        value: `${evidenceData?.affected?.vendor || "Vendor"} / ${evidenceData?.affected?.product || "Product"}`,
        timestamp: evidenceData?.published_date,
        reliability: "Catalog Match",
      });
    }

    // Remediation / Patch signal
    if (textLower.includes("patch") || textLower.includes("mitigat") || textLower.includes("remediat") || textLower.includes("action") || textLower.includes("upgrade")) {
      sources.push({
        sourceName: "Vendor Advisory / CISA Guidance",
        field: "Recommended Action",
        value: evidenceData?.recommended_action || "Prioritize patching within regular maintenance.",
        timestamp: evidenceData?.modified_date || evidenceData?.published_date,
        reliability: "Guidance",
      });
    }

    // If no specific keyword triggered, provide primary evidence baseline
    if (sources.length === 0) {
      sources.push({
        sourceName: "KEVIDENCE Deterministic Pipeline",
        field: "Priority Decision",
        value: `Score: ${evidenceData?.priority?.score?.toFixed(3) || "0.000"} (${evidenceData?.priority?.label || "LOW"})`,
        timestamp: evidenceData?.published_date,
        reliability: "Deterministic Engine",
      });
    }

    return sources;
  };

  const handleOpenDrawer = (sent: Sentence) => {
    const sources = buildSourcesForSentence(sent);
    setDrawerData({
      sentenceText: sent.text,
      isSupported: sent.supported,
      similarityScore: sent.max_similarity,
      matchedEvidence: sent.matched_evidence_sentence,
      reason: sent.reason,
      sources,
      cveId,
      audience: currentTabInfo?.role || "Audience",
    });
    setIsDrawerOpen(true);
  };

  return (
    <div className="flex flex-col h-full bg-white dark:bg-[#111827] text-gray-900 dark:text-[#F8FAFC] transition-colors">
      {/* Role Navigation Tabs */}
      <div className="border-b border-gray-200 dark:border-[#273449] bg-gray-50/60 dark:bg-[#0B1120] p-2 sm:p-3 transition-colors">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2" role="tablist">
          {tabs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                role="tab"
                aria-selected={isActive}
                onClick={() => setActiveTab(tab.id)}
                className={`py-3 px-4 rounded-xl text-center font-bold text-sm transition-all duration-150 relative border focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24] ${
                  isActive
                    ? "bg-white dark:bg-[#1E293B] border-gray-300 dark:border-[#334155] shadow-sm text-gray-950 dark:text-[#F8FAFC]"
                    : "bg-white/60 dark:bg-[#172033]/60 border-transparent hover:bg-white dark:hover:bg-[#172033] text-gray-600 dark:text-[#94A3B8] hover:text-gray-900 dark:hover:text-[#F8FAFC]"
                }`}
              >
                <div className="flex items-center justify-center gap-2">
                  <span>{tab.role}</span>
                  {isActive && <span className="w-2 h-2 rounded-full bg-[#ED7D24]" />}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Narrative Body */}
      <div className="p-6">
        {!activeNarrative ? (
          <div className="text-center py-12 bg-gray-50/50 dark:bg-[#0B1120] rounded-2xl border border-dashed border-gray-200 dark:border-[#273449]">
            <div className="w-12 h-12 rounded-2xl bg-orange-50 dark:bg-orange-950/60 text-[#ED7D24] flex items-center justify-center mx-auto mb-3">
              <Sparkles size={24} />
            </div>
            <h4 className="text-base font-bold text-gray-900 dark:text-[#F8FAFC]">No Narrative Generated Yet</h4>
            <p className="text-xs text-gray-500 dark:text-[#94A3B8] mt-1 max-w-md mx-auto mb-5">
              Synthesize a verified, evidence-grounded risk narrative tailored specifically for the {currentTabInfo?.role}.
            </p>
            <button
              onClick={generate}
              disabled={loading}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gray-900 hover:bg-black dark:bg-[#ED7D24] dark:hover:bg-[#D96B16] text-white font-medium text-xs sm:text-sm shadow-sm transition-all disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24]"
            >
              {loading ? (
                <>
                  <RefreshCw size={14} className="animate-spin" />
                  Generating & Verifying...
                </>
              ) : (
                <>
                  <Sparkles size={14} />
                  Generate {currentTabInfo?.role} Narrative
                </>
              )}
            </button>
          </div>
        ) : (
          <div className="space-y-6">
            {/* Header */}
            <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-gray-100 dark:border-[#273449]">
              <div className="flex flex-wrap items-center gap-2">
                <GeneratedBadge role={currentTabInfo?.role} />
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={generate}
                  disabled={loading}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-gray-200 dark:border-[#273449] bg-white dark:bg-[#172033] hover:bg-gray-50 dark:hover:bg-[#1E293B] text-xs font-semibold text-gray-700 dark:text-slate-200 shadow-2xs transition-colors disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24]"
                >
                  <RefreshCw size={12} className={loading ? "animate-spin text-[#ED7D24]" : ""} />
                  {loading ? "Re-verifying..." : "Regenerate"}
                </button>
              </div>
            </div>

            {/* Continuous flowing narrative with Red Risk Statement and Light-Green Hover/Focus Grounding */}
            <div className="p-6 rounded-2xl bg-white dark:bg-[#0B1120] border border-gray-200/90 dark:border-[#273449] shadow-2xs">
              <div className="text-base sm:text-lg text-gray-800 dark:text-slate-100 leading-relaxed font-serif">
                {activeNarrative.verification?.sentences && activeNarrative.verification.sentences.length > 0 ? (
                  activeNarrative.verification.sentences.map((sent, i) => {
                    const isRedRisk = !sent.supported;

                    if (isRedRisk) {
                      return (
                        <span
                          key={i}
                          tabIndex={0}
                          role="button"
                          onClick={() => handleOpenDrawer(sent)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault();
                              handleOpenDrawer(sent);
                            }
                          }}
                          title={`Deterministic Risk Decision (${(sent.max_similarity * 100).toFixed(0)}% similarity)\nClick to inspect in Evidence Drawer`}
                          className="mr-1.5 px-1.5 py-0.5 rounded text-red-900 dark:text-red-300 bg-red-100/90 dark:bg-red-950/70 border-b-2 border-red-500 font-sans font-semibold cursor-pointer transition-all duration-150 inline-block focus:outline-none focus-visible:ring-2 focus-visible:ring-red-400 focus-visible:ring-offset-1 hover:bg-red-200 dark:hover:bg-red-900/80"
                        >
                          {sent.text}
                        </span>
                      );
                    }

                    // Supported evidence-backed phrase: normal text at rest, prominent light-green on hover/focus
                    return (
                      <span
                        key={i}
                        tabIndex={0}
                        role="button"
                        onClick={() => handleOpenDrawer(sent)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            handleOpenDrawer(sent);
                          }
                        }}
                        title={`Evidence Match (${(sent.max_similarity * 100).toFixed(0)}%): ${sent.matched_evidence_sentence || "Verified ground truth"}\nClick to inspect sources in Evidence Drawer`}
                        className="mr-1.5 px-1 py-0.5 rounded-sm transition-all duration-150 cursor-pointer border-b border-transparent hover:border-b-2 hover:border-emerald-500 hover:bg-emerald-100/90 hover:text-emerald-950 hover:shadow-[0_0_8px_rgba(16,185,129,0.35)] dark:hover:border-emerald-400 dark:hover:bg-emerald-950/80 dark:hover:text-emerald-200 dark:hover:shadow-[0_0_8px_rgba(16,185,129,0.35)] focus:outline-none focus-visible:border-b-2 focus-visible:border-emerald-500 focus-visible:bg-emerald-100/90 focus-visible:text-emerald-950 focus-visible:shadow-[0_0_8px_rgba(16,185,129,0.35)] dark:focus-visible:border-emerald-400 dark:focus-visible:bg-emerald-950/80 dark:focus-visible:text-emerald-200 dark:focus-visible:shadow-[0_0_8px_rgba(16,185,129,0.35)]"
                      >
                        {sent.text}
                      </span>
                    );
                  })
                ) : (
                  <p>{activeNarrative.narrative_text}</p>
                )}
              </div>

              {/* Legend & interaction hint */}
              <div className="flex flex-wrap items-center justify-between gap-3 pt-5 mt-5 border-t border-gray-100 dark:border-[#273449] text-xs text-gray-500 dark:text-[#94A3B8]">
                <div className="flex items-center gap-3">
                  <span className="inline-flex items-center gap-1.5 font-medium text-gray-700 dark:text-slate-300">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
                    Red: Deterministic priority statement
                  </span>
                  <span className="inline-flex items-center gap-1.5 font-medium text-gray-700 dark:text-slate-300">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                    Hover green: Grounded evidence phrases
                  </span>
                </div>
                <span className="text-[11px] text-gray-400 dark:text-slate-500 font-medium">
                  Click or press Enter on any phrase to open Evidence Drawer
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Side Drawer for Claim Grounding */}
      <EvidenceDrawer
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        data={drawerData}
      />
    </div>
  );
}
