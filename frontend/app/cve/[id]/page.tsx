import React from "react";
import Link from "next/link";
import { fetcher } from "@/lib/api";
import { PriorityBadge, SourceDataBadge } from "@/components/Badges";
import NarrativeTabs from "@/components/NarrativeTabs";
import ScoreCalculationAccordion from "@/components/ScoreCalculationAccordion";
import CVEDetailLiveUpdater from "@/components/CVEDetailLiveUpdater";
import DownloadReportButton from "@/components/DownloadReportButton";
import ReportPreview from "@/components/ReportPreview";
import { formatDate } from "@/lib/utils";
import { ORG_CONTEXT, RECOMMENDED_ACTIONS } from "@/lib/constants";
import {
  ArrowLeft,
  ShieldAlert,
  Flame,
  TrendingUp,
  Building2,
  CheckCircle2,
  AlertCircle,
  Database,
  Clock,
  ExternalLink,
  Layers,
  Terminal,
  Server,
  Globe,
  FileCheck2
} from "lucide-react";

export const dynamic = "force-dynamic";

export default async function CVEDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;

  // Load both API resources concurrently so the detail route waits for only one round trip.
  const [evidenceResult, narrativesResult] = await Promise.allSettled([
    fetcher(`/cves/${id}`, { cache: "no-store" }),
    fetcher(`/cves/${id}/narratives`, { cache: "no-store" }),
  ]);

  if (evidenceResult.status === "rejected") {
    return (
      <div className="max-w-4xl mx-auto py-16 text-center space-y-4">
        <div className="w-16 h-16 rounded-full bg-red-100 dark:bg-red-950/60 text-red-600 dark:text-red-400 flex items-center justify-center mx-auto border dark:border-red-900/60">
          <AlertCircle size={32} />
        </div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-[#F8FAFC]">Vulnerability Not Found</h1>
        <p className="text-gray-500 dark:text-[#94A3B8] text-sm">Could not retrieve evidence data for record {id}.</p>
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-gray-900 hover:bg-black dark:bg-[#ED7D24] dark:hover:bg-[#D96B16] text-white font-medium text-xs transition-colors"
        >
          <ArrowLeft size={14} />
          Back to Dashboard
        </Link>
      </div>
    );
  }

  const evidence = evidenceResult.value;
  const narrativesData =
    narrativesResult.status === "fulfilled"
      ? narrativesResult.value
      : { narratives: [] };

  const { narratives = [] } = narrativesData;

  const priorityLabel = evidence.priority?.label || "LOW";
  const priorityScore = Number(evidence.priority?.score || 0);
  const cvssScore = Number(evidence.cvss?.score || 0);
  const epssProb = Number(evidence.epss?.probability || 0);
  const inKev = Boolean(evidence.kev?.in_kev);
  const vector = evidence.cvss?.vector || "";
  const isNetwork = vector.includes("AV:N") || evidence.cvss?.attack_vector === "NETWORK";
  const orgRelevance = ORG_CONTEXT.relevanceByPriority[priorityLabel] || "MEDIUM";

  // Build Real Evidence Checklist (only showing items that evaluate to true)
  const evidenceChecklist: { text: string; source: string; category: string }[] = [];

  if (cvssScore > 0) {
    evidenceChecklist.push({
      text: `CVSS Base Score = ${cvssScore.toFixed(1)} (${evidence.cvss?.severity || "Technical Severity"})`,
      source: "NVD (NIST CVE Feed)",
      category: "Technical",
    });
  }

  if (isNetwork) {
    evidenceChecklist.push({
      text: `Network-accessible attack vector (AV:N) — Remotely exploitable without physical/local access`,
      source: "CVSS v3.1 Metrics",
      category: "Exposure",
    });
  }

  if (epssProb > 0.01) {
    evidenceChecklist.push({
      text: `EPSS Exploitation Probability = ${(epssProb * 100).toFixed(2)}%${
        evidence.epss?.percentile ? ` (${(evidence.epss.percentile * 100).toFixed(0)}th percentile across global CVEs)` : ""
      }`,
      source: "FIRST.Org EPSS Model",
      category: "Likelihood",
    });
  }

  if (inKev) {
    evidenceChecklist.push({
      text: `Listed in CISA Known Exploited Vulnerabilities (KEV) Catalog — Confirmed weaponization in wild`,
      source: "CISA KEV Database",
      category: "Threat Intel",
    });
    if (evidence.kev?.date_added) {
      evidenceChecklist.push({
        text: `Federal remediation due date mandate: ${evidence.kev.due_date || "Mandatory Action Required"} (Added: ${evidence.kev.date_added})`,
        source: "CISA BOD 22-01",
        category: "Compliance",
      });
    }
  }

  if (evidence.affected?.vendor || evidence.affected?.product) {
    evidenceChecklist.push({
      text: `Affected component identified: ${evidence.affected.vendor || "Vendor"} ${evidence.affected.product || "Product"}`,
      source: "NVD CPE Catalog",
      category: "Asset Match",
    });
  }

  // Correlate with Organization Context
  evidenceChecklist.push({
    text: `Organizational Asset Relevance: Correlates with ${ORG_CONTEXT.industry} (${ORG_CONTEXT.assetCriticality})`,
    source: "Company Asset Inventory",
    category: "Context",
  });

  const recommendationText = RECOMMENDED_ACTIONS[priorityLabel] || RECOMMENDED_ACTIONS.LOW;

  return (
    <div className="space-y-8 max-w-[1600px] mx-auto w-full transition-colors duration-150">
      {/* Navigation Breadcrumb */}
      <div className="flex items-center justify-between">
        <Link
          href="/#explorer"
          className="inline-flex items-center gap-2 text-xs sm:text-sm font-semibold text-gray-600 dark:text-[#94A3B8] hover:text-gray-900 dark:hover:text-[#F8FAFC] transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24] rounded-lg p-1"
        >
          <ArrowLeft size={16} />
          Back to Vulnerability Explorer
        </Link>
        <div className="flex items-center gap-2">
          <SourceDataBadge source="Multi-Feed Ingestion" />
        </div>
      </div>

      {/* Main Hero Header Card */}
      <div className="bg-white dark:bg-[#111827] rounded-2xl border border-gray-200/90 dark:border-[#273449] shadow-2xs overflow-hidden p-6 sm:p-8 transition-colors">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-gray-100 dark:border-[#273449]">
          <div>
            <div className="flex flex-wrap items-center gap-3 mb-2">
              <h1 className="text-3xl sm:text-4xl font-black font-mono tracking-tight text-gray-950 dark:text-[#F8FAFC]">
                {id}
              </h1>
              {inKev && (
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-red-100 dark:bg-red-950/70 text-red-800 dark:text-red-300 border border-red-200 dark:border-red-800/80">
                  <Flame size={14} className="text-red-600 dark:text-red-400" />
                  Known Exploited (KEV)
                </span>
              )}
            </div>
            <p className="text-xs sm:text-sm text-gray-500 dark:text-[#94A3B8] font-medium">
              Published: {formatDate(evidence.published_date)} &bull; Last Modified: {formatDate(evidence.modified_date || evidence.published_date)}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-4 self-start lg:self-auto">
            <DownloadReportButton cveId={id} variant="button" />
            <div className="flex items-center gap-4 bg-gray-50 dark:bg-[#172033] p-4 rounded-2xl border border-gray-200 dark:border-[#273449]">
              <div className="text-right">
                <span className="text-[11px] font-bold uppercase tracking-wider text-gray-500 dark:text-[#94A3B8] block">
                  Deterministic Priority
                </span>
                <div className="text-2xl sm:text-3xl font-extrabold font-mono text-gray-950 dark:text-[#F8FAFC]">
                  {priorityScore.toFixed(3)}
                </div>
              </div>
              <PriorityBadge label={priorityLabel} size="lg" />
            </div>
          </div>
        </div>

        {/* Full CVE Description */}
        <div className="mt-6 space-y-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-gray-500 dark:text-[#94A3B8]">NVD Vulnerability Summary</h3>
          <p className="text-sm sm:text-base text-gray-800 dark:text-slate-200 leading-relaxed font-serif">
            {evidence.description || "No official description published in NVD feed."}
          </p>
        </div>
      </div>

      {/* Two-Column Core Layout (Desktop 2-Col, Mobile Stacked) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-start">
        {/* LEFT COLUMN: Risk Overview & Organization Context */}
        <div className="space-y-8">
          {/* Risk Overview Panel */}
          <div className="bg-white dark:bg-[#111827] rounded-2xl border border-gray-200/90 dark:border-[#273449] shadow-2xs p-6 space-y-5 transition-colors">
            <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-[#273449]">
              <h3 className="text-base font-bold text-gray-900 dark:text-[#F8FAFC] tracking-tight">Risk Overview & Signals</h3>
              <span className="text-xs text-gray-400 dark:text-slate-500 font-mono">Primary Triangulation</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {/* CVSS Metric */}
              <div className="p-4 rounded-xl bg-orange-50/50 dark:bg-orange-950/40 border border-orange-200/80 dark:border-orange-900/60 space-y-1">
                <span className="text-[11px] font-bold uppercase tracking-wider text-orange-700 dark:text-orange-300 block">
                  CVSS v3.1 Base
                </span>
                <div className="text-2xl font-black font-mono text-orange-950 dark:text-orange-200">
                  {cvssScore.toFixed(1)}
                </div>
                <span className="text-xs font-bold px-2 py-0.5 rounded bg-orange-200/60 dark:bg-orange-900/80 text-orange-900 dark:text-orange-200 inline-block">
                  {evidence.cvss?.severity || "MEDIUM"}
                </span>
                {evidence.cvss?.vector && (
                  <p className="text-[10px] font-mono text-gray-500 dark:text-[#94A3B8] truncate pt-1" title={evidence.cvss.vector}>
                    {evidence.cvss.vector}
                  </p>
                )}
              </div>

              {/* EPSS Metric */}
              <div className="p-4 rounded-xl bg-amber-50/50 dark:bg-amber-950/40 border border-amber-200/80 dark:border-amber-900/60 space-y-1">
                <span className="text-[11px] font-bold uppercase tracking-wider text-amber-700 dark:text-amber-300 block">
                  EPSS Probability
                </span>
                <div className="text-2xl font-black font-mono text-amber-950 dark:text-amber-200">
                  {(epssProb * 100).toFixed(1)}%
                </div>
                <span className="text-xs font-bold px-2 py-0.5 rounded bg-amber-200/60 dark:bg-amber-900/80 text-amber-900 dark:text-amber-200 inline-block">
                  {epssProb >= 0.5 ? "HIGH" : epssProb >= 0.05 ? "MODERATE" : "LOW"} LIKELIHOOD
                </span>
                {evidence.epss?.percentile && (
                  <p className="text-[10px] font-mono text-gray-500 dark:text-[#94A3B8] pt-1">
                    {(evidence.epss.percentile * 100).toFixed(0)}th Percentile
                  </p>
                )}
              </div>

              {/* CISA KEV Metric */}
              <div className={`p-4 rounded-xl border space-y-1 ${
                inKev
                  ? "bg-red-50/60 dark:bg-red-950/40 border-red-300 dark:border-red-900/60"
                  : "bg-gray-50 dark:bg-[#172033] border-gray-200 dark:border-[#273449]"
              }`}>
                <span className={`text-[11px] font-bold uppercase tracking-wider block ${
                  inKev ? "text-red-700 dark:text-red-300" : "text-gray-500 dark:text-[#94A3B8]"
                }`}>
                  CISA KEV Catalog
                </span>
                <div className={`text-2xl font-black font-mono ${inKev ? "text-red-950 dark:text-red-200" : "text-gray-400 dark:text-slate-500"}`}>
                  {inKev ? "YES" : "NO"}
                </div>
                <span className={`text-xs font-bold px-2 py-0.5 rounded inline-block ${
                  inKev
                    ? "bg-red-200 dark:bg-red-900/80 text-red-900 dark:text-red-200"
                    : "bg-gray-200 dark:bg-slate-800 text-gray-600 dark:text-slate-400"
                }`}>
                  {inKev ? "EXPLOITED IN WILD" : "NOT CATALOGED"}
                </span>
                {evidence.kev?.date_added && (
                  <p className="text-[10px] font-mono text-gray-600 dark:text-slate-400 pt-1">
                    Added: {evidence.kev.date_added}
                  </p>
                )}
              </div>
            </div>
          </div>

          {/* Organization Context Panel */}
          <div className="bg-white dark:bg-[#111827] rounded-2xl border border-gray-200/90 dark:border-[#273449] shadow-2xs p-6 space-y-5 transition-colors">
            <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-[#273449]">
              <div className="flex items-center gap-2">
                <Building2 size={18} className="text-purple-600 dark:text-purple-400" />
                <h3 className="text-base font-bold text-gray-900 dark:text-[#F8FAFC] tracking-tight">Organization Context & Impact</h3>
              </div>
              <span className={`text-xs font-bold px-2.5 py-1 rounded-lg border ${
                orgRelevance === "HIGH"
                  ? "bg-purple-100 dark:bg-purple-950/70 text-purple-800 dark:text-purple-300 border-purple-300 dark:border-purple-800"
                  : orgRelevance === "MEDIUM"
                  ? "bg-amber-100 dark:bg-amber-950/70 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-800"
                  : "bg-gray-100 dark:bg-[#172033] text-gray-700 dark:text-slate-300 border-gray-200 dark:border-[#273449]"
              }`}>
                Organizational Relevance: {orgRelevance}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="p-3.5 rounded-xl bg-gray-50/80 dark:bg-[#172033] border border-gray-100 dark:border-[#273449] space-y-1">
                <span className="text-gray-500 dark:text-[#94A3B8] font-semibold block">Organization / Tenant:</span>
                <span className="font-bold text-gray-900 dark:text-[#F8FAFC] text-sm">{ORG_CONTEXT.organization}</span>
              </div>

              <div className="p-3.5 rounded-xl bg-gray-50/80 dark:bg-[#172033] border border-gray-100 dark:border-[#273449] space-y-1">
                <span className="text-gray-500 dark:text-[#94A3B8] font-semibold block">Industry Vertical:</span>
                <span className="font-bold text-gray-900 dark:text-[#F8FAFC] text-sm">{ORG_CONTEXT.industry}</span>
              </div>

              <div className="p-3.5 rounded-xl bg-gray-50/80 dark:bg-[#172033] border border-gray-100 dark:border-[#273449] space-y-1">
                <span className="text-gray-500 dark:text-[#94A3B8] font-semibold block">Asset Criticality Tier:</span>
                <span className="font-bold text-purple-900 dark:text-purple-300 text-sm flex items-center gap-1.5">
                  <Server size={14} className="text-purple-600 dark:text-purple-400" />
                  {ORG_CONTEXT.assetCriticality}
                </span>
              </div>

              <div className="p-3.5 rounded-xl bg-gray-50/80 dark:bg-[#172033] border border-gray-100 dark:border-[#273449] space-y-1">
                <span className="text-gray-500 dark:text-[#94A3B8] font-semibold block">Internet Exposure Level:</span>
                <span className="font-bold text-blue-900 dark:text-blue-300 text-sm flex items-center gap-1.5">
                  <Globe size={14} className="text-blue-600 dark:text-blue-400" />
                  {ORG_CONTEXT.internetExposure}
                </span>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-purple-50/40 dark:bg-purple-950/30 border border-purple-100 dark:border-purple-900/50 space-y-2 text-xs">
              <div>
                <span className="text-purple-950 dark:text-purple-200 font-bold block mb-0.5">Affected Asset Scope:</span>
                <p className="text-gray-700 dark:text-slate-300">{ORG_CONTEXT.affectedAsset}</p>
              </div>
              <div className="pt-2 border-t border-purple-100/80 dark:border-purple-900/50">
                <span className="text-purple-950 dark:text-purple-200 font-bold block mb-0.5">Potential Business Impact:</span>
                <p className="text-gray-700 dark:text-slate-300">{ORG_CONTEXT.businessImpact}</p>
              </div>
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: Why is this prioritized? & How is this calculated? */}
        <div className="space-y-8">
          <ScoreCalculationAccordion evidence={evidence} />
        </div>
      </div>

      {/* FULL WIDTH SECTION: Evidence & Sources Checklist */}
      <div className="bg-white dark:bg-[#111827] rounded-2xl border border-gray-200/90 dark:border-[#273449] shadow-2xs p-6 sm:p-8 space-y-6 transition-colors">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-gray-100 dark:border-[#273449]">
          <div>
            <div className="flex items-center gap-2">
              <FileCheck2 size={20} className="text-emerald-600 dark:text-emerald-400" />
              <h3 className="text-lg font-bold text-gray-900 dark:text-[#F8FAFC] tracking-tight">Evidence & Sources Checklist</h3>
            </div>
            <p className="text-xs text-gray-500 dark:text-[#94A3B8] mt-0.5">
              Verified ground-truth facts extracted directly from authoritative threat intelligence sources.
            </p>
          </div>
          <span className="text-xs font-semibold px-2.5 py-1 bg-emerald-50 dark:bg-emerald-950/70 text-emerald-800 dark:text-emerald-300 rounded-lg border border-emerald-200 dark:border-emerald-800/80 self-start sm:self-auto">
            {evidenceChecklist.length} Verified Evidence Points
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          {evidenceChecklist.map((item, idx) => (
            <div
              key={idx}
              className="p-4 rounded-xl border border-gray-200 dark:border-[#273449] bg-gray-50/50 dark:bg-[#172033]/60 hover:bg-white dark:hover:bg-[#172033] hover:border-emerald-300 dark:hover:border-emerald-600 transition-colors flex items-start gap-3 shadow-2xs"
            >
              <div className="p-1 rounded-full bg-emerald-100 dark:bg-emerald-950/80 text-emerald-700 dark:text-emerald-400 shrink-0 mt-0.5 border dark:border-emerald-800/80">
                <CheckCircle2 size={16} />
              </div>
              <div className="space-y-1 flex-grow">
                <p className="text-xs sm:text-sm font-semibold text-gray-900 dark:text-[#F8FAFC] leading-snug">
                  {item.text}
                </p>
                <div className="flex items-center gap-2 text-[11px] text-gray-500 dark:text-[#94A3B8]">
                  <span className="font-mono bg-white dark:bg-[#0B1120] px-1.5 py-0.2 rounded border border-gray-200 dark:border-[#273449]">
                    Source: {item.source}
                  </span>
                  <span>&bull;</span>
                  <span className="text-gray-400 dark:text-slate-500">{item.category}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* FULL WIDTH SECTION: Actionable Recommendation */}
      <div className="bg-gradient-to-r from-slate-900 via-gray-900 to-slate-900 dark:from-[#111827] dark:via-[#172033] dark:to-[#111827] text-white rounded-2xl shadow-md p-6 sm:p-8 space-y-4 border border-transparent dark:border-[#273449] transition-colors">
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-xl bg-orange-500/20 text-[#ED7D24]">
            <ShieldAlert size={20} />
          </div>
          <div>
            <h3 className="text-base sm:text-lg font-bold tracking-tight text-white">Recommended Remediation Action</h3>
            <p className="text-xs text-slate-400">Deterministic operational SLA based on prioritized risk tier</p>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-white/5 border border-white/10 text-sm sm:text-base font-medium text-slate-100 leading-relaxed font-serif">
          {recommendationText}
        </div>
      </div>

      {/* Structured 6-Section Vulnerability Report Preview & Download */}
      <ReportPreview cveId={id} />

      {/* FULL WIDTH SECTION: Audience-Specific Narratives & Verifier Engine */}
      <div className="bg-white dark:bg-[#111827] rounded-2xl border border-gray-200/90 dark:border-[#273449] shadow-2xs overflow-hidden transition-colors">
        <div className="p-6 border-b border-gray-100 dark:border-[#273449] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-bold text-gray-900 dark:text-[#F8FAFC] tracking-tight">Audience-Specific Risk Narratives</h3>
            <p className="text-xs text-gray-500 dark:text-[#94A3B8] mt-0.5">
              LLM synthesized explanations strictly constrained and verified against ground-truth evidence.
            </p>
          </div>
        </div>

        <NarrativeTabs cveId={id} initialNarratives={narratives} evidenceData={evidence} />
      </div>

      {/* Source Timestamps Panel */}
      <div className="p-5 rounded-2xl bg-gray-50 dark:bg-[#111827] border border-gray-200 dark:border-[#273449] text-xs text-gray-500 dark:text-[#94A3B8] flex flex-wrap items-center justify-between gap-4 transition-colors">
        <div className="flex items-center gap-2">
          <Clock size={14} className="text-gray-400 dark:text-slate-500" />
          <span className="font-semibold text-gray-700 dark:text-slate-300">Source Synchronization Timestamps:</span>
        </div>
        <div className="flex flex-wrap items-center gap-4 font-mono text-[11px]">
          <span>NVD: {formatDate(evidence.published_date)}</span>
          <span>&bull;</span>
          <span>EPSS Feed: {evidence.epss?.fetched_at ? formatDate(evidence.epss.fetched_at) : "Daily Refresh"}</span>
          <span>&bull;</span>
          <span>CISA KEV: {evidence.kev?.date_added || "Not Cataloged"}</span>
        </div>
      </div>

      {/* Live updater — triggers server re-render when this CVE changes */}
      <CVEDetailLiveUpdater cveId={id} />
    </div>
  );
}
