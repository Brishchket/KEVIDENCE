"use client";
import { useState } from "react";
import { fetcher } from "@/lib/api";

type Sentence = {
  text: string;
  supported: boolean;
  max_similarity: number;
  reason: string;
  matched_evidence_sentence: string | null;
};

type Narrative = {
  audience: string;
  narrative_text: string;
  confidence: string;
  faithfulness_score: number;
  verification: {
    sentences: Sentence[];
  };
};

export default function NarrativeTabs({ cveId, initialNarratives }: { cveId: string, initialNarratives: Narrative[] }) {
  const [narratives, setNarratives] = useState(initialNarratives);
  const [activeTab, setActiveTab] = useState("manager");
  const [loading, setLoading] = useState(false);

  const tabs = [
    { id: "manager", label: "Business Manager" },
    { id: "analyst", label: "Security Analyst" },
    { id: "it_admin", label: "IT Administrator" },
  ];

  const activeNarrative = narratives.find(n => n.audience === activeTab);

  const generate = async () => {
    setLoading(true);
    try {
      const newNarrative = await fetcher(`/cves/${cveId}/narratives?audience=${activeTab}&regenerate=true`, {
        method: "POST"
      });
      setNarratives(prev => {
        const copy = [...prev];
        const idx = copy.findIndex(n => n.audience === activeTab);
        if (idx >= 0) copy[idx] = newNarrative;
        else copy.push(newNarrative);
        return copy;
      });
    } catch (e) {
      alert("Failed to generate narrative");
    }
    setLoading(false);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="border-b border-gray-200">
        <nav className="flex -mb-px px-6" aria-label="Tabs">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`w-1/3 py-4 px-1 text-center border-b-2 font-medium text-sm transition-colors ${
                activeTab === tab.id
                  ? "border-blue-500 text-blue-600"
                  : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      <div className="p-6">
        {!activeNarrative ? (
          <div className="text-center py-10">
            <p className="text-gray-500 mb-4">No narrative generated yet for this audience.</p>
            <button
              onClick={generate}
              disabled={loading}
              className="bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-md transition-colors"
            >
              {loading ? "Generating..." : "Generate Narrative"}
            </button>
          </div>
        ) : (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <div className="flex items-center gap-3">
                <span className="text-sm font-semibold text-gray-700">Faithfulness Confidence:</span>
                <span className={`px-2.5 py-1 rounded-md text-xs font-bold ${
                  activeNarrative.confidence === "HIGH" ? "bg-green-100 text-green-700 border border-green-200" :
                  activeNarrative.confidence === "MEDIUM" ? "bg-yellow-100 text-yellow-700 border border-yellow-200" :
                  "bg-red-100 text-red-700 border border-red-200"
                }`}>
                  {activeNarrative.confidence}
                </span>
                <span className="text-sm text-gray-500">
                  ({(activeNarrative.faithfulness_score * 100).toFixed(1)}%)
                </span>
              </div>
              <button
                onClick={generate}
                disabled={loading}
                className="text-sm text-blue-600 hover:text-blue-800 font-medium"
              >
                {loading ? "Regenerating..." : "Regenerate"}
              </button>
            </div>

            <div className="bg-gray-50 p-5 rounded-xl border border-gray-200 text-gray-800 leading-relaxed">
              {activeNarrative.verification?.sentences ? (
                <span>
                  {activeNarrative.verification.sentences.map((sent, i) => (
                    <span
                      key={i}
                      title={`Similarity: ${sent.max_similarity}\nEvidence: ${sent.matched_evidence_sentence || "None"}\nReason: ${sent.reason}`}
                      className={`mr-1 px-1 rounded transition-colors cursor-help ${
                        sent.supported ? "hover:bg-green-100" : "bg-red-100 border-b-2 border-red-400 font-medium"
                      }`}
                    >
                      {sent.text}
                    </span>
                  ))}
                </span>
              ) : (
                <p>{activeNarrative.narrative_text}</p>
              )}
            </div>
            
            <div className="text-xs text-gray-400 mt-2">
              Hover over sentences to see evidence similarity scores. Red sentences failed the faithfulness verification.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
