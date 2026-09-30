"use client";
import { useState, useEffect } from "react";
import { fetcher } from "@/lib/api";

type CompareData = {
  cve_id: string;
  raw_description: string;
  phantompatch_narrative: string;
  raw_flesch: number | null;
  phantompatch_flesch: number | null;
  phantompatch_unsupported_rate: number | null;
};

export default function ComparePage() {
  const [cves, setCves] = useState<{cve_id: string}[]>([]);
  const [selectedCve, setSelectedCve] = useState<string>("");
  const [data, setData] = useState<CompareData | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetcher("/cves?limit=50").then(d => {
      setCves(d.items);
      if (d.items.length > 0) {
        setSelectedCve(d.items[0].cve_id);
      }
    });
  }, []);

  useEffect(() => {
    if (!selectedCve) return;
    setLoading(true);
    fetcher(`/compare/${selectedCve}`).then(d => {
      setData(d);
      setLoading(false);
    });
  }, [selectedCve]);

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="flex justify-between items-end mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 tracking-tight">Baseline Comparison</h1>
          <p className="text-gray-500 mt-1">Comparing Raw NVD Data against PhantomPatch Evidence-Grounded Narratives.</p>
        </div>
        <div className="w-64">
          <label className="block text-sm font-medium text-gray-700 mb-1">Select CVE</label>
          <select 
            value={selectedCve} 
            onChange={e => setSelectedCve(e.target.value)}
            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm p-2 border"
          >
            {cves.map(c => <option key={c.cve_id} value={c.cve_id}>{c.cve_id}</option>)}
          </select>
        </div>
      </div>

      {loading || !data ? (
        <div className="p-10 text-center text-gray-500">Loading comparison...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* RAW */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden flex flex-col">
            <div className="bg-gray-50 px-4 py-3 border-b border-gray-200 font-bold text-gray-700">
              Raw NVD Description
            </div>
            <div className="p-6 flex-grow">
              <p className="text-gray-700 leading-relaxed text-sm">
                {data.raw_description || "No description available."}
              </p>
            </div>
            <div className="bg-gray-50 px-4 py-3 border-t border-gray-200 grid grid-cols-2 gap-4 text-sm">
              <div>
                <div className="text-gray-500 mb-1">Flesch Reading Ease</div>
                <div className="font-bold">{data.raw_flesch ?? "N/A"}</div>
              </div>
            </div>
          </div>

          {/* PHANTOMPATCH */}
          <div className="bg-white rounded-xl shadow-sm border border-blue-200 overflow-hidden flex flex-col ring-1 ring-blue-500">
            <div className="bg-blue-50 px-4 py-3 border-b border-blue-200 font-bold text-blue-900 flex justify-between items-center">
              <span>PhantomPatch (Manager)</span>
              <span className="text-xs bg-blue-200 text-blue-800 px-2 py-0.5 rounded-full">Verified</span>
            </div>
            <div className="p-6 flex-grow">
              <p className="text-gray-800 leading-relaxed text-sm">
                {data.phantompatch_narrative || "No narrative generated yet. Generate it from the detail page."}
              </p>
            </div>
            <div className="bg-blue-50 px-4 py-3 border-t border-blue-200 grid grid-cols-2 gap-4 text-sm">
              <div>
                <div className="text-blue-700 mb-1">Flesch Reading Ease</div>
                <div className="font-bold text-blue-900">{data.phantompatch_flesch ?? "N/A"}</div>
              </div>
              <div>
                <div className="text-blue-700 mb-1">Unsupported Claim Rate</div>
                <div className="font-bold text-blue-900">
                  {data.phantompatch_unsupported_rate !== null 
                    ? `${(data.phantompatch_unsupported_rate * 100).toFixed(1)}%` 
                    : "N/A"}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
