"use client";
import { useState, useEffect } from "react";
import { fetcher } from "@/lib/api";

export default function EvaluationPage() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetcher("/evaluation/summary").then(d => {
      setData(d);
      setLoading(false);
    });
  }, []);

  if (loading) return <div className="p-10 text-center text-gray-500">Loading evaluation summary...</div>;

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-gray-900 tracking-tight">Evaluation Harness Results</h1>
        <p className="text-gray-500 mt-1">Metrics from the latest automated evaluation run.</p>
      </div>

      {Object.entries(data).map(([key, result]: [string, any]) => (
        <div key={key} className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
          <div className="bg-gray-50 px-6 py-4 border-b border-gray-200 flex justify-between items-center">
            <h2 className="text-lg font-bold text-gray-800 capitalize">{key.replace('_', ' ')}</h2>
            {result.pass_fail && (
              <div className="flex gap-2">
                {Object.entries(result.pass_fail).map(([metric, status]: [string, any]) => (
                  <span key={metric} className={`px-2 py-1 text-xs font-bold rounded ${
                    String(status).includes("PASS") ? "bg-green-100 text-green-800" :
                    String(status).includes("PENDING") ? "bg-yellow-100 text-yellow-800" :
                    "bg-red-100 text-red-800"
                  }`}>
                    {metric}: {status}
                  </span>
                ))}
              </div>
            )}
          </div>
          <div className="p-6">
            {result.status ? (
              <div className="text-gray-500 italic">{result.status} - {result.note}</div>
            ) : (
              <pre className="text-sm bg-gray-900 text-gray-100 p-4 rounded-md overflow-x-auto">
                {JSON.stringify(result, null, 2)}
              </pre>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
