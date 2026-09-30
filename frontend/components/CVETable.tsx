"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { fetcher } from "@/lib/api";

type CVEItem = {
  cve_id: string;
  description: string;
  priority_label: string;
  priority_score: number;
  in_kev: boolean;
};

export default function CVETable() {
  const [cves, setCves] = useState<CVEItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetcher("/cves?limit=15").then((data) => {
      setCves(data.items);
      setLoading(false);
    });
  }, []);

  if (loading) return <div className="p-4">Loading CVEs...</div>;

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
      <table className="w-full text-left text-sm">
        <thead className="bg-gray-50 border-b border-gray-200 text-gray-600 font-medium">
          <tr>
            <th className="px-4 py-3">CVE ID</th>
            <th className="px-4 py-3">Priority</th>
            <th className="px-4 py-3">Score</th>
            <th className="px-4 py-3">KEV</th>
            <th className="px-4 py-3">Description</th>
            <th className="px-4 py-3">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {cves.map((cve) => (
            <tr key={cve.cve_id} className="hover:bg-gray-50/50">
              <td className="px-4 py-3 font-medium text-blue-600">
                <Link href={`/cve/${cve.cve_id}`}>{cve.cve_id}</Link>
              </td>
              <td className="px-4 py-3">
                <span
                  className={`px-2 py-1 rounded text-xs font-bold ${
                    cve.priority_label === "CRITICAL"
                      ? "bg-red-100 text-red-700"
                      : cve.priority_label === "HIGH"
                      ? "bg-orange-100 text-orange-700"
                      : cve.priority_label === "MEDIUM"
                      ? "bg-yellow-100 text-yellow-700"
                      : "bg-green-100 text-green-700"
                  }`}
                >
                  {cve.priority_label}
                </span>
              </td>
              <td className="px-4 py-3 font-mono">{cve.priority_score.toFixed(3)}</td>
              <td className="px-4 py-3">
                {cve.in_kev ? (
                  <span className="text-red-600 font-bold">Yes</span>
                ) : (
                  <span className="text-gray-400">No</span>
                )}
              </td>
              <td className="px-4 py-3 text-gray-600 max-w-xs truncate">
                {cve.description}
              </td>
              <td className="px-4 py-3">
                <Link
                  href={`/cve/${cve.cve_id}`}
                  className="text-xs bg-gray-100 hover:bg-gray-200 text-gray-700 px-3 py-1.5 rounded-md font-medium transition-colors"
                >
                  View Details
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
