import { ArrowUpRight, Database, Server, Cpu } from "lucide-react";
import { SourcesData } from "@/lib/api";

export default function SourcesCard({ data }: { data: SourcesData }) {
  const sources = [
    { key: "nvd", icon: Database, label: "NVD CVEs", count: data.nvd.count },
    { key: "epss", icon: Server, label: "EPSS Enriched", count: data.epss.count },
    { key: "kev", icon: Cpu, label: "CISA KEV", count: data.kev.count },
  ];

  return (
    <div className="flex flex-col bg-[var(--bg-card)] rounded-2xl p-5 shadow-sm min-h-[220px]">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-[#1C2B27] font-semibold text-[15px]">Sources</h2>
        <ArrowUpRight size={16} className="text-[#1C2B27]" />
      </div>
      <div className="flex flex-col gap-4 flex-1 justify-center">
        {sources.map(({ key, icon: Icon, label, count }) => (
          <div key={key} className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-[#5A6B62]">
              <Icon size={16} />
              <span className="text-[13px] font-medium">{label}</span>
            </div>
            <span className="text-[#1C2B27] font-bold text-[14px] tabular-nums">
              {count.toLocaleString()}
            </span>
          </div>
        ))}
      </div>
      {/* Pagination dots (static for styling matching reference) */}
      <div className="flex items-center justify-center gap-1.5 mt-4">
        <div className="w-1.5 h-1.5 rounded-full bg-[#1C2B27]" />
        <div className="w-1 h-1 rounded-full bg-[#1C2B27]/30" />
        <div className="w-1 h-1 rounded-full bg-[#1C2B27]/30" />
      </div>
    </div>
  );
}
