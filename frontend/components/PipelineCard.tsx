import { ArrowUpRight, ChevronRight } from "lucide-react";

export default function PipelineCard() {
  const steps = [
    { num: "/01", title: "Ingestion Complete" },
    { num: "/02", title: "Prioritization Running" },
    { num: "/03", title: "Narratives (Phase 2)" },
  ];

  return (
    <div className="flex flex-col bg-[var(--bg-card)] rounded-2xl p-5 shadow-sm min-h-[220px]">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-[#1C2B27] font-semibold text-[15px]">Pipeline Status</h2>
        <ArrowUpRight size={16} className="text-[#1C2B27]" />
      </div>
      <div className="flex flex-col gap-2.5 flex-1 justify-center">
        {steps.map((s, i) => (
          <div key={s.num} className="flex items-center gap-3 bg-white/40 px-3 py-2 rounded-lg">
            <div className="w-6 h-6 flex items-center justify-center rounded bg-white text-[#5A6B62]">
              <ChevronRight size={14} />
            </div>
            <div>
              <p className="text-[10px] font-bold text-[#5A6B62] tracking-wider mb-0.5">{s.num}</p>
              <p className="text-[13px] font-medium text-[#1C2B27]">{s.title}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
