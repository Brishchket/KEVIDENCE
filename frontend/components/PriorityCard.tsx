import { ArrowUpRight } from "lucide-react";
import { SummaryData } from "@/lib/api";

export default function PriorityCard({ data }: { data: SummaryData }) {
  const bars = [
    { label: "Critical", count: data.critical, color: "#ED7D24" },
    { label: "High", count: data.high, color: "#E85D5D" },
    { label: "Medium", count: data.medium, color: "#F0B429" },
    { label: "Low", count: data.low, color: "#6BAB8C" },
  ];

  const maxCount = Math.max(...bars.map(b => b.count), 1);

  return (
    <div className="flex flex-col bg-[var(--bg-card)] rounded-2xl p-5 shadow-sm min-h-[220px]">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-[#1C2B27] font-semibold text-[15px]">Alert Breakdown</h2>
        <ArrowUpRight size={16} className="text-[#1C2B27]" />
      </div>
      <div className="flex flex-col gap-3 flex-1 justify-center">
        {bars.map(({ label, count, color }) => {
          const pct = Math.max((count / maxCount) * 100, 2); // At least 2% so bar is visible if > 0
          return (
            <div key={label} className="flex items-center gap-3">
              <span className="text-[#5A6B62] text-[12px] font-medium w-[52px]">
                {label}
              </span>
              <div className="flex-1 h-[3px] bg-[#BDC1AE] rounded-full overflow-hidden flex items-center relative">
                 {/* Dotted background effect - simple simulation with repeating linear gradient if needed, or just solid */}
                <div 
                  className="h-full rounded-full absolute left-0 top-0" 
                  style={{ width: `${pct}%`, background: color }}
                />
              </div>
              <span className="text-[#1C2B27] font-bold text-[13px] tabular-nums w-6 text-right">
                {count > 0 ? count : "-"}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
