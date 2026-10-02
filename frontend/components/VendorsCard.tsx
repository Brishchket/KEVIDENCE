import { ArrowUpRight, Monitor, Server, Laptop } from "lucide-react";
import { VendorsData } from "@/lib/api";
import { priorityColor } from "@/lib/utils";

export default function VendorsCard({ data }: { data: VendorsData }) {
  const icons = [Monitor, Server, Laptop];
  const displayVendors = data.vendors.slice(0, 3);
  
  return (
    <div className="flex flex-col bg-[var(--bg-card)] rounded-2xl p-5 shadow-sm min-h-[220px] relative">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-[#1C2B27] font-semibold text-[15px]">Affected Assets</h2>
        <ArrowUpRight size={16} className="text-[#1C2B27]" />
      </div>
      
      <div className="flex flex-col gap-4 flex-1 justify-center z-10">
        {displayVendors.map((v, i) => {
          const Icon = icons[i % icons.length];
          return (
            <div key={v.vendor} className="flex items-center gap-3 border-b border-[#BDC1AE]/50 pb-2 last:border-0 last:pb-0">
              <Icon size={16} className="text-[#5A6B62]" />
              <div 
                className="w-2 h-2 rounded-sm"
                style={{ backgroundColor: priorityColor(v.worst_label || "LOW") }}
              />
              <span className="text-[13px] font-medium text-[#1C2B27] truncate">
                {v.vendor}
              </span>
            </div>
          );
        })}
        {displayVendors.length === 0 && (
          <p className="text-[#5A6B62] text-[12px] italic">No asset data</p>
        )}
      </div>

      <div className="absolute bottom-4 right-5 flex items-baseline gap-1">
        <span className="text-[#1C2B27] font-bold text-4xl tabular-nums tracking-tighter leading-none">
          {data.vendors.length}
        </span>
        <span className="text-[#1C2B27] text-[11px] font-semibold tracking-wide">
          Total
        </span>
      </div>
    </div>
  );
}
