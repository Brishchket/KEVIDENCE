import { Plus, User } from "lucide-react";
import { formatDate } from "@/lib/utils";

interface StatusBarProps {
  lastRun: string | null;
  lastCveTime: string | null;
}

export default function StatusBar({ lastRun, lastCveTime }: StatusBarProps) {
  return (
    <div className="flex flex-col md:flex-row items-center gap-4 py-4 px-2">
      {/* User & Last Run */}
      <div className="flex items-center gap-3 flex-1 w-full relative">
        <div className="w-8 h-8 rounded-full bg-[#BDC1AE] flex items-center justify-center shrink-0">
          <User size={16} className="text-[#5A6B62]" />
        </div>
        <div className="flex flex-col relative z-10 bg-[var(--bg-page)] pr-4">
          <span className="text-[10px] text-[#5A6B62] font-semibold tracking-wider">
            Last ingestion on
          </span>
          <span className="text-[12px] text-[#1C2B27] font-medium">
            {formatDate(lastRun)}
          </span>
        </div>
        {/* Progress line connector */}
        <div className="absolute top-1/2 left-10 right-0 h-px bg-[#BDC1AE]/60 -z-0" />
      </div>

      {/* Center Event */}
      <div className="flex items-center gap-3 bg-[var(--bg-page)] px-4 shrink-0 relative z-10 border border-[#BDC1AE]/60 rounded-full py-1">
        <div className="w-6 h-6 rounded bg-[#BDC1AE]/30 flex items-center justify-center">
          <Plus size={14} className="text-[#1C2B27]" />
        </div>
        <div className="flex flex-col pr-2">
          <span className="text-[10px] text-[#5A6B62] font-semibold tracking-wider">
            Last alert added on
          </span>
          <span className="text-[12px] text-[#1C2B27] font-medium">
            {formatDate(lastCveTime)}
          </span>
        </div>
      </div>

      {/* Right User & Action */}
      <div className="flex items-center gap-3 flex-1 w-full justify-end relative">
        <div className="absolute top-1/2 left-0 right-10 h-px bg-[#BDC1AE]/60 -z-0" />
        <div className="flex flex-col items-end relative z-10 bg-[var(--bg-page)] pl-4">
          <span className="text-[10px] text-[#5A6B62] font-semibold tracking-wider">
            System status
          </span>
          <span className="text-[12px] text-[#1C2B27] font-medium">
            Active / Phase 1
          </span>
        </div>
        <button className="px-5 py-2.5 rounded-xl bg-[var(--accent-orange)] text-white text-[13px] font-bold hover:opacity-90 transition-opacity z-10 shadow-sm shrink-0">
          Full timeline
        </button>
      </div>
    </div>
  );
}
