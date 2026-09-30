"use client";
import { VendorEntry } from "@/lib/api";
import { priorityColor } from "@/lib/utils";

interface RadialGaugeProps {
  total: number;
  pctBelowMedium: number;
  vendors: VendorEntry[];
}

const VENDOR_POSITIONS = [
  { angle: -150 }, // top-left
  { angle: -120 },
  { angle: -90 },  // top
  { angle: -60 },
  { angle: -30 },  // top-right
  { angle: 0 },    // right
  { angle: 30 },
  { angle: 60 },   // bottom-right (avoid, semicircle = top half)
];

// We only use top semicircle: angles from -170 to -10 (avoiding straight down)
const ARC_POSITIONS = [-160, -130, -100, -75, -50, -25, 0, 25, 50, 75];

function polarToCartesian(cx: number, cy: number, r: number, angleDeg: number) {
  const rad = ((angleDeg - 90) * Math.PI) / 180;
  return {
    x: cx + r * Math.cos(rad),
    y: cy + r * Math.sin(rad),
  };
}

function describeArc(cx: number, cy: number, r: number, startAngle: number, endAngle: number) {
  const start = polarToCartesian(cx, cy, r, endAngle);
  const end = polarToCartesian(cx, cy, r, startAngle);
  const largeArc = endAngle - startAngle <= 180 ? "0" : "1";
  return `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 0 ${end.x} ${end.y}`;
}

export default function RadialGauge({ total, pctBelowMedium, vendors }: RadialGaugeProps) {
  const cx = 200;
  const cy = 200;
  const outerR = 150;
  const innerR = 90;

  // Arc for pct: from -180 (left) to angle mapped to percentage
  const startAngle = -180;
  const sweepAngle = 180 * (pctBelowMedium / 100);
  const endAngle = startAngle + sweepAngle;

  // Dotted outer ring: render as many short arcs (dashes)
  const totalDots = 60;
  const dotLen = 2;
  const gapLen = 4;

  const sliceAngle = 180 / totalDots;

  return (
    <div className="flex flex-col items-center justify-center h-full">
      <p className="text-[11px] font-medium text-[#8A9E95] mb-1 tracking-wider uppercase">
        {total.toLocaleString()} CVEs Tracked
      </p>
      <svg viewBox="0 0 400 230" className="w-full max-w-[340px]">
        {/* Background semi-ring */}
        <path
          d={describeArc(cx, cy, outerR, -180, 0)}
          fill="none"
          stroke="#1E3A30"
          strokeWidth={28}
          strokeLinecap="butt"
        />

        {/* Green progress arc */}
        {pctBelowMedium > 0 && (
          <path
            d={describeArc(cx, cy, outerR, startAngle, Math.min(endAngle, 0))}
            fill="none"
            stroke="#6BAB8C"
            strokeWidth={6}
            strokeLinecap="round"
            className="transition-all duration-700"
          />
        )}

        {/* Dotted outer ring */}
        {Array.from({ length: totalDots }, (_, i) => {
          const a = -180 + i * sliceAngle;
          const p1 = polarToCartesian(cx, cy, outerR + 18, a);
          const p2 = polarToCartesian(cx, cy, outerR + 22, a);
          return (
            <circle
              key={i}
              cx={(p1.x + p2.x) / 2}
              cy={(p1.y + p2.y) / 2}
              r={1.5}
              fill="#2C4A3E"
            />
          );
        })}

        {/* Inner circle */}
        <circle cx={cx} cy={cy} r={innerR} fill="#0D1A16" />
        <circle cx={cx} cy={cy} r={innerR - 2} fill="none" stroke="#1E3A30" strokeWidth={1} />

        {/* Center text */}
        <text
          x={cx}
          y={cy - 8}
          textAnchor="middle"
          fontSize={32}
          fontWeight={700}
          fill="white"
          fontFamily="Inter, sans-serif"
        >
          {pctBelowMedium.toFixed(0)}%
        </text>
        <text
          x={cx}
          y={cy + 14}
          textAnchor="middle"
          fontSize={10}
          fill="#6BAB8C"
          fontFamily="Inter, sans-serif"
        >
          Below Medium Priority
        </text>

        {/* Vendor nodes around arc */}
        {vendors.slice(0, 8).map((v, i) => {
          const angle = ARC_POSITIONS[i] ?? -90;
          const pos = polarToCartesian(cx, cy, outerR + 40, angle);
          const clr = priorityColor(v.worst_label);
          const label = v.vendor.length > 9 ? v.vendor.slice(0, 8) + "…" : v.vendor;
          return (
            <g key={v.vendor}>
              <circle cx={pos.x} cy={pos.y} r={12} fill={clr} opacity={0.18} />
              <circle cx={pos.x} cy={pos.y} r={6} fill={clr} />
              <text
                x={pos.x}
                y={pos.y + 20}
                textAnchor="middle"
                fontSize={8}
                fill="#8A9E95"
                fontFamily="Inter, sans-serif"
              >
                {label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
