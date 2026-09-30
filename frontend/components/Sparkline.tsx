"use client";
import { LineChart, Line, ResponsiveContainer, Tooltip } from "recharts";

interface SparklineProps {
  data: { day: string; count: number }[];
}

export default function Sparkline({ data }: SparklineProps) {
  if (!data || data.length === 0) return null;
  return (
    <ResponsiveContainer width="100%" height={40}>
      <LineChart data={data} margin={{ top: 2, right: 2, left: 2, bottom: 2 }}>
        <Tooltip
          contentStyle={{ background: "#0D1A16", border: "none", borderRadius: 8, fontSize: 11, color: "#fff" }}
          formatter={(v: number) => [v, "CVEs"]}
          labelFormatter={(l: string) => l}
        />
        <Line
          type="monotone"
          dataKey="count"
          stroke="#6BAB8C"
          strokeWidth={1.5}
          dot={false}
          activeDot={{ r: 3, fill: "#ED7D24" }}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}
