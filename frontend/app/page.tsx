import React from "react";
import DashboardClient from "@/components/DashboardClient";
import { fetcher } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  let stats: any = {
    total_cves: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    kev_count: 0,
    parse_rate: 100,
    last_updated: {},
    risk_drivers: {},
  };

  try {
    stats = await fetcher("/stats", { cache: "no-store" });
  } catch (e) {
    console.error("Failed to fetch stats:", e);
  }

  return <DashboardClient stats={stats} />;
}
