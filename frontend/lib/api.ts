export const API_BASE = (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000") + "/api";

export interface SummaryData {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  trend?: { day: string; count: number }[];
  pct_below_medium?: number;
  [key: string]: any;
}

export interface VendorEntry {
  vendor: string;
  count: number;
  worst_label?: string;
  [key: string]: any;
}

export interface VendorsData {
  vendors: VendorEntry[];
}

export interface FeedEvent {
  id: string | number;
  event_type: string;
  detail: string;
  cve_id: string;
  [key: string]: any;
}

export interface FeedData {
  events: FeedEvent[];
}

export interface SourcesData {
  [key: string]: any;
}

export async function fetcher(url: string, options?: RequestInit) {
  const res = await fetch(`${API_BASE}${url}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }
  return res.json();
}
