export const API_BASE = (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000") + "/api";

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
