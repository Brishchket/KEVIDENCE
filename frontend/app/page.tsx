import CVETable from "@/components/CVETable";
import { fetcher } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function Dashboard() {
  let stats;
  try {
    stats = await fetcher("/stats", { cache: 'no-store' });
  } catch (e) {
    stats = {
      total_cves: 0, critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, kev_count: 0
    };
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 tracking-tight">Vulnerability Priority Dashboard</h1>
          <p className="text-gray-500 mt-1">Evidence-grounded scoring & verification pipeline.</p>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <StatCard title="Total Ingested" value={stats.total_cves} />
        <StatCard title="Critical" value={stats.critical_count} color="text-red-600" />
        <StatCard title="High" value={stats.high_count} color="text-orange-600" />
        <StatCard title="Medium" value={stats.medium_count} color="text-yellow-600" />
        <StatCard title="Low" value={stats.low_count} color="text-green-600" />
        <StatCard title="CISA KEV" value={stats.kev_count} color="text-purple-600" />
      </div>

      <div>
        <h2 className="text-xl font-semibold mb-3">Top Priority CVEs</h2>
        <CVETable />
      </div>
    </div>
  );
}

function StatCard({ title, value, color = "text-gray-900" }: { title: string, value: number, color?: string }) {
  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
      <div className="text-sm font-medium text-gray-500 mb-1">{title}</div>
      <div className={`text-3xl font-bold ${color}`}>{value.toLocaleString()}</div>
    </div>
  );
}
