export default function Loading() {
  return (
    <div
      role="status"
      aria-label="Loading page"
      className="max-w-[1600px] mx-auto w-full space-y-6 animate-pulse"
    >
      <div className="h-8 w-56 rounded-lg bg-gray-200 dark:bg-slate-800" />
      <div className="h-32 rounded-2xl border border-gray-200 bg-white dark:border-[#273449] dark:bg-[#111827]" />
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className="h-56 rounded-2xl border border-gray-200 bg-white dark:border-[#273449] dark:bg-[#111827]" />
        <div className="h-56 rounded-2xl border border-gray-200 bg-white dark:border-[#273449] dark:bg-[#111827]" />
      </div>
      <div className="h-72 rounded-2xl border border-gray-200 bg-white dark:border-[#273449] dark:bg-[#111827]" />
      <span className="sr-only">Loading page content…</span>
    </div>
  );
}
