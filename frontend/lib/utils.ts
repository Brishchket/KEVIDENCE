export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function priorityColor(label: string): string {
  switch (label?.toUpperCase()) {
    case "CRITICAL": return "#ED7D24";
    case "HIGH":     return "#E85D5D";
    case "MEDIUM":   return "#F0B429";
    case "LOW":      return "#6BAB8C";
    default:         return "#9CA3AF";
  }
}

export function priorityBg(label: string): string {
  switch (label?.toUpperCase()) {
    case "CRITICAL": return "bg-[#ED7D24]";
    case "HIGH":     return "bg-[#E85D5D]";
    case "MEDIUM":   return "bg-[#F0B429]";
    case "LOW":      return "bg-[#6BAB8C]";
    default:         return "bg-gray-400";
  }
}

export function priorityLabel(label: string): string {
  switch (label?.toUpperCase()) {
    case "CRITICAL": return "C";
    case "HIGH":     return "H";
    case "MEDIUM":   return "M";
    case "LOW":      return "L";
    default:         return "?";
  }
}
