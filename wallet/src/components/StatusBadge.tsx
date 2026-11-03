const STYLES: Record<string, string> = {
  active: "bg-emerald-50 text-emerald-700 ring-emerald-200",
  valid: "bg-emerald-50 text-emerald-700 ring-emerald-200",
  revoked: "bg-red-50 text-red-700 ring-red-200",
  invalid: "bg-red-50 text-red-700 ring-red-200",
  expired: "bg-amber-50 text-amber-800 ring-amber-200",
  unknown: "bg-slate-100 text-slate-600 ring-slate-200",
};

export function StatusBadge({ status }: { status?: string }) {
  const s = status || "unknown";
  return <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold capitalize ring-1 ${STYLES[s] || STYLES.unknown}`}>{s}</span>;
}
