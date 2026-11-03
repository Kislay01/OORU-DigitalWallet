import { GraduationCap, UserRound } from "lucide-react";
import type { StoredCredential } from "../lib/campusId";
import { StatusBadge } from "./StatusBadge";

export function CampusIdCard({ cred, compact }: { cred: StoredCredential; compact?: boolean }) {
  const c = cred.claims;
  const status = cred.expiresAt < Date.now() ? "expired" : cred.lastStatus?.status;
  const dim = status === "revoked" || status === "expired";
  return (
    <div className={`relative overflow-hidden rounded-2xl bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-700 p-5 text-white shadow-lg ${dim ? "opacity-70 grayscale-[40%]" : ""}`}>
      <div className="pointer-events-none absolute -right-10 -top-10 h-40 w-40 rounded-full bg-white/10" />
      <div className="pointer-events-none absolute -bottom-16 -left-8 h-44 w-44 rounded-full bg-white/5" />
      <div className="relative flex items-start justify-between">
        <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-blue-100">
          <GraduationCap size={16} /> Campus ID
        </div>
        <StatusBadge status={status} />
      </div>
      <div className="relative mt-4 flex items-center gap-4">
        {c.photo ? (
          <img src={`data:image/jpeg;base64,${c.photo}`} alt="" className="h-16 w-16 rounded-xl border-2 border-white/40 object-cover" />
        ) : (
          <div className="flex h-16 w-16 items-center justify-center rounded-xl bg-white/15"><UserRound size={30} /></div>
        )}
        <div className="min-w-0">
          <div className="truncate text-lg font-semibold">{c.name}</div>
          <div className="text-sm text-blue-100">{c.branch}</div>
        </div>
      </div>
      {!compact && (
        <div className="relative mt-5 grid grid-cols-3 gap-2 text-xs">
          <div><div className="text-blue-200">Roll no.</div><div className="font-semibold">{c.roll_number}</div></div>
          <div><div className="text-blue-200">Status</div><div className="font-semibold capitalize">{c.enrollment_status}</div></div>
          <div><div className="text-blue-200">Valid until</div><div className="font-semibold">{c.valid_until}</div></div>
        </div>
      )}
      <div className="relative mt-4 font-mono text-[11px] text-blue-200">{cred.id}</div>
    </div>
  );
}
