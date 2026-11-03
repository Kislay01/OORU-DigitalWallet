import { Plus, ScanLine } from "lucide-react";
import { CampusIdCard } from "../components/CampusIdCard";
import { go } from "../router";
import { useWallet } from "../wallet";

export function Home() {
  const { credentials } = useWallet();
  if (!credentials.length) {
    return (
      <div className="mt-10 text-center">
        <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-soft text-brand"><Plus size={28} /></div>
        <h2 className="text-lg font-semibold">No Campus ID yet</h2>
        <p className="mx-auto mt-1 max-w-xs text-sm text-slate-500">Ask your college office for your Campus ID QR, then scan it here.</p>
        <button className="btn btn-primary mt-6" onClick={() => go("/scan")}><ScanLine size={18} /> Scan to add</button>
      </div>
    );
  }
  return (
    <div className="space-y-4">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">My IDs</h2>
      {credentials.map((c) => (
        <button key={c.id} className="block w-full text-left" onClick={() => go(`/card/${c.id}`)}><CampusIdCard cred={c} /></button>
      ))}
      <button className="btn w-full" onClick={() => go("/scan")}><ScanLine size={18} /> Scan a QR to add or share</button>
    </div>
  );
}
