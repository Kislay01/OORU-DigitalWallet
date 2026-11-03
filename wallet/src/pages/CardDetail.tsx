import { ArrowLeft, RefreshCw, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { CampusIdCard } from "../components/CampusIdCard";
import { FIELD_LABELS, FIELD_ORDER } from "../lib/campusId";
import { go } from "../router";
import { useWallet } from "../wallet";

export function CardDetail({ id }: { id: string }) {
  const { credentials, refreshStatus, remove, receipts } = useWallet();
  const cred = credentials.find((c) => c.id === id);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const check = async () => {
    setChecking(true); setError(null);
    try { await refreshStatus(id); } catch (e) { setError((e as Error).message); } finally { setChecking(false); }
  };
  useEffect(() => { if (cred) check(); }, [id]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!cred) return <p className="text-slate-500">This ID is no longer in your wallet.</p>;
  const shares = receipts.filter((r) => r.credentialId === id && r.event === "credential_shared").length;
  const fmt = (t: number) => new Date(t).toLocaleString();

  return (
    <div className="space-y-4">
      <button className="flex items-center gap-1 text-sm text-slate-500" onClick={() => go("/")}><ArrowLeft size={16} /> Back</button>
      <CampusIdCard cred={cred} />
      {cred.lastStatus?.status === "revoked" && <div className="rounded-lg bg-red-50 p-3 text-sm text-red-700">Your college has revoked this ID. Verifiers will reject it.</div>}
      <div className="card">
        <div className="mb-2 flex items-center justify-between">
          <h3 className="font-semibold">Details</h3>
          <button className="flex items-center gap-1 text-xs text-brand" onClick={check} disabled={checking}><RefreshCw size={14} className={checking ? "animate-spin" : ""} /> Check status</button>
        </div>
        {error && <p className="mb-2 text-sm text-red-600">{error}</p>}
        <dl className="grid grid-cols-[auto,1fr] gap-x-4 gap-y-2 text-sm">
          {FIELD_ORDER.filter((f) => f !== "photo" && (cred.claims as any)[f]).map((f) => (
            <div key={f} className="contents"><dt className="text-slate-500">{FIELD_LABELS[f]}</dt><dd className="font-medium">{(cred.claims as any)[f]}</dd></div>
          ))}
          <dt className="text-slate-500">Issued by</dt><dd className="break-all font-medium">{cred.issuer}</dd>
          <dt className="text-slate-500">Received</dt><dd className="font-medium">{fmt(cred.receivedAt)}</dd>
          {cred.lastStatus && <><dt className="text-slate-500">Last checked</dt><dd className="font-medium">{fmt(cred.lastStatus.checkedAt)}</dd></>}
          <dt className="text-slate-500">Times shared</dt><dd className="font-medium">{shares}</dd>
        </dl>
      </div>
      <button className="btn btn-danger w-full" onClick={async () => { if (confirm("Remove this ID from your wallet? You'll need a new QR from your college to add it again.")) { await remove(id); go("/"); } }}>
        <Trash2 size={16} /> Remove from wallet
      </button>
    </div>
  );
}
