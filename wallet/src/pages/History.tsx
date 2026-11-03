import { ArrowDownToLine, CheckCircle2, Download, Share2, ShieldAlert, ShieldCheck, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { FIELD_LABELS } from "../lib/campusId";
import type { ChainCheck, Receipt } from "../lib/receipts";
import { useWallet } from "../wallet";

const ICON = { credential_received: ArrowDownToLine, credential_shared: Share2, share_rejected: XCircle, status_checked: CheckCircle2 };
const TITLE = { credential_received: "Received ID from", credential_shared: "Shared with", share_rejected: "Share failed with", status_checked: "Checked status with" };

export function History() {
  const { receipts, verifyReceipts, holder } = useWallet();
  const [check, setCheck] = useState<ChainCheck | null>(null);
  useEffect(() => { verifyReceipts().then(setCheck).catch(() => setCheck({ ok: false, reason: "could not verify" })); }, [receipts, verifyReceipts]);

  const exportLog = () => {
    const blob = new Blob([JSON.stringify({ holder_key: holder?.jwk, receipts }, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `campus-id-activity-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const list = [...receipts].reverse();
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Activity</h2>
        {receipts.length > 0 && <button className="btn px-3 py-1.5 text-xs" onClick={exportLog}><Download size={14} /> Export</button>}
      </div>
      {check && receipts.length > 0 && (
        check.ok
          ? <div className="flex items-start gap-2 rounded-lg bg-emerald-50 p-3 text-sm text-emerald-800"><ShieldCheck size={18} className="shrink-0" /> All {receipts.length} receipts are signed by this wallet and unaltered.</div>
          : <div className="flex items-start gap-2 rounded-lg bg-red-50 p-3 text-sm text-red-700"><ShieldAlert size={18} className="shrink-0" /> Activity log check failed at entry {check.brokenAt}: {check.reason}.</div>
      )}
      {!list.length && <p className="mt-10 text-center text-sm text-slate-500">Nothing yet. Every ID you receive or share will show up here with a signed receipt.</p>}
      <ul className="space-y-3">
        {list.map((r) => <ReceiptRow key={r.seq} r={r} />)}
      </ul>
    </div>
  );
}

function ReceiptRow({ r }: { r: Receipt }) {
  const [open, setOpen] = useState(false);
  const Icon = ICON[r.event];
  const bad = r.event === "share_rejected" || (r.event === "credential_shared" && r.outcome !== "valid");
  return (
    <li className="card">
      <button className="flex w-full items-start gap-3 text-left" onClick={() => setOpen(!open)}>
        <span className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${bad ? "bg-red-50 text-red-600" : "bg-brand-soft text-brand"}`}><Icon size={16} /></span>
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-medium">{TITLE[r.event]} {r.counterparty}</span>
          <span className="block text-xs text-slate-500">{new Date(r.at).toLocaleString()}</span>
          {r.event !== "credential_received" && <span className="mt-1 block text-xs text-slate-600">{r.fields.map((f) => FIELD_LABELS[f] || f).join(", ") || "No fields"}</span>}
        </span>
        <span className={`text-xs font-semibold capitalize ${bad ? "text-red-600" : "text-emerald-700"}`}>{r.event === "share_rejected" ? "failed" : r.outcome}</span>
      </button>
      {open && (
        <dl className="mt-3 grid grid-cols-[auto,1fr] gap-x-3 gap-y-1 border-t border-slate-100 pt-3 font-mono text-[11px] text-slate-600">
          <dt>Receipt</dt><dd>#{r.seq}</dd>
          <dt>ID</dt><dd className="break-all">{r.credentialId}</dd>
          {r.event === "share_rejected" && <><dt>Reason</dt><dd className="break-all font-sans">{r.outcome}</dd></>}
          {r.payloadDigest && <><dt>Sent hash</dt><dd className="break-all">{r.payloadDigest}</dd></>}
          <dt>Prev</dt><dd className="break-all">{r.prevHash.slice(0, 24)}…</dd>
          <dt>Hash</dt><dd className="break-all">{r.hash.slice(0, 24)}…</dd>
        </dl>
      )}
    </li>
  );
}
