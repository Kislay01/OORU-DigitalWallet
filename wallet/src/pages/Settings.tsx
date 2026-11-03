import { KeyRound, Lock, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { jwkThumbprint } from "../lib/crypto";
import { validPin } from "../lib/vault";
import { useWallet } from "../wallet";

export function Settings() {
  const { holder, lock, changePin, wipe, credentials, receipts } = useWallet();
  const [thumb, setThumb] = useState("");
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (holder) jwkThumbprint(holder.jwk).then(setThumb); }, [holder]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setMsg(null);
    if (!validPin(next)) return setMsg({ ok: false, text: "New PIN must be 6 digits" });
    setBusy(true);
    try { await changePin(cur, next); setMsg({ ok: true, text: "PIN changed" }); setCur(""); setNext(""); }
    catch (err) { setMsg({ ok: false, text: (err as Error).message }); }
    finally { setBusy(false); }
  };

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Settings</h2>
      <div className="card space-y-2 text-sm">
        <h3 className="flex items-center gap-2 font-semibold"><KeyRound size={16} /> Wallet key</h3>
        <p className="text-slate-500">Your IDs are bound to this key. It was created on this device and can't be copied out of it.</p>
        <div className="break-all rounded-lg bg-slate-50 p-2 font-mono text-xs">{thumb || "…"}</div>
        <p className="text-xs text-slate-500">Storage: encrypted with a device key and your PIN (AES-256-GCM, two layers). {credentials.length} ID(s), {receipts.length} receipt(s).</p>
      </div>
      <form className="card space-y-3" onSubmit={submit}>
        <h3 className="font-semibold">Change PIN</h3>
        <input className="input" type="password" inputMode="numeric" maxLength={6} placeholder="Current PIN" value={cur} onChange={(e) => setCur(e.target.value.replace(/\D/g, ""))} />
        <input className="input" type="password" inputMode="numeric" maxLength={6} placeholder="New 6-digit PIN" value={next} onChange={(e) => setNext(e.target.value.replace(/\D/g, ""))} />
        {msg && <p className={`text-sm ${msg.ok ? "text-emerald-700" : "text-red-600"}`}>{msg.text}</p>}
        <button className="btn w-full" disabled={busy || cur.length !== 6}>{busy ? "Updating…" : "Update PIN"}</button>
      </form>
      <button className="btn w-full" onClick={lock}><Lock size={16} /> Lock now</button>
      <button className="btn btn-danger w-full" onClick={async () => { if (confirm("Erase this wallet? Your IDs, key and activity will be permanently deleted from this device.")) await wipe(); }}>
        <Trash2 size={16} /> Erase wallet
      </button>
    </div>
  );
}
