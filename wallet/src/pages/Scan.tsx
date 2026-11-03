import { AlertTriangle, ArrowLeft, CheckCircle2, ClipboardPaste, EyeOff, Loader2, ShieldAlert, XCircle } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { CampusIdCard } from "../components/CampusIdCard";
import { QrScanner } from "../components/QrScanner";
import { FIELD_LABELS, FIELD_ORDER, type StoredCredential } from "../lib/campusId";
import { isCredentialOffer, parseCredentialOffer, type CredentialOffer } from "../lib/oid4vci";
import { isPresentationRequest, parsePresentationRequest, responseUriTrusted, type PresentationRequest } from "../lib/oid4vp";
import { go } from "../router";
import { useWallet } from "../wallet";

type Step =
  | { kind: "input" }
  | { kind: "working"; text: string }
  | { kind: "offer"; offer: CredentialOffer; raw: string }
  | { kind: "added"; cred: StoredCredential }
  | { kind: "consent"; req: PresentationRequest }
  | { kind: "shared"; status: string; verifier: string; fields: string[] }
  | { kind: "error"; message: string };

export function Scan({ initialLink }: { initialLink?: string | null }) {
  const [step, setStep] = useState<Step>({ kind: "input" });
  const [paste, setPaste] = useState("");

  const handle = useCallback(async (text: string) => {
    const t = text.trim();
    if (!t) return;
    try {
      if (isCredentialOffer(t)) {
        setStep({ kind: "working", text: "Reading the offer…" });
        setStep({ kind: "offer", offer: await parseCredentialOffer(t), raw: t });
      } else if (isPresentationRequest(t)) {
        setStep({ kind: "working", text: "Reading the request…" });
        setStep({ kind: "consent", req: await parsePresentationRequest(t) });
      } else {
        setStep({ kind: "error", message: "This QR isn't a Campus ID offer or an ID check request." });
      }
    } catch (e) {
      setStep({ kind: "error", message: (e as Error).message });
    }
  }, []);

  useEffect(() => { if (initialLink) handle(initialLink); }, [initialLink, handle]);

  const back = () => { setPaste(""); setStep({ kind: "input" }); };

  switch (step.kind) {
    case "input":
      return (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold">Scan a QR</h2>
            <p className="text-sm text-slate-500">Scan your college's QR to add your ID, or a verifier's QR to share it.</p>
          </div>
          <QrScanner onResult={handle} />
          <div className="card space-y-2">
            <label className="label" htmlFor="paste">Or paste a link</label>
            <textarea id="paste" className="input min-h-20 font-mono text-xs" placeholder="openid-credential-offer://… or openid4vp://…" value={paste} onChange={(e) => setPaste(e.target.value)} />
            <button className="btn w-full" disabled={!paste.trim()} onClick={() => handle(paste)}><ClipboardPaste size={16} /> Continue</button>
          </div>
        </div>
      );
    case "working":
      return <div className="mt-20 flex flex-col items-center gap-3 text-slate-500"><Loader2 className="animate-spin" size={28} />{step.text}</div>;
    case "error":
      return (
        <div className="mt-10 space-y-4 text-center">
          <XCircle className="mx-auto text-red-600" size={40} />
          <p className="text-slate-700">{step.message}</p>
          <button className="btn" onClick={back}>Try again</button>
        </div>
      );
    case "offer":
      return <OfferStep offer={step.offer} raw={step.raw} onBack={back} onDone={(cred) => setStep({ kind: "added", cred })} onError={(m) => setStep({ kind: "error", message: m })} />;
    case "added":
      return (
        <div className="space-y-4">
          <div className="flex items-center gap-2 text-emerald-700"><CheckCircle2 size={22} /><h2 className="text-lg font-semibold">Campus ID added</h2></div>
          <p className="text-sm text-slate-500">The college's signature was checked and the ID is bound to this wallet's key.</p>
          <CampusIdCard cred={step.cred} />
          <button className="btn btn-primary w-full" onClick={() => go("/")}>Go to wallet</button>
        </div>
      );
    case "consent":
      return <ConsentStep req={step.req} onBack={back} onDone={(status, fields) => setStep({ kind: "shared", status, verifier: step.req.verifierName, fields })} onError={(m) => setStep({ kind: "error", message: m })} />;
    case "shared": {
      const ok = step.status === "valid";
      return (
        <div className="mt-6 space-y-4 text-center">
          {ok ? <CheckCircle2 className="mx-auto text-emerald-600" size={48} /> : <XCircle className="mx-auto text-red-600" size={48} />}
          <h2 className="text-lg font-semibold">{ok ? "ID accepted" : step.status === "revoked" ? "ID was rejected: revoked" : "ID was not accepted"}</h2>
          <p className="text-sm text-slate-500">
            {step.verifier} received: {step.fields.map((f) => FIELD_LABELS[f] || f).join(", ") || "no fields"}.
          </p>
          <p className="text-xs text-slate-400">A signed receipt was added to your activity.</p>
          <div className="flex justify-center gap-2"><button className="btn" onClick={() => go("/history")}>View activity</button><button className="btn btn-primary" onClick={() => go("/")}>Done</button></div>
        </div>
      );
    }
  }
}

function OfferStep({ offer, raw, onBack, onDone, onError }: { offer: CredentialOffer; raw: string; onBack: () => void; onDone: (c: StoredCredential) => void; onError: (m: string) => void }) {
  const { claim } = useWallet();
  const [busy, setBusy] = useState(false);
  const accept = async () => {
    setBusy(true);
    try { onDone(await claim(raw)); } catch (e) { onError((e as Error).message); }
  };
  return (
    <div className="space-y-4">
      <button className="flex items-center gap-1 text-sm text-slate-500" onClick={onBack}><ArrowLeft size={16} /> Back</button>
      <h2 className="text-lg font-semibold">Add a Campus ID?</h2>
      <div className="card space-y-1 text-sm">
        <div className="text-slate-500">Offered by</div>
        <div className="break-all font-medium">{offer.credentialIssuer}</div>
      </div>
      <p className="text-sm text-slate-500">Your wallet will prove it holds its own key, receive the signed ID, check the college's signature and store it encrypted on this device. The offer can only be used once.</p>
      <button className="btn btn-primary w-full" onClick={accept} disabled={busy}>{busy ? <><Loader2 size={16} className="animate-spin" /> Adding…</> : "Add to wallet"}</button>
    </div>
  );
}

function ConsentStep({ req, onBack, onDone, onError }: { req: PresentationRequest; onBack: () => void; onDone: (status: string, fields: string[]) => void; onError: (m: string) => void }) {
  const { credentials, share } = useWallet();
  const usable = credentials.filter((c) => c.lastStatus?.status !== "revoked" && c.expiresAt > Date.now());
  const [credId, setCredId] = useState(usable[0]?.id || "");
  const requested = FIELD_ORDER.filter((f) => req.requestedFields.includes(f));
  const [picked, setPicked] = useState<string[]>(requested);
  const [busy, setBusy] = useState(false);
  const trusted = responseUriTrusted(req);
  const cred = credentials.find((c) => c.id === credId);
  const privateFields = FIELD_ORDER.filter((f) => !requested.includes(f) && cred && (cred.claims as any)[f]);
  const missing = requested.filter((f) => !picked.includes(f));

  if (!usable.length) {
    return (
      <div className="mt-10 space-y-3 text-center">
        <AlertTriangle className="mx-auto text-amber-600" size={40} />
        <p className="text-slate-700">You don't have a valid Campus ID to share. {credentials.length ? "Your ID is revoked or expired." : "Add one first."}</p>
        <button className="btn" onClick={onBack}>Back</button>
      </div>
    );
  }

  const submit = async () => {
    setBusy(true);
    try {
      const r = await share(req, credId, picked);
      onDone(r.status, r.disclosed);
    } catch (e) { onError((e as Error).message); }
  };

  return (
    <div className="space-y-4">
      <button className="flex items-center gap-1 text-sm text-slate-500" onClick={onBack}><ArrowLeft size={16} /> Back</button>
      <div>
        <div className="text-sm text-slate-500">ID check from</div>
        <h2 className="text-lg font-semibold">{req.verifierName}</h2>
        <div className="break-all text-xs text-slate-400">{req.clientId}</div>
      </div>
      {!trusted && (
        <div className="flex gap-2 rounded-lg bg-red-50 p-3 text-sm text-red-700"><ShieldAlert size={18} className="shrink-0" /> This request would send your data to a different site than the verifier's. Sharing is blocked.</div>
      )}
      {usable.length > 1 && (
        <select className="input" value={credId} onChange={(e) => setCredId(e.target.value)}>
          {usable.map((c) => <option key={c.id} value={c.id}>{c.claims.name} · {c.id}</option>)}
        </select>
      )}
      <div className="card">
        <h3 className="mb-1 font-semibold">They're asking for</h3>
        <p className="mb-3 text-xs text-slate-500">Turn off anything you don't want to share. They may reject the check if a requested field is missing.</p>
        <ul className="divide-y divide-slate-100">
          {requested.map((f) => {
            const on = picked.includes(f);
            const value = cred ? (cred.claims as any)[f] : undefined;
            return (
              <li key={f} className="flex items-center justify-between gap-3 py-2.5">
                <div className="min-w-0">
                  <div className="text-sm font-medium">{FIELD_LABELS[f]}</div>
                  <div className="truncate text-xs text-slate-500">{f === "photo" ? (value ? "Your photo" : "Not on your ID") : value ?? "Not on your ID"}</div>
                </div>
                <button
                  role="switch" aria-checked={on} aria-label={`Share ${FIELD_LABELS[f]}`}
                  onClick={() => setPicked((p) => (on ? p.filter((x) => x !== f) : [...p, f]))}
                  className={`relative h-6 w-11 shrink-0 rounded-full transition ${on ? "bg-brand" : "bg-slate-300"}`}
                >
                  <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition ${on ? "left-[22px]" : "left-0.5"}`} />
                </button>
              </li>
            );
          })}
        </ul>
      </div>
      {privateFields.length > 0 && (
        <div className="flex gap-2 text-xs text-slate-500"><EyeOff size={14} className="mt-0.5 shrink-0" /> Kept private: {privateFields.map((f) => FIELD_LABELS[f]).join(", ")}</div>
      )}
      {missing.length > 0 && <div className="rounded-lg bg-amber-50 p-3 text-xs text-amber-800">Not sharing {missing.map((f) => FIELD_LABELS[f]).join(", ")}. The verifier will likely reject this check.</div>}
      <button className="btn btn-primary w-full" onClick={submit} disabled={busy || !trusted || !picked.length}>
        {busy ? <><Loader2 size={16} className="animate-spin" /> Sharing…</> : `Share ${picked.length} field${picked.length === 1 ? "" : "s"}`}
      </button>
    </div>
  );
}
