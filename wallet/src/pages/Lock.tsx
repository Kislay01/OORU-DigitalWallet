import { ShieldCheck } from "lucide-react";
import { useState } from "react";
import { PinPad } from "../components/PinPad";
import { useWallet } from "../wallet";

export function Setup() {
  const { setUp } = useWallet();
  const [first, setFirst] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [started, setStarted] = useState(false);

  if (!started) {
    return (
      <div className="mx-auto flex min-h-screen max-w-md flex-col justify-center px-6">
        <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-2xl bg-brand text-white"><ShieldCheck size={32} /></div>
        <h1 className="text-center text-2xl font-semibold">Campus ID Wallet</h1>
        <p className="mt-2 text-center text-slate-500">Keep your college ID on your phone and share only what's needed.</p>
        <ul className="mt-8 space-y-3 text-sm text-slate-700">
          <li className="card">Your ID stays on this device, encrypted with a key that never leaves it and your PIN.</li>
          <li className="card">When someone checks your ID, you choose exactly which fields they see.</li>
          <li className="card">Every share is recorded in a signed activity log you can verify.</li>
        </ul>
        <button className="btn btn-primary mt-8 w-full" onClick={() => setStarted(true)}>Set up wallet</button>
      </div>
    );
  }

  const complete = async (pin: string) => {
    if (!first) { setFirst(pin); setError(null); return; }
    if (pin !== first) { setFirst(null); setError("PINs didn't match. Start again."); return; }
    setBusy(true);
    try { await setUp(pin); } catch (e) { setError((e as Error).message); setFirst(null); } finally { setBusy(false); }
  };
  return (
    <div className="flex min-h-screen items-center px-6">
      <PinPad key={first ? "confirm" : "create"} title={first ? "Confirm your PIN" : "Create a 6-digit PIN"} subtitle="You'll use it to open the wallet and approve shares." error={error} busy={busy} onComplete={complete} />
    </div>
  );
}

export function Unlock() {
  const { unlock } = useWallet();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const complete = async (pin: string) => {
    setBusy(true);
    try { await unlock(pin); } catch (e) { setError((e as Error).message); setAttempt((a) => a + 1); } finally { setBusy(false); }
  };
  return (
    <div className="flex min-h-screen items-center px-6">
      <PinPad key={attempt} title="Enter your PIN" subtitle="Your wallet is locked." error={error} busy={busy} onComplete={complete} />
    </div>
  );
}
