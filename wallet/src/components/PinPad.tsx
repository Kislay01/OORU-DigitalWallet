import { Delete } from "lucide-react";
import { useEffect, useState } from "react";

export function PinPad({ title, subtitle, error, busy, onComplete }: {
  title: string; subtitle?: string; error?: string | null; busy?: boolean; onComplete: (pin: string) => void;
}) {
  const [pin, setPin] = useState("");
  useEffect(() => { if (error) setPin(""); }, [error]);
  useEffect(() => { if (pin.length === 6) onComplete(pin); }, [pin]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (busy) return;
      if (/^\d$/.test(e.key)) setPin((p) => (p.length < 6 ? p + e.key : p));
      if (e.key === "Backspace") setPin((p) => p.slice(0, -1));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy]);

  const press = (d: string) => !busy && setPin((p) => (p.length < 6 ? p + d : p));
  return (
    <div className="mx-auto flex max-w-xs flex-col items-center">
      <h1 className="text-xl font-semibold">{title}</h1>
      {subtitle && <p className="mt-1 text-center text-sm text-slate-500">{subtitle}</p>}
      <div className="my-6 flex gap-3" aria-label={`${pin.length} of 6 digits entered`}>
        {Array.from({ length: 6 }).map((_, i) => (
          <span key={i} className={`h-3.5 w-3.5 rounded-full border-2 ${i < pin.length ? "border-brand bg-brand" : "border-slate-300"}`} />
        ))}
      </div>
      <p className="mb-4 min-h-5 text-center text-sm text-red-600" role="alert">{busy ? <span className="text-slate-500">Checking…</span> : error}</p>
      <div className="grid w-full grid-cols-3 gap-3">
        {["1", "2", "3", "4", "5", "6", "7", "8", "9"].map((d) => (
          <button key={d} type="button" onClick={() => press(d)} className="h-14 rounded-xl border border-slate-200 bg-white text-xl font-medium shadow-sm active:bg-slate-100">{d}</button>
        ))}
        <span />
        <button type="button" onClick={() => press("0")} className="h-14 rounded-xl border border-slate-200 bg-white text-xl font-medium shadow-sm active:bg-slate-100">0</button>
        <button type="button" aria-label="Delete digit" onClick={() => setPin((p) => p.slice(0, -1))} className="flex h-14 items-center justify-center rounded-xl text-slate-500 active:bg-slate-100"><Delete size={22} /></button>
      </div>
    </div>
  );
}
