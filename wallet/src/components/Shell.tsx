import { History, Lock, ScanLine, Settings, WalletCards } from "lucide-react";
import type { ReactNode } from "react";
import { go } from "../router";
import { useWallet } from "../wallet";

const TABS = [
  { path: "/", label: "Wallet", icon: WalletCards },
  { path: "/scan", label: "Scan", icon: ScanLine },
  { path: "/history", label: "Activity", icon: History },
  { path: "/settings", label: "Settings", icon: Settings },
];

export function Shell({ route, children }: { route: string; children: ReactNode }) {
  const { lock } = useWallet();
  const active = (p: string) => (p === "/" ? route === "/" || route.startsWith("/card") : route.startsWith(p));
  return (
    <div className="mx-auto flex min-h-screen max-w-md flex-col bg-slate-50">
      <header className="sticky top-0 z-10 flex items-center justify-between bg-brand px-4 py-3 text-white">
        <div>
          <div className="text-base font-semibold leading-tight">Campus ID Wallet</div>
          <div className="text-xs text-blue-200">OORU Digital Identity</div>
        </div>
        <button onClick={lock} className="rounded-lg p-2 text-blue-100 hover:bg-white/10" aria-label="Lock wallet"><Lock size={18} /></button>
      </header>
      <main className="flex-1 px-4 pb-24 pt-4">{children}</main>
      <nav className="fixed inset-x-0 bottom-0 z-10 mx-auto flex max-w-md border-t border-slate-200 bg-white pb-[env(safe-area-inset-bottom)]">
        {TABS.map(({ path, label, icon: Icon }) => (
          <button key={path} onClick={() => go(path)} className={`flex flex-1 flex-col items-center gap-0.5 py-2.5 text-xs ${active(path) ? "font-semibold text-brand" : "text-slate-500"}`}>
            <Icon size={20} /> {label}
          </button>
        ))}
      </nav>
    </div>
  );
}
