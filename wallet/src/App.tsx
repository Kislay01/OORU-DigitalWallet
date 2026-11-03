import { useEffect, useState } from "react";
import { Shell } from "./components/Shell";
import { CardDetail } from "./pages/CardDetail";
import { History } from "./pages/History";
import { Home } from "./pages/Home";
import { Setup, Unlock } from "./pages/Lock";
import { Scan } from "./pages/Scan";
import { Settings } from "./pages/Settings";
import { go, useRoute } from "./router";
import { useWallet } from "./wallet";

/** A link opened as ?link=<offer or request> is handled after the wallet is unlocked. */
function takeLaunchLink(): string | null {
  const link = new URLSearchParams(location.search).get("link");
  if (link) history.replaceState(null, "", location.pathname + location.hash);
  return link;
}

export default function App() {
  const { phase } = useWallet();
  const route = useRoute();
  const [pending, setPending] = useState<string | null>(takeLaunchLink);

  useEffect(() => { if (phase === "ready" && pending) go("/scan"); }, [phase, pending]);
  useEffect(() => { if (pending && phase === "ready" && route.startsWith("/scan")) { const t = setTimeout(() => setPending(null), 0); return () => clearTimeout(t); } }, [pending, phase, route]);

  if (phase === "loading") return <div className="flex min-h-screen items-center justify-center text-slate-400">Loading…</div>;
  if (phase === "setup") return <Setup />;
  if (phase === "locked") return <Unlock />;

  let page;
  if (route.startsWith("/card/")) page = <CardDetail id={decodeURIComponent(route.slice(6))} />;
  else if (route.startsWith("/scan")) page = <Scan initialLink={pending} />;
  else if (route.startsWith("/history")) page = <History />;
  else if (route.startsWith("/settings")) page = <Settings />;
  else page = <Home />;

  return <Shell route={route}>{page}</Shell>;
}
