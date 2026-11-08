import { useEffect, useState } from "react";

const NAV_EVENT = "wallet:navigate";

export interface Route {
  path: string;
  /** Changes on every navigation, including to the page already open, so pages can reset. */
  key: number;
}

let navCount = 0;

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => ({ path: location.hash.slice(1) || "/", key: navCount }));
  useEffect(() => {
    const on = () => setRoute({ path: location.hash.slice(1) || "/", key: navCount });
    window.addEventListener("hashchange", on);
    window.addEventListener(NAV_EVENT, on);
    return () => {
      window.removeEventListener("hashchange", on);
      window.removeEventListener(NAV_EVENT, on);
    };
  }, []);
  return route;
}

/** Navigate to `path`. Tapping the tab you're already on starts that page fresh. */
export function go(path: string): void {
  navCount += 1;
  if ((location.hash.slice(1) || "/") === path) window.dispatchEvent(new Event(NAV_EVENT));
  else location.hash = path;
}
