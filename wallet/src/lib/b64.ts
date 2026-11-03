export function b64urlEncode(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export const utf8 = (s: string) => new TextEncoder().encode(s);
export const fromUtf8 = (b: Uint8Array) => new TextDecoder().decode(b);
export const b64urlJson = (v: unknown) => b64urlEncode(utf8(JSON.stringify(v)));
export const parseB64urlJson = <T = any>(s: string): T => JSON.parse(fromUtf8(b64urlDecode(s)));

export async function sha256b64url(input: string | Uint8Array): Promise<string> {
  const data = typeof input === "string" ? utf8(input) : input;
  return b64urlEncode(await crypto.subtle.digest("SHA-256", data as BufferSource));
}

export async function sha256hex(input: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(input) as BufferSource));
  return [...d].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/** Deterministic JSON (sorted keys) so hashes and signatures over objects are stable. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).sort().filter((k) => o[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(",")}}`;
}
