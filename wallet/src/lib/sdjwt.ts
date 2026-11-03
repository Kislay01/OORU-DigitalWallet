import { b64urlDecode, fromUtf8, parseB64urlJson, sha256b64url } from "./b64";
import { importPublicJwk, signJwt, verifyJwtSignature } from "./crypto";

export interface Disclosure {
  raw: string;
  salt: string;
  name: string;
  value: unknown;
  digest: string;
}

export interface ParsedSdJwt {
  issuerJwt: string;
  header: Record<string, any>;
  payload: Record<string, any>;
  disclosures: Disclosure[];
}

export async function parseSdJwt(sdJwt: string): Promise<ParsedSdJwt> {
  const parts = sdJwt.trim().split("~");
  if (parts.length < 2) throw new Error("Not an SD-JWT credential");
  const [issuerJwt, ...rest] = parts;
  const [h, p] = issuerJwt.split(".");
  const header = parseB64urlJson(h);
  const payload = parseB64urlJson(p);
  const allowed = new Set<string>(payload._sd || []);

  const disclosures: Disclosure[] = [];
  for (const raw of rest.slice(0, -1).filter(Boolean)) {
    const [salt, name, value] = JSON.parse(fromUtf8(b64urlDecode(raw)));
    const digest = await sha256b64url(raw);
    if (!allowed.has(digest)) throw new Error(`Disclosure for "${name}" is not signed by the issuer`);
    disclosures.push({ raw, salt, name, value, digest });
  }
  return { issuerJwt, header, payload, disclosures };
}

/** Check the issuer's signature using the keys it publishes at /.well-known/jwt-vc-issuer. */
export async function verifyIssuerSignature(parsed: ParsedSdJwt, fetchFn: typeof fetch = fetch): Promise<boolean> {
  const iss: string = parsed.payload.iss;
  const res = await fetchFn(`${iss.replace(/\/+$/, "")}/.well-known/jwt-vc-issuer`);
  if (!res.ok) throw new Error("Could not fetch the issuer's public keys");
  const meta = await res.json();
  if (meta.issuer !== iss) throw new Error("Issuer metadata does not match the credential");
  const keys: any[] = meta.jwks?.keys || [];
  const jwk = keys.find((k) => k.kid === parsed.header.kid) || (keys.length === 1 ? keys[0] : null);
  if (!jwk) throw new Error("Issuer signing key not found");
  return verifyJwtSignature(parsed.issuerJwt, await importPublicJwk(jwk));
}

/** Build a presentation that reveals only `reveal`, bound to this verifier and request. */
export async function buildPresentation(opts: {
  sdJwt: string;
  reveal: string[];
  audience: string;
  nonce: string;
  holderPrivateKey: CryptoKey;
  now?: number;
}): Promise<{ presentation: string; disclosed: string[] }> {
  const parsed = await parseSdJwt(opts.sdJwt);
  const kept = parsed.disclosures.filter((d) => opts.reveal.includes(d.name));
  const presented = `${parsed.issuerJwt}~${kept.map((d) => `${d.raw}~`).join("")}`;
  const kb = await signJwt(
    opts.holderPrivateKey,
    { typ: "kb+jwt" },
    {
      aud: opts.audience,
      nonce: opts.nonce,
      iat: Math.floor((opts.now ?? Date.now()) / 1000),
      sd_hash: await sha256b64url(presented),
    },
  );
  return { presentation: presented + kb, disclosed: kept.map((d) => d.name) };
}
