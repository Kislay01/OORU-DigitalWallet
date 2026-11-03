import { b64urlDecode, b64urlEncode, b64urlJson, sha256b64url, utf8 } from "./b64";

export type PublicJwk = { kty: "EC"; crv: "P-256"; x: string; y: string };

export interface HolderKey {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  jwk: PublicJwk;
}

const ECDSA = { name: "ECDSA", namedCurve: "P-256" } as const;

/** The private key is non-extractable: it can sign, but its bytes can never be read back out. */
export async function generateHolderKey(): Promise<HolderKey> {
  const pair = (await crypto.subtle.generateKey(ECDSA, false, ["sign", "verify"])) as CryptoKeyPair;
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, jwk: await exportPublicJwk(pair.publicKey) };
}

export async function exportPublicJwk(key: CryptoKey): Promise<PublicJwk> {
  const j = await crypto.subtle.exportKey("jwk", key);
  return { kty: "EC", crv: "P-256", x: j.x!, y: j.y! };
}

export async function importPublicJwk(jwk: { x: string; y: string }): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, ext: true }, ECDSA, true, ["verify"]);
}

export async function signJwt(privateKey: CryptoKey, header: Record<string, unknown>, payload: Record<string, unknown>): Promise<string> {
  const input = `${b64urlJson({ alg: "ES256", ...header })}.${b64urlJson(payload)}`;
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, utf8(input) as BufferSource);
  return `${input}.${b64urlEncode(sig)}`;
}

export async function verifyJwtSignature(jwt: string, publicKey: CryptoKey): Promise<boolean> {
  const [h, p, s] = jwt.split(".");
  if (!h || !p || !s) return false;
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, b64urlDecode(s) as BufferSource, utf8(`${h}.${p}`) as BufferSource);
}

export async function signBytes(privateKey: CryptoKey, data: string): Promise<string> {
  return b64urlEncode(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, utf8(data) as BufferSource));
}

export async function verifyBytes(publicKey: CryptoKey, data: string, sig: string): Promise<boolean> {
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, b64urlDecode(sig) as BufferSource, utf8(data) as BufferSource);
}

/** RFC 7638 thumbprint — a short, stable ID for the holder key. */
export async function jwkThumbprint(jwk: PublicJwk): Promise<string> {
  return sha256b64url(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }));
}
