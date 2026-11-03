/**
 * Tamper-evident receipts for everything the wallet sends or receives.
 *
 * Each receipt records what happened (claimed, shared, share failed), with whom,
 * which fields (names only, never values) and a SHA-256 digest of exactly what was sent.
 * Receipts are hash-chained (each one includes the previous receipt's hash) and signed
 * with the holder key, so editing, deleting or reordering any entry is detectable.
 */

import { canonicalJson, sha256hex } from "./b64";
import { importPublicJwk, signBytes, verifyBytes, type HolderKey } from "./crypto";

export type ReceiptEvent = "credential_received" | "credential_shared" | "share_rejected" | "status_checked";

export interface ReceiptBody {
  seq: number;
  event: ReceiptEvent;
  at: number;
  counterparty: string;
  credentialId: string;
  fields: string[];
  outcome: string;
  payloadDigest: string | null;
  prevHash: string;
}

export interface Receipt extends ReceiptBody {
  hash: string;
  signature: string;
}

export const GENESIS = "0".repeat(64);

export async function appendReceipt(
  chain: Receipt[],
  holder: HolderKey,
  entry: { event: ReceiptEvent; counterparty: string; credentialId: string; fields: string[]; outcome: string; payload?: string },
): Promise<Receipt[]> {
  const prev = chain[chain.length - 1];
  const body: ReceiptBody = {
    seq: prev ? prev.seq + 1 : 1,
    event: entry.event,
    at: Date.now(),
    counterparty: entry.counterparty,
    credentialId: entry.credentialId,
    fields: [...entry.fields].sort(),
    outcome: entry.outcome,
    payloadDigest: entry.payload ? await sha256hex(entry.payload) : null,
    prevHash: prev ? prev.hash : GENESIS,
  };
  const canonical = canonicalJson(body);
  const receipt: Receipt = { ...body, hash: await sha256hex(canonical), signature: await signBytes(holder.privateKey, canonical) };
  return [...chain, receipt];
}

export interface ChainCheck {
  ok: boolean;
  brokenAt?: number;
  reason?: string;
}

export async function verifyChain(chain: Receipt[], holderJwk: { x: string; y: string }): Promise<ChainCheck> {
  const pub = await importPublicJwk(holderJwk);
  let prevHash = GENESIS;
  for (let i = 0; i < chain.length; i++) {
    const { hash, signature, ...body } = chain[i];
    if (body.seq !== i + 1) return { ok: false, brokenAt: body.seq, reason: "entries are missing or out of order" };
    if (body.prevHash !== prevHash) return { ok: false, brokenAt: body.seq, reason: "chain link does not match the previous entry" };
    const canonical = canonicalJson(body);
    if ((await sha256hex(canonical)) !== hash) return { ok: false, brokenAt: body.seq, reason: "entry was edited" };
    if (!(await verifyBytes(pub, canonical, signature))) return { ok: false, brokenAt: body.seq, reason: "signature is not valid" };
    prevHash = hash;
  }
  return { ok: true };
}
