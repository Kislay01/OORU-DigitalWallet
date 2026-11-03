/**
 * Wallet vault with two encryption layers.
 *
 * - Holder signing key: ECDSA P-256, non-extractable, stored as a CryptoKey object.
 * - Device layer: AES-GCM key generated on this device, non-extractable. Data copied
 *   off the device is useless without it.
 * - PIN layer: AES-GCM key derived from the user's PIN (PBKDF2-SHA256, 310k rounds).
 *   A stolen, unlocked device is useless without the PIN.
 *
 * Every record is encrypted with the PIN layer first, then the device layer.
 * The PIN key exists only in memory while the wallet is unlocked.
 */

import { b64urlDecode, b64urlEncode, fromUtf8, utf8 } from "./b64";
import { generateHolderKey, type HolderKey } from "./crypto";
import { idbClear, idbDel, idbGet, idbSet } from "./idb";

const PBKDF2_ROUNDS = 310_000;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 30_000;
const CHECK_VALUE = "ooru-campus-id-vault-v1";

interface Envelope { iv: string; ct: string }
interface Meta { salt: string; check: Envelope; failed: number; lockedUntil: number }

let pinKey: CryptoKey | null = null;

async function aesKeyFromPin(pin: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", utf8(pin) as BufferSource, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations: PBKDF2_ROUNDS },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function seal(key: CryptoKey, data: Uint8Array): Promise<Envelope> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, data as BufferSource);
  return { iv: b64urlEncode(iv), ct: b64urlEncode(ct) };
}

async function open(key: CryptoKey, env: Envelope): Promise<Uint8Array> {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64urlDecode(env.iv) as BufferSource }, key, b64urlDecode(env.ct) as BufferSource);
  return new Uint8Array(pt);
}

async function deviceKey(): Promise<CryptoKey> {
  const k = await idbGet<CryptoKey>("device_key");
  if (!k) throw new Error("Wallet is not set up on this device");
  return k;
}

export function validPin(pin: string): boolean {
  return /^\d{6}$/.test(pin);
}

export async function isSetUp(): Promise<boolean> {
  return !!(await idbGet("meta"));
}

export function isUnlocked(): boolean {
  return pinKey !== null;
}

export async function setUp(pin: string): Promise<void> {
  if (!validPin(pin)) throw new Error("PIN must be 6 digits");
  if (await isSetUp()) throw new Error("Wallet is already set up");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const dk = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  await idbSet("device_key", dk);
  const holder = await generateHolderKey();
  await idbSet("holder_key", holder);
  pinKey = await aesKeyFromPin(pin, salt);
  const meta: Meta = { salt: b64urlEncode(salt), check: await seal(pinKey, utf8(CHECK_VALUE)), failed: 0, lockedUntil: 0 };
  await idbSet("meta", meta);
}

export async function unlock(pin: string): Promise<void> {
  const meta = await idbGet<Meta>("meta");
  if (!meta) throw new Error("Wallet is not set up");
  if (meta.lockedUntil > Date.now()) {
    throw new Error(`Too many wrong attempts. Try again in ${Math.ceil((meta.lockedUntil - Date.now()) / 1000)}s`);
  }
  const key = await aesKeyFromPin(pin, b64urlDecode(meta.salt));
  try {
    if (fromUtf8(await open(key, meta.check)) !== CHECK_VALUE) throw new Error();
  } catch {
    meta.failed += 1;
    if (meta.failed >= MAX_ATTEMPTS) { meta.failed = 0; meta.lockedUntil = Date.now() + LOCKOUT_MS; }
    await idbSet("meta", meta);
    const left = meta.lockedUntil > Date.now() ? 0 : MAX_ATTEMPTS - meta.failed;
    throw new Error(left ? `Wrong PIN. ${left} attempt${left === 1 ? "" : "s"} left` : "Too many wrong attempts. Wallet locked for 30s");
  }
  meta.failed = 0; meta.lockedUntil = 0;
  await idbSet("meta", meta);
  pinKey = key;
}

export function lock(): void {
  pinKey = null;
}

function requireUnlocked(): CryptoKey {
  if (!pinKey) throw new Error("Wallet is locked");
  return pinKey;
}

export async function changePin(current: string, next: string): Promise<void> {
  if (!validPin(next)) throw new Error("New PIN must be 6 digits");
  await unlock(current);
  const records = await Promise.all(RECORDS.map(async (r) => [r, await readRecord(r)] as const));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  pinKey = await aesKeyFromPin(next, salt);
  const meta = (await idbGet<Meta>("meta"))!;
  meta.salt = b64urlEncode(salt);
  meta.check = await seal(pinKey, utf8(CHECK_VALUE));
  await idbSet("meta", meta);
  for (const [r, v] of records) if (v !== undefined) await writeRecord(r, v);
}

export async function holderKey(): Promise<HolderKey> {
  requireUnlocked();
  const k = await idbGet<HolderKey>("holder_key");
  if (!k) throw new Error("Holder key missing");
  return k;
}

const RECORDS = ["credentials", "receipts"] as const;
type RecordName = (typeof RECORDS)[number];

export async function readRecord<T = any>(name: RecordName): Promise<T | undefined> {
  const pk = requireUnlocked();
  const outer = await idbGet<Envelope>(`rec:${name}`);
  if (!outer) return undefined;
  const inner = JSON.parse(fromUtf8(await open(await deviceKey(), outer))) as Envelope;
  return JSON.parse(fromUtf8(await open(pk, inner)));
}

export async function writeRecord(name: RecordName, value: unknown): Promise<void> {
  const pk = requireUnlocked();
  const inner = await seal(pk, utf8(JSON.stringify(value)));
  const outer = await seal(await deviceKey(), utf8(JSON.stringify(inner)));
  await idbSet(`rec:${name}`, outer);
}

export async function deleteRecord(name: RecordName): Promise<void> {
  await idbDel(`rec:${name}`);
}

export async function wipe(): Promise<void> {
  pinKey = null;
  await idbClear();
}
