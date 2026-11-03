import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { StoredCredential } from "./lib/campusId";
import type { HolderKey } from "./lib/crypto";
import { checkStatus, claimCredential, parseCredentialOffer } from "./lib/oid4vci";
import { sharePresentation, type PresentationRequest, type ShareResult } from "./lib/oid4vp";
import { appendReceipt, verifyChain, type ChainCheck, type Receipt } from "./lib/receipts";
import * as vault from "./lib/vault";

const IDLE_LOCK_MS = 5 * 60_000;

type Phase = "loading" | "setup" | "locked" | "ready";

interface WalletState {
  phase: Phase;
  credentials: StoredCredential[];
  receipts: Receipt[];
  holder: HolderKey | null;
  setUp(pin: string): Promise<void>;
  unlock(pin: string): Promise<void>;
  lock(): void;
  claim(offerText: string): Promise<StoredCredential>;
  share(req: PresentationRequest, credentialId: string, fields: string[]): Promise<ShareResult>;
  refreshStatus(id: string): Promise<string>;
  remove(id: string): Promise<void>;
  verifyReceipts(): Promise<ChainCheck>;
  changePin(current: string, next: string): Promise<void>;
  wipe(): Promise<void>;
}

const Ctx = createContext<WalletState | null>(null);

export function useWallet(): WalletState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useWallet outside provider");
  return v;
}

export function WalletProvider({ children }: { children: ReactNode }) {
  const [phase, setPhase] = useState<Phase>("loading");
  const [credentials, setCredentials] = useState<StoredCredential[]>([]);
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [holder, setHolder] = useState<HolderKey | null>(null);
  const receiptsRef = useRef<Receipt[]>([]);
  const credsRef = useRef<StoredCredential[]>([]);

  useEffect(() => {
    vault.isSetUp().then((ok) => setPhase(ok ? "locked" : "setup")).catch(() => setPhase("setup"));
  }, []);

  const load = useCallback(async () => {
    const [c, r, h] = await Promise.all([vault.readRecord<StoredCredential[]>("credentials"), vault.readRecord<Receipt[]>("receipts"), vault.holderKey()]);
    credsRef.current = c || [];
    receiptsRef.current = r || [];
    setCredentials(credsRef.current);
    setReceipts(receiptsRef.current);
    setHolder(h);
    setPhase("ready");
  }, []);

  const saveCreds = async (next: StoredCredential[]) => {
    credsRef.current = next;
    setCredentials(next);
    await vault.writeRecord("credentials", next);
  };

  const addReceipt = async (h: HolderKey, entry: Parameters<typeof appendReceipt>[2]) => {
    const next = await appendReceipt(receiptsRef.current, h, entry);
    receiptsRef.current = next;
    setReceipts(next);
    await vault.writeRecord("receipts", next);
  };

  const lock = useCallback(() => {
    vault.lock();
    setHolder(null);
    setCredentials([]);
    setReceipts([]);
    credsRef.current = [];
    receiptsRef.current = [];
    setPhase((p) => (p === "ready" ? "locked" : p));
  }, []);

  // auto-lock when idle
  useEffect(() => {
    if (phase !== "ready") return;
    let t = setTimeout(lock, IDLE_LOCK_MS);
    const bump = () => { clearTimeout(t); t = setTimeout(lock, IDLE_LOCK_MS); };
    const events = ["pointerdown", "keydown", "scroll"];
    events.forEach((e) => window.addEventListener(e, bump, { passive: true }));
    return () => { clearTimeout(t); events.forEach((e) => window.removeEventListener(e, bump)); };
  }, [phase, lock]);

  const value = useMemo<WalletState>(() => ({
    phase, credentials, receipts, holder,
    async setUp(pin) { await vault.setUp(pin); await load(); },
    async unlock(pin) { await vault.unlock(pin); await load(); },
    lock,
    async claim(offerText) {
      const h = await vault.holderKey();
      const offer = await parseCredentialOffer(offerText);
      const { credential, issuerName } = await claimCredential(offer, h);
      credential.lastStatus = { status: "active", checkedAt: Date.now() };
      await saveCreds([credential, ...credsRef.current.filter((c) => c.id !== credential.id)]);
      await addReceipt(h, { event: "credential_received", counterparty: issuerName, credentialId: credential.id, fields: Object.keys(credential.claims), outcome: "stored", payload: credential.sdJwt });
      return credential;
    },
    async share(req, credentialId, fields) {
      const h = await vault.holderKey();
      const cred = credsRef.current.find((c) => c.id === credentialId);
      if (!cred) throw new Error("Credential not found");
      try {
        const res = await sharePresentation({ request: req, sdJwt: cred.sdJwt, reveal: fields, holderPrivateKey: h.privateKey });
        await addReceipt(h, { event: "credential_shared", counterparty: req.verifierName, credentialId, fields: res.disclosed, outcome: res.status, payload: res.presentation });
        return res;
      } catch (e) {
        await addReceipt(h, { event: "share_rejected", counterparty: req.verifierName, credentialId, fields, outcome: (e as Error).message.slice(0, 120) });
        throw e;
      }
    },
    async refreshStatus(id) {
      const cred = credsRef.current.find((c) => c.id === id);
      if (!cred) throw new Error("Credential not found");
      const status = await checkStatus(cred);
      await saveCreds(credsRef.current.map((c) => (c.id === id ? { ...c, lastStatus: { status, checkedAt: Date.now() } } : c)));
      return status;
    },
    async remove(id) { await saveCreds(credsRef.current.filter((c) => c.id !== id)); },
    async verifyReceipts() {
      const h = await vault.holderKey();
      return verifyChain(receiptsRef.current, h.jwk);
    },
    async changePin(current, next) { await vault.changePin(current, next); },
    async wipe() { await vault.wipe(); setHolder(null); setCredentials([]); setReceipts([]); setPhase("setup"); },
  }), [phase, credentials, receipts, holder, load, lock]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
