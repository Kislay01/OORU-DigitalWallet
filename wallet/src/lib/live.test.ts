/**
 * Full round trip against a running backend: issue → claim → share → verify → revoke.
 * Runs only when BACKEND_URL is set, e.g. BACKEND_URL=http://localhost:8000 npm test
 */
import { describe, expect, it } from "vitest";
import { generateHolderKey } from "./crypto";
import { checkStatus, claimCredential, parseCredentialOffer } from "./oid4vci";
import { parsePresentationRequest, sharePresentation } from "./oid4vp";

const BASE: string | undefined = (globalThis as any).process?.env?.BACKEND_URL;

async function login(u: string, p: string) {
  const r = await fetch(`${BASE}/api/v1/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: u, password: p }) });
  return { Authorization: `Bearer ${(await r.json()).access_token}`, "Content-Type": "application/json" };
}

describe.skipIf(!BASE)("live backend", () => {
  it("claims, shares selectively, and sees revocation", async () => {
    const admin = await login("admin", "admin123");
    const verifier = await login("verifier", "verifier123");
    const roll = `LIVE-${Date.now()}`;
    const valid = new Date(Date.now() + 200 * 864e5).toISOString().slice(0, 10);
    const offer = await (await fetch(`${BASE}/api/v1/issuer/offers`, { method: "POST", headers: admin, body: JSON.stringify({ name: "Live Test", roll_number: roll, branch: "IT", valid_until: valid }) })).json();

    const holder = await generateHolderKey();
    const { credential } = await claimCredential(await parseCredentialOffer(offer.credential_offer_uri), holder);
    expect(credential.claims.roll_number).toBe(roll);
    expect(await checkStatus(credential)).toBe("active");

    const req = await (await fetch(`${BASE}/api/v1/verifier/requests`, { method: "POST", headers: verifier, body: JSON.stringify({ requested_claims: ["name", "enrollment_status"] }) })).json();
    const parsed = await parsePresentationRequest(req.authorization_request_uri);
    const shared = await sharePresentation({ request: parsed, sdJwt: credential.sdJwt, reveal: ["name", "enrollment_status"], holderPrivateKey: holder.privateKey });
    expect(shared.status).toBe("valid");

    const result = await (await fetch(`${BASE}/api/v1/verifier/requests/${req.request_id}`, { headers: verifier })).json();
    expect(Object.keys(result.result.claims).sort()).toEqual(["enrollment_status", "name"]);

    await fetch(`${BASE}/api/v1/credentials/${credential.id}/revoke`, { method: "POST", headers: admin, body: "{}" });
    expect(await checkStatus(credential)).toBe("revoked");
  });
});
