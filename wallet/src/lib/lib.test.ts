import { beforeEach, describe, expect, it } from "vitest";
import { b64urlJson, canonicalJson, parseB64urlJson, sha256b64url } from "./b64";
import { generateHolderKey, signJwt, verifyJwtSignature, importPublicJwk } from "./crypto";
import { parseCredentialOffer, toStoredCredential } from "./oid4vci";
import { parsePresentationRequest, responseUriTrusted } from "./oid4vp";
import { appendReceipt, verifyChain, type Receipt } from "./receipts";
import { buildPresentation, parseSdJwt } from "./sdjwt";
import * as vault from "./vault";

const ISS = "http://issuer.test";

async function fakeIssuer(holderJwk: { x: string; y: string }, claims: Record<string, unknown>) {
  const issuer = await generateHolderKey();
  const disclosures: string[] = [];
  const digests: string[] = [];
  for (const [k, v] of Object.entries(claims)) {
    const d = b64urlJson([`salt-${k}`, k, v]);
    disclosures.push(d);
    digests.push(await sha256b64url(d));
  }
  const jwt = await signJwt(issuer.privateKey, { typ: "vc+sd-jwt", kid: "k1" }, {
    iss: ISS, vct: "CampusID", iat: 1, exp: 4102444800, credential_id: "CID-TEST",
    cnf: { jwk: { kty: "EC", crv: "P-256", ...holderJwk } }, _sd: digests, _sd_alg: "sha-256",
    status: { url: `${ISS}/status/CID-TEST` },
  });
  const sdJwt = `${jwt}~${disclosures.map((d) => `${d}~`).join("")}`;
  const fetchFn = (async (url: string) => {
    if (url === `${ISS}/.well-known/jwt-vc-issuer`) return new Response(JSON.stringify({ issuer: ISS, jwks: { keys: [{ ...issuer.jwk, kid: "k1" }] } }));
    return new Response("{}", { status: 404 });
  }) as typeof fetch;
  return { sdJwt, fetchFn };
}

describe("encoding", () => {
  it("canonical JSON sorts keys and round-trips base64url", () => {
    expect(canonicalJson({ b: 1, a: [2, { d: 1, c: 2 }] })).toBe('{"a":[2,{"c":2,"d":1}],"b":1}');
    expect(parseB64urlJson(b64urlJson({ x: "ü" }))).toEqual({ x: "ü" });
  });
});

describe("crypto", () => {
  it("signs ES256 JWTs with a non-extractable key", async () => {
    const k = await generateHolderKey();
    expect(k.privateKey.extractable).toBe(false);
    const jwt = await signJwt(k.privateKey, { typ: "x" }, { a: 1 });
    expect(await verifyJwtSignature(jwt, await importPublicJwk(k.jwk))).toBe(true);
    expect(await verifyJwtSignature(jwt.slice(0, -3) + "AAA", await importPublicJwk(k.jwk))).toBe(false);
  });
});

describe("sd-jwt", () => {
  it("accepts a valid credential and builds a selective presentation", async () => {
    const holder = await generateHolderKey();
    const { sdJwt, fetchFn } = await fakeIssuer(holder.jwk, { name: "Asha", roll_number: "1", branch: "CSE" });
    const stored = await toStoredCredential(sdJwt, holder, fetchFn);
    expect(stored.claims).toEqual({ name: "Asha", roll_number: "1", branch: "CSE" });

    const { presentation, disclosed } = await buildPresentation({ sdJwt, reveal: ["name"], audience: "aud", nonce: "n1", holderPrivateKey: holder.privateKey });
    expect(disclosed).toEqual(["name"]);
    const parts = presentation.split("~");
    expect(parts).toHaveLength(3);
    const kb = parseB64urlJson(parts[2].split(".")[1]);
    expect(kb.nonce).toBe("n1");
    expect(kb.sd_hash).toBe(await sha256b64url(`${parts[0]}~${parts[1]}~`));
  });

  it("rejects a credential bound to another wallet", async () => {
    const holder = await generateHolderKey();
    const other = await generateHolderKey();
    const { sdJwt, fetchFn } = await fakeIssuer(other.jwk, { name: "Asha" });
    await expect(toStoredCredential(sdJwt, holder, fetchFn)).rejects.toThrow(/not bound/);
  });

  it("rejects a disclosure the issuer never signed", async () => {
    const holder = await generateHolderKey();
    const { sdJwt } = await fakeIssuer(holder.jwk, { name: "Asha" });
    const forged = sdJwt.split("~")[0] + "~" + b64urlJson(["s", "name", "Mallory"]) + "~";
    await expect(parseSdJwt(forged)).rejects.toThrow(/not signed/);
  });
});

describe("protocol links", () => {
  it("parses a credential offer link", async () => {
    const offer = { credential_issuer: "http://x/", credential_configuration_ids: ["CampusID_SD_JWT"], grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "abc" } } };
    const parsed = await parseCredentialOffer("openid-credential-offer://?credential_offer=" + encodeURIComponent(JSON.stringify(offer)));
    expect(parsed).toEqual({ credentialIssuer: "http://x", configurationIds: ["CampusID_SD_JWT"], preAuthorizedCode: "abc" });
  });

  it("parses an OpenID4VP request and checks the response address", async () => {
    const q = new URLSearchParams({
      client_id: "http://v.test/verifier", response_type: "vp_token", response_mode: "direct_post",
      response_uri: "http://v.test/api/v1/verifier/response", nonce: "n", state: "REQ-1",
      dcql_query: JSON.stringify({ credentials: [{ id: "campus_id", format: "vc+sd-jwt", meta: { vct_values: ["CampusID"] }, claims: [{ path: ["name"] }, { path: ["branch"] }] }] }),
    });
    const req = await parsePresentationRequest(`openid4vp://authorize?${q}`);
    expect(req.requestedFields).toEqual(["name", "branch"]);
    expect(responseUriTrusted(req)).toBe(true);
    expect(responseUriTrusted({ ...req, responseUri: "http://evil.test/collect" })).toBe(false);
  });
});

describe("vault", () => {
  beforeEach(async () => { await vault.wipe(); });

  it("encrypts records and needs the PIN to read them", async () => {
    await vault.setUp("123456");
    await vault.writeRecord("credentials", [{ id: "CID-1", name: "Asha Patil" }]);
    const { idbGet } = await import("./idb");
    expect(JSON.stringify(await idbGet("rec:credentials"))).not.toContain("Asha");

    vault.lock();
    await expect(vault.readRecord("credentials")).rejects.toThrow(/locked/);
    await expect(vault.unlock("000000")).rejects.toThrow(/Wrong PIN/);
    await vault.unlock("123456");
    expect(await vault.readRecord("credentials")).toEqual([{ id: "CID-1", name: "Asha Patil" }]);
  });

  it("locks out after five wrong PINs", async () => {
    await vault.setUp("123456");
    vault.lock();
    for (let i = 0; i < 4; i++) await expect(vault.unlock("111111")).rejects.toThrow(/Wrong PIN/);
    await expect(vault.unlock("111111")).rejects.toThrow(/locked/);
    await expect(vault.unlock("123456")).rejects.toThrow(/Try again/);
  });

  it("keeps data when the PIN changes", async () => {
    await vault.setUp("123456");
    await vault.writeRecord("receipts", [1, 2, 3]);
    await vault.changePin("123456", "654321");
    vault.lock();
    await expect(vault.unlock("123456")).rejects.toThrow();
    await vault.unlock("654321");
    expect(await vault.readRecord("receipts")).toEqual([1, 2, 3]);
  });
});

describe("receipts", () => {
  it("detects edits, deletions and reordering", async () => {
    const holder = await generateHolderKey();
    let chain: Receipt[] = [];
    chain = await appendReceipt(chain, holder, { event: "credential_received", counterparty: "issuer", credentialId: "C", fields: ["name"], outcome: "ok", payload: "x" });
    chain = await appendReceipt(chain, holder, { event: "credential_shared", counterparty: "gate", credentialId: "C", fields: ["name"], outcome: "valid", payload: "y" });
    chain = await appendReceipt(chain, holder, { event: "credential_shared", counterparty: "library", credentialId: "C", fields: ["branch"], outcome: "valid", payload: "z" });
    expect(await verifyChain(chain, holder.jwk)).toEqual({ ok: true });

    const edited = chain.map((r, i) => (i === 1 ? { ...r, fields: [] } : r));
    expect((await verifyChain(edited, holder.jwk)).brokenAt).toBe(2);
    expect((await verifyChain([chain[0], chain[2]], holder.jwk)).ok).toBe(false);
    expect((await verifyChain([chain[1], chain[0], chain[2]], holder.jwk)).ok).toBe(false);
    expect(chain[1].payloadDigest).toMatch(/^[0-9a-f]{64}$/);
  });
});
