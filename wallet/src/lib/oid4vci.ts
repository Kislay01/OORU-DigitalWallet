import { CONFIGURATION_ID, FORMAT, type CampusIdClaims, type StoredCredential } from "./campusId";
import { signJwt, type HolderKey } from "./crypto";
import { errorMessage } from "./http";
import { parseSdJwt, verifyIssuerSignature } from "./sdjwt";

const PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

export interface CredentialOffer {
  credentialIssuer: string;
  configurationIds: string[];
  preAuthorizedCode: string;
}

export function isCredentialOffer(text: string): boolean {
  const t = text.trim();
  return t.startsWith("openid-credential-offer://") || t.includes("credential_offer=") || t.includes("credential_offer_uri=");
}

export async function parseCredentialOffer(input: string, fetchFn: typeof fetch = fetch): Promise<CredentialOffer> {
  const text = input.trim();
  let offer: any;
  if (text.startsWith("{")) {
    offer = JSON.parse(text);
  } else {
    const q = text.includes("?") ? text.slice(text.indexOf("?") + 1) : "";
    const params = new URLSearchParams(q);
    if (params.get("credential_offer")) offer = JSON.parse(params.get("credential_offer")!);
    else if (params.get("credential_offer_uri")) {
      const r = await fetchFn(params.get("credential_offer_uri")!);
      if (!r.ok) throw new Error("Could not load the credential offer");
      offer = await r.json();
    } else throw new Error("This is not a credential offer link");
  }
  const code = offer?.grants?.[PRE_AUTH]?.["pre-authorized_code"];
  if (!offer?.credential_issuer || !code) throw new Error("The offer is missing the issuer or the one-time code");
  return { credentialIssuer: String(offer.credential_issuer).replace(/\/+$/, ""), configurationIds: offer.credential_configuration_ids || [], preAuthorizedCode: code };
}

export interface ClaimResult {
  credential: StoredCredential;
  issuerName: string;
}

/** OpenID4VCI pre-authorized code flow: metadata → token → credential with proof of possession. */
export async function claimCredential(offer: CredentialOffer, holder: HolderKey, fetchFn: typeof fetch = fetch): Promise<ClaimResult> {
  if (offer.configurationIds.length && !offer.configurationIds.includes(CONFIGURATION_ID)) {
    throw new Error("This wallet only accepts Campus ID credentials");
  }
  const metaRes = await fetchFn(`${offer.credentialIssuer}/.well-known/openid-credential-issuer`);
  if (!metaRes.ok) throw new Error("Could not reach the issuer");
  const meta = await metaRes.json();
  if (meta.credential_issuer.replace(/\/+$/, "") !== offer.credentialIssuer) throw new Error("Issuer metadata does not match the offer");

  const asBase = (meta.authorization_servers?.[0] || offer.credentialIssuer).replace(/\/+$/, "");
  const asRes = await fetchFn(`${asBase}/.well-known/oauth-authorization-server`);
  const tokenEndpoint = asRes.ok ? (await asRes.json()).token_endpoint : `${offer.credentialIssuer}/api/v1/issuer/token`;

  const tokRes = await fetchFn(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: PRE_AUTH, "pre-authorized_code": offer.preAuthorizedCode }).toString(),
  });
  if (!tokRes.ok) throw new Error(await errorMessage(tokRes, "The offer could not be redeemed"));
  const tok = await tokRes.json();

  const proof = await signJwt(
    holder.privateKey,
    { typ: "openid4vci-proof+jwt", jwk: holder.jwk },
    { aud: offer.credentialIssuer, iat: Math.floor(Date.now() / 1000), nonce: tok.c_nonce },
  );
  const credRes = await fetchFn(meta.credential_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${tok.access_token}` },
    body: JSON.stringify({ credential_configuration_id: CONFIGURATION_ID, proof: { proof_type: "jwt", jwt: proof } }),
  });
  if (!credRes.ok) throw new Error(await errorMessage(credRes, "The issuer did not deliver the credential"));
  const body = await credRes.json();
  const sdJwt: string = body.credentials?.[0]?.credential || body.credential;
  if (!sdJwt) throw new Error("The issuer response did not include a credential");

  const credential = await toStoredCredential(sdJwt, holder, fetchFn);
  return { credential, issuerName: meta.display?.[0]?.name || offer.credentialIssuer };
}

/** Validate a received credential before it goes into the vault. */
export async function toStoredCredential(sdJwt: string, holder: HolderKey, fetchFn: typeof fetch = fetch): Promise<StoredCredential> {
  const parsed = await parseSdJwt(sdJwt);
  if (parsed.header.typ !== FORMAT) throw new Error("Unexpected credential format");
  if (!(await verifyIssuerSignature(parsed, fetchFn))) throw new Error("The issuer's signature on this credential is not valid");
  const cnf = parsed.payload.cnf?.jwk;
  if (!cnf || cnf.x !== holder.jwk.x || cnf.y !== holder.jwk.y) throw new Error("This credential is not bound to this wallet's key");

  const claims: CampusIdClaims = {};
  for (const d of parsed.disclosures) (claims as any)[d.name] = d.value;
  return {
    id: parsed.payload.credential_id,
    sdJwt,
    issuer: parsed.payload.iss,
    claims,
    statusUrl: parsed.payload.status?.url,
    issuedAt: parsed.payload.iat * 1000,
    expiresAt: parsed.payload.exp * 1000,
    receivedAt: Date.now(),
  };
}

export async function checkStatus(cred: StoredCredential, fetchFn: typeof fetch = fetch): Promise<string> {
  if (cred.expiresAt < Date.now()) return "expired";
  if (!cred.statusUrl) return "unknown";
  const r = await fetchFn(cred.statusUrl);
  if (!r.ok) throw new Error("Could not check status");
  return (await r.json()).status;
}
