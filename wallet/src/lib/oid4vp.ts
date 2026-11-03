import { FORMAT, VCT } from "./campusId";
import { errorMessage } from "./http";
import { buildPresentation } from "./sdjwt";

export interface PresentationRequest {
  clientId: string;
  responseUri: string;
  nonce: string;
  state: string;
  requestedFields: string[];
  verifierName: string;
  credentialQueryId: string;
}

export function isPresentationRequest(text: string): boolean {
  const t = text.trim();
  return t.startsWith("openid4vp://") || (t.includes("response_type=vp_token") && t.includes("nonce="));
}

function fromObject(o: any): PresentationRequest {
  if (o.response_type !== "vp_token") throw new Error("Unsupported request type");
  if (o.response_mode && o.response_mode !== "direct_post") throw new Error("Unsupported response mode");
  const query = typeof o.dcql_query === "string" ? JSON.parse(o.dcql_query) : o.dcql_query;
  const cq = query?.credentials?.[0];
  const meta = typeof o.client_metadata === "string" ? safeJson(o.client_metadata) : o.client_metadata;
  if (!cq) throw new Error("The request does not say which credential it needs");
  if (cq.format && cq.format !== FORMAT) throw new Error("The verifier asked for a credential format this wallet doesn't hold");
  if (cq.meta?.vct_values && !cq.meta.vct_values.includes(VCT)) throw new Error("The verifier asked for a different credential type");
  if (!o.client_id || !o.response_uri || !o.nonce || !o.state) throw new Error("The request is incomplete");
  return {
    clientId: o.client_id,
    responseUri: o.response_uri,
    nonce: o.nonce,
    state: o.state,
    requestedFields: (cq.claims || []).map((c: any) => c.path?.[0]).filter(Boolean),
    verifierName: (typeof meta?.client_name === "string" && meta.client_name.slice(0, 60)) || hostOf(o.client_id),
    credentialQueryId: cq.id || "campus_id",
  };
}

const safeJson = (s: string) => {
  try { return JSON.parse(s); } catch { return null; }
};

const hostOf = (u: string) => {
  try { return new URL(u).host; } catch { return u; }
};

export async function parsePresentationRequest(input: string, fetchFn: typeof fetch = fetch): Promise<PresentationRequest> {
  const text = input.trim();
  const params = new URLSearchParams(text.includes("?") ? text.slice(text.indexOf("?") + 1) : text);
  if (params.get("request_uri")) {
    const r = await fetchFn(params.get("request_uri")!);
    if (!r.ok) throw new Error(await errorMessage(r, "This request is no longer open"));
    return fromObject(await r.json());
  }
  const o: Record<string, string> = {};
  params.forEach((v, k) => (o[k] = v));
  return fromObject(o);
}

/** The response_uri must belong to the same site as the verifier's client_id. */
export function responseUriTrusted(req: PresentationRequest): boolean {
  try {
    return new URL(req.responseUri).origin === new URL(req.clientId).origin;
  } catch {
    return false;
  }
}

export interface ShareResult {
  status: string;
  presentation: string;
  disclosed: string[];
}

export async function sharePresentation(opts: {
  request: PresentationRequest;
  sdJwt: string;
  reveal: string[];
  holderPrivateKey: CryptoKey;
  fetchFn?: typeof fetch;
}): Promise<ShareResult> {
  const fetchFn = opts.fetchFn ?? fetch;
  if (!responseUriTrusted(opts.request)) throw new Error("The verifier's response address doesn't match its identity. Not sharing.");
  const { presentation, disclosed } = await buildPresentation({
    sdJwt: opts.sdJwt,
    reveal: opts.reveal,
    audience: opts.request.clientId,
    nonce: opts.request.nonce,
    holderPrivateKey: opts.holderPrivateKey,
  });
  const r = await fetchFn(opts.request.responseUri, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      state: opts.request.state,
      vp_token: JSON.stringify({ [opts.request.credentialQueryId]: [presentation] }),
    }).toString(),
  });
  if (!r.ok) throw new Error(await errorMessage(r, "The verifier did not accept the response"));
  return { status: (await r.json()).status || "sent", presentation, disclosed };
}
