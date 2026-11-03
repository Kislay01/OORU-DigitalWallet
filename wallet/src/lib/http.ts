/** Turn a backend error body into a readable message. */
export async function errorMessage(res: Response, fallback: string): Promise<string> {
  const body = await res.json().catch(() => ({}) as any);
  const d = body?.detail ?? body;
  return d?.error_description || d?.error?.message || (typeof d?.error === "string" ? d.error : null) || `${fallback} (HTTP ${res.status})`;
}
