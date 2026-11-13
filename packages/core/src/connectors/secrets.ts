import { redactString } from "../redact.js";
import { ConnectorError } from "./types.js";

/**
 * Remove credential material from text that may leave the connector (errors, warnings, test results).
 * Exact secret values are replaced first (they may not match any generic pattern), then the generic
 * token/key redaction runs. Short values (<6 chars) are ignored to avoid shredding unrelated text.
 */
export function scrubSecrets(text: string, secrets: Array<string | null | undefined>): string {
  let out = text;
  for (const s of secrets) {
    if (!s || s.length < 6) continue;
    out = out.split(s).join("[REDACTED]");
    // vendors sometimes echo a key URL-encoded or truncated to its tail
    const enc = encodeURIComponent(s);
    if (enc !== s) out = out.split(enc).join("[REDACTED]");
  }
  return redactString(out);
}

/** Re-throw `err` with its message scrubbed of `secrets`; keeps ConnectorError status/retry metadata. */
export function scrubError(err: unknown, secrets: Array<string | null | undefined>): Error {
  const msg = scrubSecrets(err instanceof Error ? err.message : String(err), secrets);
  if (err instanceof ConnectorError) return new ConnectorError(msg, err.status, err.retryable, err.retryAfterMs);
  const e = new Error(msg);
  if (err instanceof Error) e.name = err.name;
  return e;
}

/** Decode a JWT payload WITHOUT verifying it — only for displaying/classifying our own access token's claims. */
export function unverifiedJwtClaims(token: string): Record<string, unknown> {
  const part = token.split(".")[1];
  if (!part) return {};
  try { return JSON.parse(Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")); } catch { return {}; }
}

/**
 * Pagination links returned by a vendor (`nextLink`, `@odata.nextLink`) are followed only when they stay on the
 * expected origin and path prefix — otherwise a hostile or buggy response could steer our authenticated client
 * (and its bearer token) to another host.
 */
export function assertSameOriginLink(link: string, allowedOrigin: string, pathPrefix: string): string {
  let u: URL;
  try { u = new URL(link); } catch { throw new ConnectorError("invalid pagination link from provider"); }
  if (u.origin !== new URL(allowedOrigin).origin || !u.pathname.toLowerCase().startsWith(pathPrefix.toLowerCase())) {
    throw new ConnectorError(`refusing to follow pagination link outside ${allowedOrigin}${pathPrefix}`);
  }
  return u.toString();
}
