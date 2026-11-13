/**
 * Sanitize an error message before it leaves the API (operations page, job/run errors).
 * Removes credentials, tokens, connection strings and URLs; collapses whitespace; truncates.
 */
export function sanitizeError(input: unknown, max = 300): string | null {
  if (input === null || input === undefined || input === "") return null;
  let s = String(input);
  s = s
    // URLs / connection strings (keep only the scheme): postgres://user:pass@host/db, https://x?token=…
    .replace(/\b([a-z][a-z0-9+.-]{1,20}):\/\/[^\s'"<>)]+/gi, "$1://[redacted]")
    // Authorization headers / bearer tokens
    .replace(/\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, "$1 [redacted]")
    // key=value / key: value secrets
    .replace(/\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|authorization|session|cookie|signature|private[_-]?key)(["']?\s*[:=]\s*["']?)[^\s"',;&]+/gi, "$1$2[redacted]")
    // JWTs
    .replace(/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g, "[redacted-jwt]")
    // AWS access key ids and well-known vendor key prefixes
    .replace(/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, "[redacted-key]")
    .replace(/\b(sk-[A-Za-z0-9_-]{12,}|AIza[0-9A-Za-z_-]{20,}|ghp_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,})/g, "[redacted-key]")
    // PEM blocks
    .replace(/-----BEGIN [A-Z ]+-----[\s\S]*?(-----END [A-Z ]+-----|$)/g, "[redacted-pem]")
    // long opaque tokens (hex / base64-ish, 32+ chars)
    .replace(/\b[A-Za-z0-9+/_-]{40,}={0,2}/g, "[redacted]")
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}
