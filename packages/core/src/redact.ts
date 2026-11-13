/**
 * Sensitive-data redaction applied to the *normalized* view and to anything sent to an LLM.
 * Raw evidence is stored unmodified (immutable, access-controlled) so it stays verifiable.
 */
const PATTERNS: Array<[RegExp, string]> = [
  [/(authorization|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|[a-z]*token|secret|password|passwd|pwd|session[_-]?id|sig|signature)=([^&\s"']+)/gi, "$1=[REDACTED]"],
  [/\bBearer\s+[A-Za-z0-9\-._~+/]+=*/g, "Bearer [REDACTED]"],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g, "[REDACTED_JWT]"],
  [/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS_KEY_ID]"],
  [/\bAIza[0-9A-Za-z\-_]{35}\b/g, "[REDACTED_GCP_API_KEY]"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]"],
  [/\b(?:\d[ -]?){13,16}\b/g, (m: string) => (luhn(m.replace(/\D/g, "")) ? "[REDACTED_PAN]" : m)] as unknown as [RegExp, string],
];

function luhn(digits: string): boolean {
  if (digits.length < 13) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = Number(digits[i]);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export function redactString(s: string): string {
  let out = s;
  for (const [re, rep] of PATTERNS) out = out.replace(re, rep as never);
  return out;
}

const SENSITIVE_KEYS = /^(authorization|cookie|set-cookie|password|passwd|secret|token|access_token|refresh_token|private_key|api_key|apikey|client_secret)$/i;

export function redactDeep<T>(value: T, depth = 0): T {
  if (depth > 12) return value;
  if (typeof value === "string") return redactString(value) as T;
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, depth + 1)) as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = SENSITIVE_KEYS.test(k) ? "[REDACTED]" : redactDeep(v, depth + 1);
    }
    return out as T;
  }
  return value;
}
