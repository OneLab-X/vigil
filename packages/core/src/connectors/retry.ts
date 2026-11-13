import { ConnectorError } from "./types.js";

export interface RetryOptions {
  retries?: number;
  baseMs?: number;
  maxMs?: number;
  sleep?: (ms: number) => Promise<void>;
  onRetry?: (attempt: number, err: unknown, delayMs: number) => void;
}

const defaultSleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function isRetryable(err: unknown): boolean {
  if (err instanceof ConnectorError) return err.retryable;
  const code = (err as any)?.code ?? (err as any)?.cause?.code;
  return ["ECONNRESET", "ETIMEDOUT", "EAI_AGAIN", "ECONNREFUSED", "UND_ERR_SOCKET", "ThrottlingException", "TooManyRequestsException"].includes(code)
    || (err as any)?.name === "ThrottlingException" || (err as any)?.$retryable !== undefined;
}

/** Exponential backoff with full jitter; honors Retry-After from ConnectorError. */
export async function withRetry<T>(fn: () => Promise<T>, opts: RetryOptions = {}): Promise<T> {
  const retries = opts.retries ?? 5;
  const base = opts.baseMs ?? 500;
  const max = opts.maxMs ?? 30_000;
  const sleep = opts.sleep ?? defaultSleep;
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (attempt >= retries || !isRetryable(err)) throw err;
      const ra = err instanceof ConnectorError ? err.retryAfterMs : undefined;
      const delay = ra ?? Math.round(Math.random() * Math.min(max, base * 2 ** attempt));
      opts.onRetry?.(attempt + 1, err, delay);
      await sleep(delay);
    }
  }
}

export function httpError(status: number, body: string, retryAfter?: string | null): ConnectorError {
  const retryable = status === 429 || status >= 500;
  let ra: number | undefined;
  if (retryAfter) {
    const s = Number(retryAfter);
    ra = Number.isFinite(s) ? s * 1000 : Math.max(0, Date.parse(retryAfter) - Date.now());
  }
  // Never echo full provider bodies upward — they may include request details.
  return new ConnectorError(`provider HTTP ${status}: ${body.slice(0, 300)}`, status, retryable, ra);
}
