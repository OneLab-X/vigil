import { ConnectorError } from "./types.js";

/**
 * Time-window paging for query APIs that have no cursor and cap results per query (Log Analytics KQL,
 * New Relic NRQL). The page token encodes the next window start and the current window width. When a window
 * returns `limit` rows (possibly truncated) it is halved and re-queried, so nothing is silently dropped; small
 * result sets let the window grow back. Windows are half-open [s, e) and contiguous, so there are no gaps;
 * dedupe on provider event id absorbs any overlap the scheduler adds.
 */
export interface WindowToken { s: number; w: number }

const PREFIX = "win1:";
export const encodeWindowToken = (t: WindowToken): string => PREFIX + Buffer.from(JSON.stringify(t)).toString("base64url");

export function decodeWindowToken(tok: string, start: Date, end: Date): WindowToken {
  if (!tok.startsWith(PREFIX)) throw new ConnectorError("invalid page token");
  let t: WindowToken;
  try { t = JSON.parse(Buffer.from(tok.slice(PREFIX.length), "base64url").toString("utf8")); } catch { throw new ConnectorError("invalid page token"); }
  if (!Number.isFinite(t?.s) || !Number.isFinite(t?.w) || t.w <= 0 || t.s < start.getTime() || t.s > end.getTime()) throw new ConnectorError("page token outside requested range");
  return t;
}

export interface WindowedQueryOptions<T> {
  start: Date;
  end: Date;
  pageToken?: string | null;
  /** maximum rows one query can return; reaching it means "possibly truncated" */
  limit: number;
  /** smallest window worth splitting into (default 1s) */
  minWindowMs?: number;
  run(start: Date, end: Date): Promise<T[]>;
  /** treat this error as "window too large" (e.g. a query timeout) and split instead of failing */
  splitOn?: (err: unknown) => boolean;
}

export async function windowedQuery<T>(o: WindowedQueryOptions<T>): Promise<{ rows: T[]; nextPageToken: string | null; window: { start: string; end: string } }> {
  const endMs = o.end.getTime();
  const minW = o.minWindowMs ?? 1000;
  let { s, w } = o.pageToken ? decodeWindowToken(o.pageToken, o.start, o.end) : { s: o.start.getTime(), w: Math.max(minW, endMs - o.start.getTime()) };
  if (s >= endMs) return { rows: [], nextPageToken: null, window: { start: new Date(s).toISOString(), end: new Date(s).toISOString() } };
  for (let i = 0; i < 48; i++) {
    const e = Math.min(endMs, s + w);
    let rows: T[];
    try { rows = await o.run(new Date(s), new Date(e)); }
    catch (err) {
      if (!o.splitOn?.(err) || e - s <= minW) throw err;
      w = Math.max(minW, Math.floor((e - s) / 2));
      continue;
    }
    if (rows.length >= o.limit) {
      if (e - s <= minW) throw new ConnectorError(`more than ${o.limit} records within ${Math.round((e - s) / 1000)}s at ${new Date(s).toISOString()}; narrow the source filter`);
      w = Math.max(minW, Math.floor((e - s) / 2));
      continue;
    }
    const nextW = rows.length < o.limit / 4 ? w * 2 : w;
    return { rows, nextPageToken: e >= endMs ? null : encodeWindowToken({ s: e, w: nextW }), window: { start: new Date(s).toISOString(), end: new Date(e).toISOString() } };
  }
  throw new ConnectorError("window splitting did not converge");
}
