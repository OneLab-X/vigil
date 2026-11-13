import { createHash } from "node:crypto";
import type { CanonicalEvent } from "../types.js";

export * from "./gcp.js";
export * from "./aws.js";
export * from "./azure.js";
export * from "./logplatform.js";

export const sha256 = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");

/**
 * Deterministic idempotency key. Prefer the provider's own event id; otherwise hash the raw
 * payload bytes so an identical re-delivery still collapses into one row.
 */
export function deduplicationKey(ev: Pick<CanonicalEvent, "cloudProvider" | "projectOrAccountReference" | "providerEventId">, rawJson: string): string {
  const basis = ev.providerEventId
    ? `${ev.cloudProvider}|${ev.projectOrAccountReference ?? ""}|${ev.providerEventId}`
    : `${ev.cloudProvider}|raw|${sha256(rawJson)}`;
  return sha256(basis);
}

/** Stable JSON (sorted keys) so the raw blob hash is reproducible across re-fetches. */
export function stableStringify(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).sort().filter((k) => o[k] !== undefined).map((k) => `${JSON.stringify(k)}:${stableStringify(o[k])}`).join(",")}}`;
}
