import { createHash } from "node:crypto";
import type { DetectableEvent, Severity } from "../types.js";
import type { Condition, DetectionQuery, RuleDefinition } from "./dsl.js";

export interface RuleHit {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: number;
  groupKey: Record<string, unknown>;
  eventIds: string[];
  eventCount: number;
  firstSeen: string;
  lastSeen: string;
  dedupKey: string;
  details: Record<string, unknown>;
}

const MAX_SAMPLE = 200;
const regexCache = new Map<string, RegExp>();

export function getField(ev: DetectableEvent, field: string): unknown {
  if (field.startsWith("normalized.")) {
    let cur: unknown = ev.normalized;
    for (const part of field.slice(11).split(".")) {
      if (cur === null || typeof cur !== "object") return undefined;
      cur = (cur as Record<string, unknown>)[part];
    }
    return cur;
  }
  return (ev as unknown as Record<string, unknown>)[field];
}

export function evaluate(cond: Condition, ev: DetectableEvent): boolean {
  if ("all" in cond) return cond.all.every((c) => evaluate(c, ev));
  if ("any" in cond) return cond.any.some((c) => evaluate(c, ev));
  if ("not" in cond) return !evaluate(cond.not, ev);
  const v = getField(ev, cond.field);
  const t = cond.value;
  switch (cond.op) {
    case "exists": return v !== null && v !== undefined;
    case "eq": return Array.isArray(v) ? v.includes(t) : v === t;
    case "neq": return v !== t;
    case "in": return Array.isArray(t) && (Array.isArray(v) ? v.some((x) => t.includes(x)) : t.includes(v));
    case "nin": return Array.isArray(t) && !(Array.isArray(v) ? v.some((x) => t.includes(x)) : t.includes(v));
    case "contains": return Array.isArray(v) ? v.includes(t) : typeof v === "string" && typeof t === "string" && v.toLowerCase().includes(t.toLowerCase());
    case "startsWith": return typeof v === "string" && typeof t === "string" && v.startsWith(t);
    case "gte": return typeof v === "number" && typeof t === "number" && v >= t;
    case "lte": return typeof v === "number" && typeof t === "number" && v <= t;
    case "gt": return typeof v === "number" && typeof t === "number" && v > t;
    case "lt": return typeof v === "number" && typeof t === "number" && v < t;
    case "regex": {
      if (typeof v !== "string" || typeof t !== "string") return false;
      let re = regexCache.get(t);
      if (!re) {
        const ci = t.startsWith("(?i)");
        re = new RegExp(ci ? t.slice(4) : t, ci ? "i" : "");
        regexCache.set(t, re);
      }
      return re.test(v.slice(0, 4096));
    }
  }
}

const ms = (iso: string) => Date.parse(iso);
const hash = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 32);

function groupOf(ev: DetectableEvent, fields: string[] | undefined): { key: string; obj: Record<string, unknown> } | null {
  if (!fields?.length) return { key: "*", obj: {} };
  const obj: Record<string, unknown> = {};
  for (const f of fields) {
    const v = getField(ev, f);
    if (v === null || v === undefined || v === "") return null; // can't attribute → don't group under "null"
    obj[f] = v;
  }
  return { key: JSON.stringify(obj), obj };
}

function bucketStart(t: number, minutes: number) {
  const size = minutes * 60_000;
  return Math.floor(t / size) * size;
}

function mkHit(rule: RuleDefinition, groupObj: Record<string, unknown>, evs: DetectableEvent[], bucket: number, details: Record<string, unknown>, titleSuffix: string): RuleHit {
  const sorted = [...evs].sort((a, b) => ms(a.eventTimestamp) - ms(b.eventTimestamp));
  return {
    ruleId: rule.ruleId,
    title: `${rule.name}${titleSuffix}`,
    severity: rule.severity,
    confidence: rule.confidence,
    groupKey: groupObj,
    eventIds: sorted.slice(0, MAX_SAMPLE).map((e) => e.id),
    eventCount: evs.length,
    firstSeen: sorted[0]!.eventTimestamp,
    lastSeen: sorted[sorted.length - 1]!.eventTimestamp,
    dedupKey: hash(`${rule.ruleId}|${JSON.stringify(groupObj)}|${bucket}`),
    details,
  };
}

const describeGroup = (g: Record<string, unknown>) => {
  const parts = Object.entries(g).map(([k, v]) => `${k}=${String(v)}`);
  return parts.length ? ` (${parts.join(", ")})` : "";
};

/**
 * Evaluate a rule over events (any order). Windows are tumbling buckets aligned to epoch so
 * repeated evaluations over overlapping ranges produce identical dedup keys.
 */
export function runRule(rule: RuleDefinition, events: DetectableEvent[]): RuleHit[] {
  const q: DetectionQuery = rule.detectionQuery;
  if (q.kind === "sequence") return runSequence(rule, q, events);
  const matched = events.filter((e) => evaluate(q.where, e));
  if (!matched.length) return [];

  if (q.kind === "rate_spike") return runRateSpike(rule, q, matched);

  const window = q.windowMinutes;
  const winMs = window * 60_000;
  const groups = new Map<string, { obj: Record<string, unknown>; evs: DetectableEvent[] }>();
  for (const e of matched) {
    const g = groupOf(e, q.groupBy);
    if (!g) continue;
    let entry = groups.get(g.key);
    if (!entry) groups.set(g.key, (entry = { obj: g.obj, evs: [] }));
    entry.evs.push(e);
  }

  const hits: RuleHit[] = [];
  for (const { obj, evs } of groups.values()) {
    evs.sort((a, b) => ms(a.eventTimestamp) - ms(b.eventTimestamp));
    if (q.kind === "match") {
      // one finding per group per aligned window (stable dedup across re-runs)
      const byBucket = new Map<number, DetectableEvent[]>();
      for (const e of evs) { const b = bucketStart(ms(e.eventTimestamp), window); byBucket.set(b, [...(byBucket.get(b) ?? []), e]); }
      for (const [b, list] of byBucket) hits.push(mkHit(rule, obj, list, b, { kind: "match", window_minutes: window }, describeGroup(obj)));
      continue;
    }
    // Sliding window: find bursts anywhere in time, not just inside epoch-aligned buckets.
    let i = 0;
    while (i < evs.length) {
      const t0 = ms(evs[i]!.eventTimestamp);
      let j = i;
      while (j + 1 < evs.length && ms(evs[j + 1]!.eventTimestamp) - t0 <= winMs) j++;
      const slice = evs.slice(i, j + 1);
      let fired = false;
      if (q.kind === "threshold" && slice.length >= q.minCount) {
        hits.push(mkHit(rule, obj, slice, bucketStart(t0, window), { kind: "threshold", count: slice.length, min_count: q.minCount, window_minutes: window }, describeGroup(obj)));
        fired = true;
      } else if (q.kind === "distinct") {
        const distinct = new Set(slice.map((e) => JSON.stringify(getField(e, q.field))).filter((v) => v !== undefined && v !== "null"));
        if (distinct.size >= q.minDistinct) {
          hits.push(mkHit(rule, obj, slice, bucketStart(t0, window), { kind: "distinct", field: q.field, distinct: distinct.size, min_distinct: q.minDistinct, sample_values: [...distinct].slice(0, 25).map((v) => JSON.parse(v)), window_minutes: window }, describeGroup(obj)));
          fired = true;
        }
      }
      i = fired ? j + 1 : i + 1;
    }
  }
  return hits;
}

function runRateSpike(rule: RuleDefinition, q: Extract<DetectionQuery, { kind: "rate_spike" }>, matched: DetectableEvent[]): RuleHit[] {
  const byGroup = new Map<string, { obj: Record<string, unknown>; buckets: Map<number, DetectableEvent[]> }>();
  for (const e of matched) {
    const g = groupOf(e, q.groupBy);
    if (!g) continue;
    let entry = byGroup.get(g.key);
    if (!entry) byGroup.set(g.key, (entry = { obj: g.obj, buckets: new Map() }));
    const b = bucketStart(ms(e.eventTimestamp), q.bucketMinutes);
    const arr = entry.buckets.get(b) ?? [];
    arr.push(e);
    entry.buckets.set(b, arr);
  }
  const size = q.bucketMinutes * 60_000;
  const hits: RuleHit[] = [];
  for (const { obj, buckets } of byGroup.values()) {
    for (const [b, evs] of buckets) {
      if (evs.length < q.minCount) continue;
      let total = 0;
      for (let i = 1; i <= q.baselineBuckets; i++) total += buckets.get(b - i * size)?.length ?? 0;
      const baseline = total / q.baselineBuckets;
      // Baseline floor of 1 avoids division-by-zero "infinite" spikes on brand-new services.
      if (evs.length >= Math.max(baseline, 1) * q.factor) {
        hits.push(mkHit(rule, obj, evs, b, { kind: "rate_spike", count: evs.length, baseline_avg: Number(baseline.toFixed(2)), factor: q.factor, bucket_minutes: q.bucketMinutes }, describeGroup(obj)));
      }
    }
  }
  return hits;
}

function runSequence(rule: RuleDefinition, q: Extract<DetectionQuery, { kind: "sequence" }>, events: DetectableEvent[]): RuleHit[] {
  const sorted = [...events].sort((a, b) => ms(a.eventTimestamp) - ms(b.eventTimestamp));
  const byGroup = new Map<string, { obj: Record<string, unknown>; evs: DetectableEvent[] }>();
  for (const e of sorted) {
    if (!q.steps.some((s) => evaluate(s, e))) continue;
    const g = groupOf(e, q.groupBy);
    if (!g) continue;
    const entry = byGroup.get(g.key) ?? { obj: g.obj, evs: [] };
    entry.evs.push(e);
    byGroup.set(g.key, entry);
  }
  const hits: RuleHit[] = [];
  const windowMs = q.windowMinutes * 60_000;
  for (const { obj, evs } of byGroup.values()) {
    for (let i = 0; i < evs.length; i++) {
      if (!evaluate(q.steps[0]!, evs[i]!)) continue;
      const chain = [evs[i]!];
      let step = 1;
      const start = ms(evs[i]!.eventTimestamp);
      for (let j = i + 1; j < evs.length && step < q.steps.length; j++) {
        if (ms(evs[j]!.eventTimestamp) - start > windowMs) break;
        if (evaluate(q.steps[step]!, evs[j]!)) { chain.push(evs[j]!); step++; }
      }
      if (step === q.steps.length) {
        hits.push(mkHit(rule, obj, chain, bucketStart(start, q.windowMinutes), { kind: "sequence", steps: q.steps.length }, describeGroup(obj)));
        break; // one hit per group per evaluation; dedup handles re-runs
      }
    }
  }
  return hits;
}

export function ruleAppliesTo(rule: Pick<RuleDefinition, "provider" | "eventSources">, ev: Pick<DetectableEvent, "cloudProvider" | "sourceType">): boolean {
  if (rule.provider !== "any" && rule.provider !== ev.cloudProvider) return false;
  if (rule.eventSources.length && !rule.eventSources.includes(ev.sourceType)) return false;
  return true;
}

export function runRules(rules: RuleDefinition[], events: DetectableEvent[]): RuleHit[] {
  const out: RuleHit[] = [];
  for (const r of rules) {
    if (!r.enabled) continue;
    out.push(...runRule(r, events.filter((e) => ruleAppliesTo(r, e))));
  }
  return out;
}
