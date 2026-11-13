import { z } from "zod";

const sev = z.enum(["info", "low", "medium", "high", "critical"]);
const EvidenceItem = z.object({
  event_id: z.string().uuid(),
  claim: z.string().min(3).max(2000),
  /** Field values the agent asserts about the event; each is checked against the stored event. */
  cited_fields: z.record(z.string(), z.union([z.string(), z.number(), z.null()])).nullable().optional(),
});

export const InvestigationContractSchema = z.object({
  case_id: z.string().regex(/^CASE-\d{4,}$/),
  verdict: z.enum(["confirmed", "likely", "benign", "inconclusive", "needs_more_data"]),
  severity: sev,
  confidence: z.number().min(0).max(1),
  summary: z.string().min(10).max(6000),
  timeline: z.array(z.object({ timestamp: z.string(), description: z.string().max(1000), event_id: z.string().uuid().nullable().optional() })).max(200),
  entities: z.object({
    ips: z.array(z.string()).default([]),
    principals: z.array(z.string()).default([]),
    resources: z.array(z.string()).default([]),
  }),
  evidence: z.array(EvidenceItem).max(100),
  contradictory_evidence: z.array(EvidenceItem).max(100),
  impact_assessment: z.object({
    outcome: z.enum(["succeeded", "failed", "blocked", "unknown"]),
    scope: z.string().max(2000),
    data_exposure: z.enum(["none_observed", "possible", "confirmed", "unknown"]),
  }),
  recommended_actions: z.array(z.object({ action: z.string().max(500), rationale: z.string().max(2000), priority: z.enum(["low", "medium", "high", "urgent"]) })).max(20),
  requires_human_approval: z.literal(true),
  abstention_reason: z.string().max(2000).nullable().optional(),
});
export type InvestigationContract = z.infer<typeof InvestigationContractSchema>;

export const TriageOutputSchema = z.object({
  should_investigate: z.boolean(),
  rationale: z.string().min(5).max(4000),
  priority: z.enum(["low", "medium", "high", "urgent"]),
  related_event_ids: z.array(z.string().uuid()).max(100).default([]),
  unexplained_patterns: z.array(z.string().max(500)).max(20).default([]),
});
export type TriageOutput = z.infer<typeof TriageOutputSchema>;

export interface GroundingEvent {
  id: string;
  eventTimestamp: string;
  sourceIp: string | null;
  destinationIp: string | null;
  principal: string | null;
  resourceId: string | null;
  action: string | null;
  status: string | null;
  httpStatus: number | null;
  urlPath: string | null;
}

export interface GroundingIssue { path: string; problem: string }

const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const FIELD_MAP: Record<string, keyof GroundingEvent> = {
  source_ip: "sourceIp", destination_ip: "destinationIp", principal: "principal", resource_id: "resourceId",
  action: "action", status: "status", http_status: "httpStatus", url_path: "urlPath", event_timestamp: "eventTimestamp", timestamp: "eventTimestamp",
};

/**
 * Anti-fabrication check. `seen` = events the agent actually received from the tool broker in
 * this run (by id). Any reference to an event, IP or timestamp the agent could not have seen
 * is an error, and the verdict is rejected.
 */
export function validateGrounding(c: InvestigationContract, seen: Map<string, GroundingEvent>): GroundingIssue[] {
  const issues: GroundingIssue[] = [];
  const knownIps = new Set<string>();
  for (const e of seen.values()) { if (e.sourceIp) knownIps.add(e.sourceIp); if (e.destinationIp) knownIps.add(e.destinationIp); }

  const checkItem = (item: z.infer<typeof EvidenceItem>, path: string) => {
    const ev = seen.get(item.event_id);
    if (!ev) { issues.push({ path, problem: `event ${item.event_id} was not returned by any tool call in this run` }); return; }
    for (const [k, v] of Object.entries(item.cited_fields ?? {})) {
      const col = FIELD_MAP[k];
      if (!col) { issues.push({ path: `${path}.cited_fields.${k}`, problem: "unknown field" }); continue; }
      const actual = ev[col];
      const same = col === "eventTimestamp"
        ? typeof v === "string" && Date.parse(v) === Date.parse(String(actual))
        : String(actual ?? "") === String(v ?? "");
      if (!same) issues.push({ path: `${path}.cited_fields.${k}`, problem: `cited ${JSON.stringify(v)} but event has ${JSON.stringify(actual)}` });
    }
    for (const ip of item.claim.match(IP_RE) ?? []) if (!knownIps.has(ip)) issues.push({ path: `${path}.claim`, problem: `IP ${ip} not present in any retrieved event` });
  };

  c.evidence.forEach((e, i) => checkItem(e, `evidence[${i}]`));
  c.contradictory_evidence.forEach((e, i) => checkItem(e, `contradictory_evidence[${i}]`));
  c.timeline.forEach((t, i) => {
    if (!t.event_id) return;
    const ev = seen.get(t.event_id);
    if (!ev) issues.push({ path: `timeline[${i}]`, problem: `event ${t.event_id} not retrieved in this run` });
    else if (Math.abs(Date.parse(t.timestamp) - Date.parse(ev.eventTimestamp)) > 1000) issues.push({ path: `timeline[${i}].timestamp`, problem: `timestamp ${t.timestamp} does not match event (${ev.eventTimestamp})` });
  });
  c.entities.ips.forEach((ip, i) => { if (!knownIps.has(ip)) issues.push({ path: `entities.ips[${i}]`, problem: `IP ${ip} not present in any retrieved event` }); });
  for (const ip of c.summary.match(IP_RE) ?? []) if (!knownIps.has(ip)) issues.push({ path: "summary", problem: `IP ${ip} not present in any retrieved event` });

  // Strong verdicts require evidence. Abstention verdicts don't.
  if ((c.verdict === "confirmed" || c.verdict === "likely") && c.evidence.length === 0) issues.push({ path: "evidence", problem: `verdict ${c.verdict} requires at least one evidence item` });
  if (c.verdict === "confirmed" && c.confidence < 0.5) issues.push({ path: "confidence", problem: "confirmed verdict with confidence < 0.5 is inconsistent" });
  return issues;
}
