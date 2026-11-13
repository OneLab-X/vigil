/**
 * Shared driver for LIVE, read-only connector verification against a real vendor account (manual; never in CI).
 * Talks only to a running Vigil API (+ worker); the connector itself only reads from the vendor.
 * Credentials come from environment variables and are never printed.
 */
import fs from "node:fs";

export interface LiveSpec {
  provider: string;
  displayName: string;
  config: Record<string, unknown>;
  credentials?: Record<string, unknown>;
  /** which discovered presets to enable (sourceType or preset name substring); default: all recommended + available */
  pick?: (s: { sourceType: string; name: string; available: boolean; recommended: boolean }) => boolean;
  hours: number;
  /** identity of the existing connection to reuse (matches accountRef) */
  accountRef: string;
}

export async function verifyLive(spec: LiveSpec) {
  const base = process.env.VIGIL_API ?? "http://127.0.0.1:8080/api/v1";
  const creds = JSON.parse(fs.readFileSync(new URL("../../.local/dev-credentials.json", import.meta.url), "utf8"));
  let cookie = "", csrf = "";
  const secretValues = Object.values(spec.credentials ?? {}).filter((v): v is string => typeof v === "string" && v.length >= 6);
  const safe = (s: string) => secretValues.reduce((acc, v) => acc.split(v).join("[REDACTED]"), s);
  async function call(method: string, path: string, body?: unknown) {
    const r = await fetch(base + path, { method, headers: { "content-type": "application/json", cookie, ...(method !== "GET" ? { "x-vigil-csrf": csrf } : {}) }, body: body ? JSON.stringify(body) : undefined });
    const sc = r.headers.get("set-cookie"); if (sc) cookie = sc.split(";")[0]!;
    const j: any = await r.json(); if (!r.ok) throw new Error(safe(`${method} ${path} → ${r.status} ${JSON.stringify(j)}`)); return j;
  }
  const step = (s: string) => console.log(`\n▶ ${s}`);
  csrf = (await call("POST", "/auth/login", { email: "owner@vigil.test", password: creds["owner@vigil.test"] })).csrf;

  step(`1. connect ${spec.provider} ${spec.accountRef}`);
  const existing = (await call("GET", "/cloud-connections")).items.find((c: any) => c.provider === spec.provider && c.accountRef === spec.accountRef && c.status !== "disconnected");
  const conn = existing ?? (await call("POST", "/cloud-connections", { provider: spec.provider, displayName: spec.displayName, config: spec.config, credentials: spec.credentials })).connection;
  console.log("connection", conn.id, existing ? "(existing)" : "(created)");

  step("2. validate access + read-only permissions");
  const t = await call("POST", `/cloud-connections/${conn.id}/test`);
  console.log({ ok: t.ok, readOnly: t.readOnly, principal: t.principal, credentialType: t.credentialType, sampleReadOk: t.sampleReadOk, errors: t.errors, warnings: t.warnings });
  console.log("  checks:", t.checks.map((c: any) => `${c.granted ? "✓" : "·"}${c.excessive ? "!" : ""} ${c.permission}`).join(" | "));
  for (const s of secretValues) if (JSON.stringify(t).includes(s)) throw new Error("SECRET LEAKED IN TEST RESULT");
  if (!t.ok) process.exit(1);

  step("3. discover sources");
  const d = await call("GET", `/cloud-connections/${conn.id}/sources`);
  for (const s of d.discovered) console.log(`  ${s.available ? "✓" : "·"} ${s.sourceType.padEnd(28)} ${s.name}${s.filter ? `  [${s.filter}]` : ""}`);
  const chosen = d.discovered.filter(spec.pick ?? ((s: any) => s.available && s.recommended));
  const sources = [];
  for (const s of chosen) sources.push((await call("POST", `/cloud-connections/${conn.id}/sources`, { sourceType: s.sourceType, name: s.name, filter: s.filter, enabled: true })).source);

  step(`4. historical ingestion: last ${spec.hours}h for ${sources.length} source(s)`);
  const end = new Date(), start = new Date(end.getTime() - spec.hours * 3600_000);
  const jobs = [];
  for (const s of sources) jobs.push(await call("POST", "/ingestion/jobs", { logSourceId: s.id, start: start.toISOString(), end: end.toISOString() }));
  for (;;) {
    await new Promise((r) => setTimeout(r, 3000));
    const list = (await call("GET", "/ingestion/jobs?limit=50")).items.filter((j: any) => jobs.some((x) => x.job.id === j.id));
    console.log("  " + list.map((j: any) => `${j.status} pages=${j.pagesFetched} seen=${j.eventsSeen} inserted=${j.eventsInserted} dup=${j.duplicates}${j.error ? " note=" + j.error.slice(0, 160) : ""}`).join(" | "));
    if (list.every((j: any) => j.status === "succeeded" || j.status === "failed")) break;
  }

  step("5. events in Event Explorer");
  const ev = await call("GET", `/events?start=${start.toISOString()}&limit=5`);
  console.log("  events in range:", ev.total);
  for (const e of ev.items) console.log(`   ${e.eventTimestamp} ${e.cloudProvider} ${e.normalizedEventType} ${e.principal ?? ""} ${e.sourceIp ?? ""} ${(e.action ?? e.message ?? "").slice(0, 80)}`);
  if (ev.items[0]) console.log("  raw integrity:", (await call("GET", `/events/${ev.items[0].id}`)).integrity);

  step("6. findings (after detection job)");
  await new Promise((r) => setTimeout(r, 5000));
  const f = await call("GET", "/findings?limit=50");
  console.log("  findings:", f.items.length, f.items.slice(0, 10).map((x: any) => `${x.rule.ruleId} ${x.title} (${x.eventCount})`));
}
