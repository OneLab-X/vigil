/**
 * LIVE verification against a real GCP project (read-only). Requires a running API + worker.
 * Usage: node --experimental-strip-types scripts/verify-gcp-live.mts [projectId] [hours] [authMode]
 * Reads dev credentials from .local/dev-credentials.json (never prints them).
 */
import fs from "node:fs";
const [projectId = "example-project", hours = "6", authMode = "gcloud_cli"] = process.argv.slice(2);
const base = process.env.VIGIL_API ?? "http://127.0.0.1:8080/api/v1";
const creds = JSON.parse(fs.readFileSync(new URL("../.local/dev-credentials.json", import.meta.url), "utf8"));
let cookie = "", csrf = "";
async function call(method: string, path: string, body?: unknown) {
  const r = await fetch(base + path, { method, headers: { "content-type": "application/json", cookie, ...(method !== "GET" ? { "x-vigil-csrf": csrf } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const sc = r.headers.get("set-cookie"); if (sc) cookie = sc.split(";")[0]!;
  const j: any = await r.json(); if (!r.ok) throw new Error(`${method} ${path} → ${r.status} ${JSON.stringify(j)}`); return j;
}
const step = (s: string) => console.log(`\n▶ ${s}`);
csrf = (await call("POST", "/auth/login", { email: "owner@vigil.test", password: creds["owner@vigil.test"] })).csrf;

step(`1. connect GCP project ${projectId} (auth: ${authMode})`);
const existing = (await call("GET", "/cloud-connections")).items.find((c: any) => c.config.projectId === projectId && c.status !== "disconnected");
const conn = existing ?? (await call("POST", "/cloud-connections", { provider: "gcp", displayName: projectId, projectId, authMode })).connection;
console.log("connection", conn.id, existing ? "(existing)" : "(created)");

step("2. validate access + read-only permissions");
const t = await call("POST", `/cloud-connections/${conn.id}/test`);
console.log({ ok: t.ok, readOnly: t.readOnly, principal: t.principal, sampleReadOk: t.sampleReadOk, errors: t.errors, warnings: t.warnings });
if (!t.ok) process.exit(1);

step("3. discover sources");
const d = await call("GET", `/cloud-connections/${conn.id}/sources`);
for (const s of d.discovered) console.log(`  ${s.available ? "✓" : "·"} ${s.sourceType.padEnd(28)} ${s.filter ?? ""}`);
const gae = d.discovered.find((s: any) => s.sourceType === "gcp_gae_app");
const audit = d.discovered.find((s: any) => s.sourceType === "gcp_audit_admin_activity");
const src = (await call("POST", `/cloud-connections/${conn.id}/sources`, { sourceType: gae.sourceType, name: gae.name, filter: gae.filter, enabled: true })).source;
const asrc = (await call("POST", `/cloud-connections/${conn.id}/sources`, { sourceType: audit.sourceType, name: audit.name, filter: audit.filter, enabled: true })).source;

step(`4-5. historical ingestion: last ${hours}h`);
const end = new Date(), start = new Date(end.getTime() - Number(hours) * 3600_000);
const jobs = [await call("POST", "/ingestion/jobs", { logSourceId: src.id, start: start.toISOString(), end: end.toISOString() }), await call("POST", "/ingestion/jobs", { logSourceId: asrc.id, start: new Date(end.getTime() - 7 * 86400_000).toISOString(), end: end.toISOString() })];
for (;;) {
  await new Promise((r) => setTimeout(r, 3000));
  const list = (await call("GET", "/ingestion/jobs?limit=20")).items.filter((j: any) => jobs.some((x) => x.job.id === j.id));
  console.log("  " + list.map((j: any) => `${j.kind}:${j.status} pages=${j.pagesFetched} seen=${j.eventsSeen} inserted=${j.eventsInserted} dup=${j.duplicates}${j.error ? " note=" + j.error : ""}`).join(" | "));
  if (list.every((j: any) => j.status === "succeeded" || j.status === "failed")) break;
}

step("6. stored + normalized events, trace correlation");
const ev = await call("GET", `/events?start=${start.toISOString()}&limit=5&eventType=http.request`);
console.log("  http.request events in range:", ev.total);
if (ev.items[0]) {
  const det = await call("GET", `/events/${ev.items[0].id}`);
  console.log("  sample:", ev.items[0].action, ev.items[0].httpStatus, "| integrity:", det.integrity, "| related by trace:", det.relatedByTrace.length);
}
const all = await call("GET", `/events?start=${start.toISOString()}&limit=1`);
console.log("  all events in range:", all.total);

step("7-8. detections and incidents (after detection job)");
await new Promise((r) => setTimeout(r, 5000));
const f = await call("GET", "/findings?limit=50");
console.log("  findings:", f.items.length, f.items.slice(0, 10).map((x: any) => `${x.rule.ruleId} ${x.title} (${x.eventCount})`));
const inc = await call("GET", "/incidents?limit=20");
console.log("  incidents:", inc.items.map((i: any) => `${i.caseId} [${i.severity}/${i.status}] ${i.title}`));
const runs = await call("GET", "/agents/runs?limit=5");
console.log("  agent runs:", runs.items.map((r: any) => `${r.role}:${r.status}${r.error ? " — " + r.error.slice(0, 160) : ""}`));
