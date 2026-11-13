/**
 * Demo data for screenshots, docs and walkthroughs — SYNTHETIC ONLY.
 *
 * Fills an EMPTY database (refuses otherwise, and refuses in production) with the replay scenarios from
 * packages/core/src/fixtures/synthetic.ts pushed through the real pipeline: connections → ingestion → detection →
 * correlation → agent triage/investigation (scripted, in-process) → human approval → knowledge. IPs are RFC 5737
 * documentation ranges, the cloud project is `example-project`, the AWS account `111122223333`, people `@example.com`.
 *
 *   VIGIL_DATABASE_URL=…/vigil_demo VIGIL_DATA_DIR=/tmp/vigil-demo pnpm db:demo
 *
 * Generated passwords go to $VIGIL_DATA_DIR/demo-credentials.json (mode 600), never stdout.
 */
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { sql } from "drizzle-orm";
import { buildScenarios, normalizeCloudTrail, normalizeGcpEntry, type CloudConnector } from "@vigil/core";
import { buildApp } from "./app.js";
import { closeDb, getDb } from "./db.js";
import { env } from "./env.js";
import { randomToken } from "./lib/crypto.js";
import { setConnectorOverride } from "./services/connectors.js";
import { addMember, createTenant, upsertUser } from "./services/tenancy.js";
import { drainOnce } from "./worker.js";

if (env.nodeEnv === "production") { console.error("refusing to load demo data in production"); process.exit(1); }
const db = getDb();
const [{ n }] = (await db.execute(sql`select count(*)::int as n from users`)) as unknown as Array<{ n: number }>;
if (n > 0) { console.error("refusing: this database already has users. Point VIGIL_DATABASE_URL at a fresh, migrated database."); process.exit(1); }

// ---------- in-process agent stub: the "agent" answers below, through the real internal API ----------
const runs: any[] = [];
const agentPort = Number(new URL(env.agentsUrl).port || 80);
const agent = http.createServer((req, res) => { let b = ""; req.on("data", (d) => (b += d)); req.on("end", () => { runs.push(JSON.parse(b || "{}")); res.writeHead(202); res.end("{}"); }); });
await new Promise<void>((r) => agent.listen(agentPort, "127.0.0.1", () => r()));

// ---------- fixture connector ----------
const scenarios = buildScenarios(new Date(Date.now() - 3 * 3600_000));
const gcpRaw = scenarios.flatMap((s) => s.gcp ?? []);
const awsRaw = scenarios.flatMap((s) => s.aws ?? []);
const isAudit = (e: any) => String(e.logName ?? "").includes("cloudaudit");
const fixture = (provider: "gcp" | "aws"): CloudConnector => ({
  provider,
  async connect() {},
  async testConnection() {
    return { ok: true, provider, accountRef: provider === "gcp" ? "example-project" : "111122223333", principal: provider === "gcp" ? "vigil-reader@example-project.iam.gserviceaccount.com" : "arn:aws:iam::111122223333:role/vigil-reader",
      credentialType: provider === "gcp" ? "workload identity federation" : "assumed role", checks: [{ permission: provider === "gcp" ? "logging.logEntries.list" : "cloudtrail:LookupEvents", granted: true, required: true }],
      readOnly: true, warnings: [], errors: [], sampleReadOk: true, testedAt: new Date().toISOString() };
  },
  async discoverSources() {
    return provider === "gcp"
      ? [{ sourceType: "gcp_gae_app", name: "App Engine · default module", filter: 'resource.type="gae_app" AND resource.labels.module_id="default"', description: "Request and application logs", available: true, recommended: true },
         { sourceType: "gcp_audit_admin_activity", name: "Cloud Audit Logs · Admin Activity", filter: 'logName:"cloudaudit.googleapis.com%2Factivity"', description: "IAM, config and resource changes", available: true, recommended: true }]
      : [{ sourceType: "aws_cloudtrail_management", name: "CloudTrail management events", filter: null, description: "", available: true, recommended: true }];
  },
  async listEvents(q) {
    const raw = provider === "aws" ? awsRaw : gcpRaw.filter((e) => (q.sourceType.startsWith("gcp_audit") ? isAudit(e) : !isAudit(e)));
    return { raw, nextPageToken: null };
  },
  normalize(raw, sourceType) {
    return provider === "gcp" ? normalizeGcpEntry(raw as any, { projectId: "example-project", sourceType }) : normalizeCloudTrail(raw as any, { sourceType });
  },
  async getCheckpoint() { return null; }, async saveCheckpoint() {}, async disconnect() {},
});
setConnectorOverride((row) => fixture(row.provider as "gcp" | "aws"));

// ---------- people ----------
const app = buildApp();
const creds: Record<string, string> = {};
const person = async (email: string, name: string) => upsertUser(db, email, name, (creds[email] = randomToken(15)));
const owner = await person("owner@example.com", "Olivia Owner");
const admin = await person("admin@example.com", "Adam Admin");
const analyst = await person("analyst@example.com", "Arjun Analyst");
const reviewer = await person("reviewer@example.com", "Riya Reviewer");
const viewer = await person("viewer@example.com", "Vik Viewer");
const tenantId = await createTenant(db, "Example Security", "example", owner);
await addMember(db, tenantId, admin, "admin");
await addMember(db, tenantId, analyst, "analyst");
await addMember(db, tenantId, reviewer, "analyst");
await addMember(db, tenantId, viewer, "viewer");

class Session {
  cookie = ""; csrf = "";
  async login(email: string) {
    const res = await app.request("/api/v1/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, password: creds[email] }) });
    if (res.status !== 200) throw new Error(`login ${email}: ${res.status}`);
    this.cookie = res.headers.get("set-cookie")!.split(";")[0]!; this.csrf = ((await res.json()) as any).csrf; return this;
  }
  async call(method: string, p: string, body?: unknown): Promise<any> {
    const res = await app.request(`/api/v1${p}`, { method, headers: { cookie: this.cookie, "x-vigil-csrf": this.csrf, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
    const j = await res.json().catch(() => null);
    if (res.status >= 400) throw new Error(`${method} ${p}: ${res.status} ${JSON.stringify(j)}`);
    return j;
  }
  get = (p: string) => this.call("GET", p);
  post = (p: string, b: unknown = {}) => this.call("POST", p, b);
  patch = (p: string, b: unknown) => this.call("PATCH", p, b);
}
const internal = async (p: string, token: string, body: unknown): Promise<any> => {
  const res = await app.request(`/internal/v1${p}`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
  return res.json();
};
const tool = async (run: any, name: string, args: unknown = {}) => {
  const r = await internal(`/broker/tools/${name}`, run.run_token, args);
  return r.result_json ? JSON.parse(r.result_json) : r.result;
};
const usage = { steps: 4, input_tokens: 18_400, output_tokens: 2_100, cost_usd: 0.031, model_provider: "openai_compatible", model_name: "llama-3.3-70b" };

const o = await new Session().login("owner@example.com");
const a = await new Session().login("analyst@example.com");
const rv = await new Session().login("reviewer@example.com");

// ---------- connections & ingestion ----------
const range = { start: new Date(Date.now() - 6 * 3600_000).toISOString(), end: new Date().toISOString() };
const gcp = (await o.post("/cloud-connections", { provider: "gcp", displayName: "example-project", projectId: "example-project", authMode: "adc" })).connection;
await o.post(`/cloud-connections/${gcp.id}/test`);
for (const s of (await o.get(`/cloud-connections/${gcp.id}/sources`)).discovered) {
  const src = (await o.post(`/cloud-connections/${gcp.id}/sources`, { sourceType: s.sourceType, name: s.name, filter: s.filter })).source;
  await o.post("/ingestion/jobs", { logSourceId: src.id, ...range });
}
const aws = (await o.post("/cloud-connections", { provider: "aws", displayName: "prod-aws", accountId: "111122223333", roleArn: "arn:aws:iam::111122223333:role/vigil-reader", regions: ["us-east-1"] })).connection;
await o.post(`/cloud-connections/${aws.id}/test`);
const ct = (await o.post(`/cloud-connections/${aws.id}/sources`, { sourceType: "aws_cloudtrail_management", name: "CloudTrail management events", filter: null })).source;
await o.post("/ingestion/jobs", { logSourceId: ct.id, ...range });
await drainOnce(db, 500);

// ---------- agents: triage every case; full investigation on the brute-force case ----------
const ATTACKER = "198.51.100.77";
const incidents = (await o.get("/incidents?limit=100")).items as any[];
const brute = incidents.find((i) => i.correlationKey === `sourceIp:${ATTACKER}`);
const handled = new Set<string>();
for (let round = 0; round < 4; round++) {
  for (const run of runs.filter((r) => !handled.has(r.run_id))) {
    handled.add(run.run_id);
    const ctx = await tool(run, "get_case_context");
    const ev = ctx?.events?.[0];
    if (run.role === "detection_analyst") {
      const isBrute = run.case_id === brute?.caseId;
      await internal(`/runs/${run.run_id}/result`, run.run_token, { status: "succeeded", usage: { ...usage, input_tokens: 6_200, output_tokens: 400, cost_usd: 0.004 }, output: {
        should_investigate: isBrute, priority: isBrute ? "high" : "medium",
        rationale: isBrute ? "Repeated failed logins followed by a success from the same source IP." : "Pattern matches the rule but no follow-on activity; leaving for analyst review.",
        related_event_ids: ev ? [ev.event_id] : [] } });
    } else if (run.role === "investigation_analyst" && run.case_id === brute?.caseId) {
      const hits = await tool(run, "search_events", { filters: { source_ip: ATTACKER, http_status: 200 }, start: range.start });
      const success = hits.events[0];
      const fail = ctx.events.find((e: any) => e.http_status === 401);
      await internal(`/runs/${run.run_id}/result`, run.run_token, { status: "succeeded", usage, output: {
        case_id: run.case_id, verdict: "likely", severity: "high", confidence: 0.8,
        summary: `${ATTACKER} made 14 failed login attempts followed by one successful login; credential compromise is likely.`,
        timeline: [{ timestamp: fail.event_timestamp, description: "First failed login", event_id: fail.event_id }, { timestamp: success.event_timestamp, description: "Successful login", event_id: success.event_id }],
        entities: { ips: [ATTACKER], principals: [], resources: [] },
        evidence: [{ event_id: fail.event_id, claim: `POST /v1/auth/login from ${ATTACKER} returned 401`, cited_fields: { source_ip: ATTACKER, http_status: 401 } },
          { event_id: success.event_id, claim: "Subsequent login returned 200", cited_fields: { http_status: 200 } }],
        contradictory_evidence: [{ event_id: success.event_id, claim: "Only one successful request; no post-login activity observed from this IP", cited_fields: { url_path: "/v1/auth/login" } }],
        impact_assessment: { outcome: "succeeded", scope: "one application account may be compromised", data_exposure: "unknown" },
        recommended_actions: [{ action: "Reset the password for the targeted account and invalidate its sessions", rationale: "Successful login after brute force", priority: "urgent" },
          { action: `Block ${ATTACKER} at the load balancer for 24 hours`, rationale: "Source of the credential-stuffing attempts", priority: "high" }],
        requires_human_approval: true } });
    }
  }
  await drainOnce(db, 500);
}

// ---------- human decisions, knowledge, evaluation ----------
if (brute) {
  const ws = await a.get(`/incidents/${brute.id}`);
  const verdict = ws.verdicts[0];
  if (verdict) {
    await a.post(`/incidents/${brute.id}/approve`, { verdictId: verdict.id, decision: "approved", comment: "Confirmed with the app owner; account reset requested." });
    if (ws.recommendations[0]) await a.patch(`/recommendations/${ws.recommendations[0].id}`, { status: "approved" });
  }
  await a.patch(`/incidents/${brute.id}`, { assigneeId: analyst });
  await a.post(`/incidents/${brute.id}/notes`, { body: "Account owner confirmed they did not log in. Password reset and sessions revoked." });
  const fb = await a.post(`/incidents/${brute.id}/feedback`, { kind: "lesson", key: "VGL-AUTH-001", title: "Brute force followed by success", body: "Always check for a 2xx after repeated 401s from the same IP." });
  await rv.post(`/knowledge/${fb.knowledge.id}/decision`, { decision: "approved" });
}
const tf = await a.post("/knowledge", { kind: "trusted_identity", key: "terraform@example-project.iam.gserviceaccount.com", title: "Terraform CI service account", body: "Managed by the platform team; creates deployer keys during rotations." });
await rv.post(`/knowledge/${tf.knowledge.id}/decision`, { decision: "approved" });
await a.post("/knowledge", { kind: "known_false_positive", key: "VGL-HTTP-404-RECON", title: "Uptime checker probes", body: "The uptime monitor requests random paths every few minutes; 404 bursts from 192.0.2.10 are expected." }).catch(() => null);
await o.post("/evaluations/detection-replay");

// ---------- settings shown in the docs ----------
await o.post("/model-providers", { name: "Local Ollama", kind: "openai_compatible", baseUrl: "http://host.docker.internal:11434/v1", apiKey: null, hosting: "customer_hosted", timeoutSeconds: 120, priceInputPerMtok: 0, priceOutputPerMtok: 0 });
await o.post("/members", { email: "new.hire@example.com", displayName: "Nina Newhire", role: "viewer" });
await o.post("/notification-channels", { kind: "slack", name: "SOC Slack", minSeverity: "high", webhookUrl: "https://hooks.slack.com/services/T00000000/B00000000/EXAMPLEEXAMPLEEXAMPLE", config: { label: "#sec-alerts", redactEntities: false } });
await o.post("/notification-channels", { kind: "email", name: "On-call email", minSeverity: "critical", config: { host: "smtp.example.com", port: 587, security: "starttls", verifyCert: true, username: "alerts@example.com", from: "vigil@example.com", fromName: "Vigil", to: ["soc@example.com", "oncall@example.com"], redactEntities: true }, password: "example-password" });

await fs.mkdir(env.dataDir, { recursive: true });
const file = path.join(env.dataDir, "demo-credentials.json");
await fs.writeFile(file, JSON.stringify(creds, null, 2), { mode: 0o600 });
const final = (await o.get("/incidents?limit=100")).items as any[];
console.log(`demo tenant "Example Security": ${final.length} incidents, ${runs.length} agent runs; credentials in ${file}`);
setConnectorOverride(null);
agent.close();
await closeDb();
process.exit(0);
