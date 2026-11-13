import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { sql } from "drizzle-orm";
import { getDb } from "../src/db.js";
import { addMember, upsertUser } from "../src/services/tenancy.js";
import { classifySource, routeGroup } from "../src/services/operations.js";
import { histQuantile, latencyRecorder, LatencyRecorder, HIST_LEN, bucketIndex } from "../src/lib/latency.js";
import { sanitizeError } from "../src/lib/sanitize.js";
import { as, ownerDb, resetDb, seedTenant } from "./helpers.js";

let A: Awaited<ReturnType<typeof seedTenant>>;
let B: Awaited<ReturnType<typeof seedTenant>>;
let owner: Awaited<ReturnType<typeof ownerDb>>;
const ids: Record<string, string> = {};
const SECRET_URL = "postgres://vigil_app:hunter2-SECRET@db.internal.example:5432/vigil";

const one = async <T = any>(q: ReturnType<typeof sql>) => ((await owner.db.execute(q)) as unknown as T[])[0]!;

/** Fixtures are written as the owner role (bypasses RLS) so the API is the only thing under test. */
async function seedOps(tenantId: string, tag: string) {
  const conn = await one<{ id: string }>(sql`insert into cloud_connections (tenant_id, provider, display_name, config) values (${tenantId}, 'gcp', ${`conn-${tag}`}, '{}') returning id`);
  const acct = await one<{ id: string }>(sql`insert into cloud_accounts (tenant_id, connection_id, provider, external_id) values (${tenantId}, ${conn.id}, 'gcp', ${`proj-${tag}`}) returning id`);
  const src = async (name: string, enabled = true) => (await one<{ id: string }>(sql`insert into log_sources (tenant_id, connection_id, cloud_account_id, source_type, name, enabled)
    values (${tenantId}, ${conn.id}, ${acct.id}, 'gcp_gae_app', ${`${tag}-${name}`}, ${enabled}) returning id`)).id;
  const healthy = await src("healthy"), lagging = await src("lagging"), failing = await src("failing"), never = await src("never"), disabled = await src("disabled", false);
  const job = (s: string, status: string, minsAgo: number, error: string | null = null) => owner.db.execute(sql`insert into ingestion_jobs (tenant_id, log_source_id, kind, status, range_start, range_end, error, started_at, finished_at, created_at)
    values (${tenantId}, ${s}, 'incremental', ${status}, now() - interval '1 day', now(), ${error}, now() - make_interval(mins => ${minsAgo}), now() - make_interval(mins => ${minsAgo}), now() - make_interval(mins => ${minsAgo}))`);
  const wm = (s: string, minsAgo: number) => owner.db.execute(sql`insert into ingestion_checkpoints (tenant_id, log_source_id, watermark) values (${tenantId}, ${s}, now() - make_interval(mins => ${minsAgo}))`);
  await job(healthy, "succeeded", 3); await wm(healthy, 8);
  await job(lagging, "succeeded", 3); await wm(lagging, 120);
  await job(failing, "succeeded", 60); await job(failing, "failed", 2, `fetch failed: ${SECRET_URL} Bearer abcdefghijklmnop0123456789`); await wm(failing, 70);
  await wm(disabled, 600);

  // queue: 1 stuck running, 1 healthy running, 2 queued (one runnable 15 min old), 1 dead-lettered with a secret in last_error, 3 done
  const qj = (type: string, status: string, extra: ReturnType<typeof sql>) => one<{ id: string }>(sql`insert into jobs (tenant_id, type, payload, status, locked_at, run_after, attempts, last_error, updated_at)
    values (${tenantId}, ${type}, '{}', ${status}, ${extra}) returning id`);
  ids[`${tag}-stuck`] = (await qj("ingest", "running", sql`now() - interval '20 minutes', now() - interval '20 minutes', 1, null, now() - interval '20 minutes'`)).id;
  await qj("detect", "running", sql`now() - interval '1 minute', now() - interval '1 minute', 1, null, now()`);
  await qj("ingest", "queued", sql`null, now() - interval '15 minutes', 0, null, now()`);
  await qj("agent_run", "queued", sql`null, now() + interval '1 hour', 2, 'transient', now()`);
  ids[`${tag}-dead`] = (await qj("agent_run", "failed", sql`null, now(), 5, ${`agent call failed ${SECRET_URL} api_key=sk-live-abcdefghijklmnopqrstuvwxyz`}, now() - interval '1 hour'`)).id;
  for (let i = 0; i < 3; i++) await qj("detect", "done", sql`null, now(), 1, null, now() - interval '5 minutes'`);

  // investigations + model usage: 3 succeeded runs (0.012, 0.020, 0.100), 1 failed run (0.5), 1 old usage row outside 24h
  const inc = await one<{ id: string }>(sql`insert into incidents (tenant_id, case_number, title, severity, correlation_key, first_seen, last_seen) values (${tenantId}, 1, 'x', 'high', ${`k-${tag}`}, now(), now()) returning id`);
  const def = await one<{ id: string }>(sql`insert into agent_definitions (tenant_id, role, version, prompt_version, model_provider, model_name, allowed_tools) values (${tenantId}, 'investigation_analyst', 99, 'v1', 'anthropic', 'claude', '[]') returning id`);
  const run = async (status: string, usage: Array<[string, string, string]>, error: string | null = null) => {
    const r = await one<{ id: string }>(sql`insert into investigation_runs (tenant_id, incident_id, agent_definition_id, role, status, task, error) values (${tenantId}, ${inc.id}, ${def.id}, 'investigation_analyst', ${status}, 't', ${error}) returning id`);
    for (const [provider, model, c] of usage) await owner.db.execute(sql`insert into model_usage (tenant_id, run_id, provider, model, input_tokens, output_tokens, cost_usd) values (${tenantId}, ${r.id}, ${provider}, ${model}, 1000, 100, ${c})`);
    return r.id;
  };
  await run("succeeded", [["anthropic", "claude-a", "0.010000"], ["openai", "gpt-x", "0.002000"]]);
  await run("succeeded", [["anthropic", "claude-a", "0.020000"]]);
  await run("succeeded", [["anthropic", "claude-a", "0.100000"]]);
  ids[`${tag}-failedrun`] = await run("failed", [["anthropic", "claude-a", "0.500000"]], "model error token=supersecretvalue123");
  await owner.db.execute(sql`insert into model_usage (tenant_id, run_id, provider, model, input_tokens, output_tokens, cost_usd, created_at) values (${tenantId}, null, 'anthropic', 'claude-a', 1, 1, '9.000000', now() - interval '2 days')`);

  await owner.db.execute(sql`insert into raw_event_references (tenant_id, storage_uri, sha256, size_bytes) values (${tenantId}, 'file:///x', ${`sha-${tag}-1`}, 1000), (${tenantId}, 'file:///y', ${`sha-${tag}-2`}, 2500)`);
  return { healthy, lagging, failing, never, disabled };
}

let srcA: Awaited<ReturnType<typeof seedOps>>;

beforeAll(async () => {
  await resetDb();
  owner = await ownerDb();
  A = await seedTenant("opsa");
  B = await seedTenant("opsb");
  const admin = await upsertUser(getDb(), "admin@opsa.test", "Admin opsa", "pw-admin-123456");
  await addMember(getDb(), A.tenantId, admin, "admin");
  await owner.db.execute(sql`delete from worker_heartbeats`);
  srcA = await seedOps(A.tenantId, "a");
});
afterAll(async () => { await owner.close(); });

const ownerA = () => as("owner@opsa.test", "pw-owner-123456");
const ownerB = () => as("owner@opsb.test", "pw-owner-123456");

describe("operations: RBAC", () => {
  it("viewer and analyst get 403; admin and owner get 200", async () => {
    expect((await (await as("viewer@opsa.test", "pw-viewer-123456")).get("/operations/overview")).status).toBe(403);
    expect((await (await as("analyst@opsa.test", "pw-analyst-123456")).get("/operations/overview")).status).toBe(403);
    expect((await (await as("admin@opsa.test", "pw-admin-123456")).get("/operations/overview")).status).toBe(200);
    expect((await (await ownerA()).get("/operations/overview")).status).toBe(200);
  });

  it("exposes operations:read only to admin and owner via /auth/me", async () => {
    expect((await (await as("viewer@opsa.test", "pw-viewer-123456")).get("/auth/me")).json.permissions).not.toContain("operations:read");
    expect((await (await as("analyst@opsa.test", "pw-analyst-123456")).get("/auth/me")).json.permissions).not.toContain("operations:read");
    expect((await (await as("admin@opsa.test", "pw-admin-123456")).get("/auth/me")).json.permissions).toContain("operations:read");
  });

  it("validates the window parameter", async () => {
    expect((await (await ownerA()).get("/operations/overview?window=2y")).status).toBe(400);
    expect((await (await ownerA()).get("/operations/overview?lagThresholdMinutes=1")).status).toBe(400);
  });

  it("is documented in OpenAPI under the operations tag", async () => {
    const { app } = await import("./helpers.js");
    const doc = (await (await app.request("/api/v1/openapi.json")).json()) as any;
    expect(doc.paths["/api/v1/operations/overview"].get.tags).toEqual(["operations"]);
  });
});

describe("operations: classification", () => {
  it("classifies log sources (unit)", () => {
    const now = new Date("2026-01-01T12:00:00Z");
    const ago = (m: number) => new Date(now.getTime() - m * 60_000);
    expect(classifySource({ enabled: true, watermark: ago(10), lastFinishedStatus: "succeeded" }, now, 30)).toBe("healthy");
    expect(classifySource({ enabled: true, watermark: ago(31), lastFinishedStatus: "succeeded" }, now, 30)).toBe("lagging");
    expect(classifySource({ enabled: true, watermark: null, lastFinishedStatus: "succeeded" }, now, 30)).toBe("lagging");
    expect(classifySource({ enabled: true, watermark: ago(1), lastFinishedStatus: "failed" }, now, 30)).toBe("failing");
    expect(classifySource({ enabled: true, watermark: null, lastFinishedStatus: null }, now, 30)).toBe("never_run");
    expect(classifySource({ enabled: false, watermark: ago(999), lastFinishedStatus: "failed" }, now, 30)).toBe("disabled");
  });

  it("reports ingestion lag per source with the configured threshold", async () => {
    const r = (await (await ownerA()).get("/operations/overview")).json;
    const by = Object.fromEntries(r.ingestion.sources.map((s: any) => [s.id, s]));
    expect(by[srcA.healthy].status).toBe("healthy");
    expect(by[srcA.healthy].lagSeconds).toBeGreaterThanOrEqual(8 * 60 - 5);
    expect(by[srcA.lagging].status).toBe("lagging");
    expect(by[srcA.failing].status).toBe("failing");
    expect(by[srcA.never].status).toBe("never_run");
    expect(by[srcA.disabled].status).toBe("disabled");
    expect(by[srcA.failing].lastSuccessAt).not.toBeNull();
    expect(r.ingestion.thresholdMinutes).toBe(30);
    expect(r.ingestion.counts).toEqual({ healthy: 1, lagging: 1, failing: 1, never_run: 1, disabled: 1 });
    // a larger threshold turns the 2h-old watermark healthy
    const r2 = (await (await ownerA()).get("/operations/overview?lagThresholdMinutes=180")).json;
    expect(r2.ingestion.sources.find((s: any) => s.id === srcA.lagging).status).toBe("healthy");
  });

  it("reports queue depth, oldest queued age, stuck and dead-lettered jobs", async () => {
    const q = (await (await ownerA()).get("/operations/overview")).json.queue;
    expect(q.stuck).toBe(1);
    expect(q.stuckJobs.map((j: any) => j.id)).toEqual([ids["a-stuck"]]);
    expect(q.running).toBe(2);
    expect(q.deadLettered).toBe(1);
    expect(q.runnable).toBe(1);
    expect(q.scheduled).toBe(1);
    expect(q.retrying).toBe(1);
    expect(q.oldestQueuedSeconds).toBeGreaterThanOrEqual(15 * 60 - 5);
    expect(q.oldestQueuedSeconds).toBeLessThan(16 * 60);
    const done = q.byTypeStatus.find((x: any) => x.type === "detect" && x.status === "done");
    expect(done.n).toBe(3);
  });

  it("reports worker heartbeat as unknown, ok, then stale", async () => {
    const worker = async () => (await (await ownerA()).get("/operations/overview")).json.components.find((c: any) => c.id === "worker");
    expect((await worker()).status).toBe("unknown");
    const { workerHeartbeat } = await import("../src/worker.js");
    const id = "00000000-0000-4000-8000-000000000001";
    await workerHeartbeat(getDb(), id);
    expect((await worker()).status).toBe("ok");
    await owner.db.execute(sql`update worker_heartbeats set last_seen_at = now() - interval '10 minutes' where worker_id = ${id}`);
    expect((await worker()).status).toBe("stale");
  });

  it("includes component health without leaking connection details", async () => {
    const r = (await (await ownerA()).get("/operations/overview")).json;
    expect(r.components.map((c: any) => c.id)).toEqual(["database", "schema", "evidenceStore", "agents", "worker"]);
    expect(r.components.find((c: any) => c.id === "database").status).toBe("ok");
    expect(JSON.stringify(r.components)).not.toMatch(/127\.0\.0\.1|localhost|vigil_app_dev/);
  });
});

describe("operations: failures and sanitization", () => {
  it("counts failures over 24h/7d and returns sanitized recent errors", async () => {
    const r = (await (await ownerA()).get("/operations/overview")).json;
    expect(r.failures.counts).toEqual({ jobs: { "24h": 1, "7d": 1 }, ingestion: { "24h": 1, "7d": 1 }, investigations: { "24h": 1, "7d": 1 } });
    const kinds = r.failures.recent.map((f: any) => f.kind).sort();
    expect(kinds).toEqual(["ingestion", "investigation", "job"]);
    const body = JSON.stringify(r);
    for (const leak of ["hunter2-SECRET", "db.internal.example", "abcdefghijklmnop0123456789", "sk-live-abcdefghijklmnopqrstuvwxyz", "supersecretvalue123", "vigil_app:"]) expect(body).not.toContain(leak);
    expect(r.failures.recent.find((f: any) => f.kind === "job").error).toContain("postgres://[redacted]");
  });

  it("sanitizeError strips credentials, tokens and URLs and truncates (unit)", () => {
    const s = sanitizeError(`boom ${SECRET_URL} Authorization: Bearer abc.def.ghi-12345678 password=p@ss AKIAABCDEFGHIJKLMNOP eyJhbGciOi.eyJzdWIiOiJ4.c2lnbmF0dXJl https://user:pw@api.example.com/x?token=t0k3n`)!;
    for (const leak of ["hunter2", "db.internal", "abc.def.ghi", "p@ss", "AKIAABCDEFGHIJKLMNOP", "eyJhbGciOi", "user:pw", "api.example.com", "t0k3n"]) expect(s).not.toContain(leak);
    expect(sanitizeError("word ".repeat(300), 50)!.length).toBe(50);
    expect(sanitizeError("x".repeat(1000))).toBe("[redacted]");
    expect(sanitizeError(null)).toBeNull();
    expect(sanitizeError("line1\n\tline2")).toBe("line1 line2");
  });
});

describe("operations: cost per investigation", () => {
  it("aggregates model usage with numeric math and returns fixed-decimal strings", async () => {
    const c = (await (await ownerA()).get("/operations/overview?window=24h")).json.cost;
    expect(c.totalUsd).toBe("0.632000"); // 0.012 + 0.02 + 0.1 + 0.5; the 2-day-old 9.00 row is outside 24h
    expect(c.modelCalls).toBe(5);
    expect(c.perInvestigation).toMatchObject({ completedRuns: 3, avgUsd: "0.044000", p95Usd: "0.100000", totalUsd: "0.132000" });
    const claude = c.byModel.find((m: any) => m.model === "claude-a");
    expect(claude).toMatchObject({ provider: "anthropic", calls: 4, runs: 4, costUsd: "0.630000" });
    expect(c.byModel.find((m: any) => m.model === "gpt-x").costUsd).toBe("0.002000");
    const c7 = (await (await ownerA()).get("/operations/overview?window=7d")).json.cost;
    expect(c7.totalUsd).toBe("9.632000");
  });

  it("reports storage for the tenant", async () => {
    const s = (await (await ownerA()).get("/operations/overview")).json.storage;
    expect(s.rawEvidenceBytes).toBe(3500);
    expect(s.rawEvidenceObjects).toBe(2);
    expect(typeof s.securityEvents).toBe("number");
    expect(s.databaseBytes === null || s.databaseBytes > 0).toBe(true);
  });
});

describe("operations: latency middleware", () => {
  it("records route templates, never raw paths or query strings, and only for tenant-bound requests", async () => {
    await latencyRecorder.flush(getDb()); // discard anything buffered by earlier requests
    await owner.db.execute(sql`delete from api_latency_rollups`);
    const a = await ownerA();
    const raw = "11111111-2222-4333-8444-555555555555";
    await a.get(`/incidents/${raw}?secret=querystringvalue`);
    await a.get(`/incidents/${raw}`);
    await a.get(`/operations/overview?window=1h`);
    await a.get(`/no-such-route/${raw}`);
    const { app } = await import("./helpers.js");
    await app.request(`/api/v1/incidents/${raw}`); // unauthenticated: not attributable → not recorded
    await latencyRecorder.flush(getDb());
    const rows = (await owner.db.execute(sql`select tenant_id, method, route, count, status_4xx, status_5xx, hist from api_latency_rollups`)) as unknown as any[];
    const routes = rows.map((r) => r.route);
    expect(routes).toContain("/incidents/:id");
    expect(routes).toContain("/operations/overview");
    expect(routes).toContain("unmatched");
    expect(JSON.stringify(rows)).not.toContain(raw);
    expect(JSON.stringify(rows)).not.toContain("querystringvalue");
    expect(rows.every((r) => r.tenant_id === A.tenantId)).toBe(true);
    const inc = rows.find((r) => r.route === "/incidents/:id");
    expect(inc.count).toBe(2);
    expect(inc.status_4xx).toBe(2); // 404 not found
    expect(inc.hist.length).toBe(HIST_LEN);
    expect(inc.hist.reduce((n: number, v: number) => n + v, 0)).toBe(2);
  });

  it("merges flushes additively into the same minute bucket", async () => {
    const rec = new LatencyRecorder();
    const at = Date.now();
    rec.record(A.tenantId, "GET", "/merge-test", 200, 3, at);
    await rec.flush(getDb());
    rec.record(A.tenantId, "GET", "/merge-test", 503, 700, at);
    await rec.flush(getDb());
    const r = await one<any>(sql`select count, status_5xx, max_ms, hist from api_latency_rollups where route = '/merge-test'`);
    expect(r.count).toBe(2);
    expect(r.status_5xx).toBe(1);
    expect(r.max_ms).toBe(700);
    expect(r.hist[bucketIndex(3)]).toBe(1);
    expect(r.hist[bucketIndex(700)]).toBe(1);
  });

  it("serves p50/p95/p99 and error rate per route group", async () => {
    const l = (await (await ownerA()).get("/operations/overview?window=1h")).json.latency;
    const g = l.groups.find((x: any) => x.group === "incidents");
    expect(g.requests).toBe(2);
    expect(g.p50Ms).not.toBeNull();
    expect(g.p95Ms).toBeGreaterThanOrEqual(g.p50Ms);
    expect(g.p99Ms).toBeGreaterThanOrEqual(g.p95Ms);
    expect(l.groups.find((x: any) => x.group === "merge-test").errorRate).toBe(0.5);
    expect(l.series.length).toBeGreaterThan(0);
    // 30d is clamped to the 7-day rollup retention
    expect((await (await ownerA()).get("/operations/overview?window=30d")).json.latency.windowHours).toBe(168);
  });

  it("histogram quantiles and route groups (unit)", () => {
    const h = new Array(HIST_LEN).fill(0);
    h[bucketIndex(20)] = 90; // (10,25]
    h[bucketIndex(400)] = 10; // (250,500]
    expect(histQuantile(h, 0.5, 450)).toBeGreaterThan(10);
    expect(histQuantile(h, 0.5, 450)).toBeLessThanOrEqual(25);
    expect(histQuantile(h, 0.95, 450)).toBeGreaterThan(250);
    expect(histQuantile(h, 0.99, 450)).toBeLessThanOrEqual(450);
    expect(histQuantile(new Array(HIST_LEN).fill(0), 0.5, 0)).toBeNull();
    expect(routeGroup("/incidents/:id/notes")).toBe("incidents");
    expect(routeGroup("unmatched")).toBe("unmatched");
  });
});

describe("operations: cross-tenant isolation", () => {
  it("tenant B never sees tenant A's sources, jobs, failures, costs, latency or storage", async () => {
    // generate some B traffic so B has its own latency rows
    const b = await ownerB();
    await b.get("/incidents?limit=1");
    await latencyRecorder.flush(getDb());
    const r = (await b.get("/operations/overview?window=7d")).json;
    expect(r.ingestion.sources).toEqual([]);
    expect(r.queue.byTypeStatus).toEqual([]);
    expect(r.queue.stuck).toBe(0);
    expect(r.queue.deadLettered).toBe(0);
    expect(r.failures.recent).toEqual([]);
    expect(r.failures.counts.jobs["7d"]).toBe(0);
    expect(r.cost.totalUsd).toBe("0.000000");
    expect(r.cost.byModel).toEqual([]);
    expect(r.cost.hasInvestigations).toBe(false);
    expect(r.storage.rawEvidenceBytes).toBe(0);
    expect(r.latency.groups.map((g: any) => g.group)).not.toContain("merge-test");
    expect(r.latency.routes.every((x: any) => x.route !== "/operations/overview" || x.requests >= 0)).toBe(true);
    const body = JSON.stringify(r);
    for (const id of [ids["a-stuck"], ids["a-dead"], ids["a-failedrun"], srcA.healthy, srcA.failing]) expect(body).not.toContain(id!);
    // and A still sees its own
    const ra = (await (await ownerA()).get("/operations/overview?window=7d")).json;
    expect(ra.ingestion.sources.length).toBe(5);
    expect(ra.latency.groups.map((g: any) => g.group)).not.toContain("incidents?limit=1");
  });

  it("latency rollups are protected by RLS", async () => {
    const { withTenant } = await import("@vigil/db");
    const n = await withTenant(getDb(), { tenantId: B.tenantId }, (tx) => tx.execute(sql`select count(*)::int as n from api_latency_rollups where route = '/merge-test'`)) as unknown as Array<{ n: number }>;
    expect(n[0]!.n).toBe(0);
    const none = (await getDb().execute(sql`select count(*)::int as n from api_latency_rollups`)) as unknown as Array<{ n: number }>;
    expect(none[0]!.n).toBe(0);
  });

  it("answers within the latency budget on the fixture dataset", async () => {
    const r = (await (await ownerA()).get("/operations/overview?window=30d")).json;
    expect(r.queryMs).toBeLessThan(1000); // budget is 300 ms on the seeded dev DB; generous here for CI noise
  });
});
