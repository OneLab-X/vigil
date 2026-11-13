import http from "node:http";
import { sql } from "drizzle-orm";
import { createDb } from "@vigil/db";
import { buildApp } from "../src/app.js";
import { getDb } from "../src/db.js";
import { addMember, createTenant, upsertUser } from "../src/services/tenancy.js";
import { resetRateLimits } from "../src/lib/ratelimit.js";

export const app = buildApp();

/** Wipe all data as the owner role (tests only). */
export async function resetDb() {
  const owner = createDb(process.env.VIGIL_OWNER_DATABASE_URL!, { max: 1 });
  const tables = ["audit_logs", "jobs", "sessions", "memberships", "users", "tenants"];
  await owner.db.execute(sql.raw(`truncate ${tables.join(", ")} cascade`));
  await owner.close();
  resetRateLimits();
  sessionCache.clear();
}

export async function ownerDb() { return createDb(process.env.VIGIL_OWNER_DATABASE_URL!, { max: 1 }); }

export async function seedTenant(slug: string) {
  const db = getDb();
  const owner = await upsertUser(db, `owner@${slug}.test`, `Owner ${slug}`, "pw-owner-123456");
  const analyst = await upsertUser(db, `analyst@${slug}.test`, `Analyst ${slug}`, "pw-analyst-123456");
  const analyst2 = await upsertUser(db, `reviewer@${slug}.test`, `Reviewer ${slug}`, "pw-reviewer-123456");
  const viewer = await upsertUser(db, `viewer@${slug}.test`, `Viewer ${slug}`, "pw-viewer-123456");
  const tenantId = await createTenant(db, `Tenant ${slug}`, slug, owner);
  await addMember(db, tenantId, analyst, "analyst");
  await addMember(db, tenantId, analyst2, "analyst");
  await addMember(db, tenantId, viewer, "viewer");
  return { tenantId, owner, analyst, analyst2, viewer };
}

const sessionCache = new Map<string, Client>();
/** Reuse sessions across tests so the login rate limiter isn't the thing under test everywhere. */
export async function as(email: string, password: string): Promise<Client> {
  const k = `${email}|${password}`;
  if (!sessionCache.has(k)) sessionCache.set(k, await new Client().login(email, password));
  return sessionCache.get(k)!;
}
export function clearSessions() { sessionCache.clear(); }

export class Client {
  cookie = "";
  csrf = "";
  async login(email: string, password: string) {
    const res = await app.request("/api/v1/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, password }) });
    if (res.status !== 200) throw new Error(`login failed ${res.status} ${await res.text()}`);
    this.cookie = res.headers.get("set-cookie")!.split(";")[0]!;
    this.csrf = ((await res.json()) as any).csrf;
    return this;
  }
  async req(method: string, path: string, body?: unknown, opts: { csrf?: boolean } = {}) {
    const headers: Record<string, string> = { cookie: this.cookie, "content-type": "application/json" };
    if (opts.csrf !== false) headers["x-vigil-csrf"] = this.csrf;
    const res = await app.request(`/api/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await res.text();
    let json: any; try { json = JSON.parse(text); } catch { json = text; }
    return { status: res.status, json };
  }
  get = (p: string) => this.req("GET", p);
  post = (p: string, b?: unknown) => this.req("POST", p, b ?? {});
  patch = (p: string, b: unknown) => this.req("PATCH", p, b);
}

export async function internal(path: string, token: string, body: unknown) {
  const res = await app.request(`/internal/v1${path}`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
  return { status: res.status, json: (await res.json()) as any };
}

/** Stub agent worker: records dispatched runs (so tests can act as the agent with the real run token). */
export function startAgentStub(port = 18091) {
  const runs: any[] = [];
  const server = http.createServer((req, res) => {
    let b = ""; req.on("data", (d) => (b += d)); req.on("end", () => { runs.push(JSON.parse(b || "{}")); res.writeHead(202, { "content-type": "application/json" }); res.end('{"accepted":true}'); });
  });
  return new Promise<{ runs: any[]; close: () => Promise<void> }>((r) => server.listen(port, "127.0.0.1", () => r({ runs, close: () => new Promise((d) => server.close(() => d())) })));
}
