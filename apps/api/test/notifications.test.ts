import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest";
import http from "node:http";
import dns from "node:dns/promises";
import { randomUUID } from "node:crypto";
import { SMTPServer } from "smtp-server";
import { sql } from "drizzle-orm";
import { detectionRules, findings, jobs, withTenant } from "@vigil/db";
import { getDb } from "../src/db.js";
import { drainOnce } from "../src/worker.js";
import { correlate } from "../src/services/detection.js";
import { buildIncidentMessage, resolveSmtpHost } from "../src/services/notifications.js";
import { as, ownerDb, resetDb, seedTenant, startAgentStub } from "./helpers.js";

const SLACK_PORT = 18092, SMTP_PORT = 18025;
const SLACK_ORIGIN = `http://127.0.0.1:${SLACK_PORT}`;
process.env.VIGIL_SLACK_WEBHOOK_HOSTS = SLACK_ORIGIN;
const HOOK = `${SLACK_ORIGIN}/services/T000/B000/SECRETtoken123456`;

let A: Awaited<ReturnType<typeof seedTenant>>;
let B: Awaited<ReturnType<typeof seedTenant>>;
let agent: Awaited<ReturnType<typeof startAgentStub>>;
const ownerA = () => as("owner@alpha.test", "pw-owner-123456");
const adminA = async () => as("analyst@alpha.test", "pw-analyst-123456");

// ---- Slack stub ----
const slack = { posts: [] as Array<{ path: string; body: any }>, fail: 0 as number, failBody: "" };
const slackServer = http.createServer((req, res) => {
  let b = ""; req.on("data", (d) => (b += d));
  req.on("end", () => {
    if (slack.fail > 0) { slack.fail--; res.writeHead(400); res.end(slack.failBody || "invalid_payload"); return; }
    slack.posts.push({ path: req.url ?? "", body: JSON.parse(b || "{}") }); res.writeHead(200); res.end("ok");
  });
});
// ---- SMTP sink ----
const mails: Array<{ from?: string; to: string[]; raw: string; user?: string; pass?: string }> = [];
let lastAuth: { user?: string; pass?: string } = {};
const smtp = new SMTPServer({
  secure: false, disabledCommands: ["STARTTLS"], allowInsecureAuth: true, authOptional: true, logger: false,
  onAuth(auth, _s, cb) { lastAuth = { user: auth.username, pass: auth.password }; cb(null, { user: auth.username }); },
  onData(stream, s, cb) {
    let raw = ""; stream.on("data", (d) => (raw += d));
    stream.on("end", () => { mails.push({ from: s.envelope.mailFrom ? s.envelope.mailFrom.address : undefined, to: s.envelope.rcptTo.map((r) => r.address), raw, ...lastAuth }); cb(); });
  },
});

const emailConfig = (over: Record<string, unknown> = {}) => ({ host: "127.0.0.1", port: SMTP_PORT, security: "none", allowInsecure: true, verifyCert: false,
  username: "alerts", from: "vigil@alpha.test", fromName: "Vigil", to: ["soc@alpha.test"], ...over });

async function makeFinding(tenantId: string, severity: string, ip = `198.51.100.${Math.floor(Math.random() * 250) + 1}`, title = `Suspicious activity from ${ip}`) {
  return withTenant(getDb(), { tenantId }, async (tx) => {
    const [rule] = await tx.select({ id: detectionRules.id }).from(detectionRules).limit(1);
    const now = new Date();
    const [f] = await tx.insert(findings).values({ tenantId, ruleId: rule!.id, title, severity: severity as any, confidence: 0.9, groupKey: { sourceIp: ip },
      eventIds: [], eventCount: 1, firstSeen: now, lastSeen: now, dedupKey: randomUUID() }).returning({ id: findings.id });
    const [incidentId] = await correlate(tx, tenantId, [f!.id]);
    return { incidentId: incidentId!, ip };
  });
}

async function runDue() {
  const o = await ownerDb();
  await o.db.execute(sql`update jobs set run_after = now() where status = 'queued' and type like 'notify%'`);
  await o.close();
  await drainOnce(getDb(), 500);
}

async function deliveries() {
  return (await (await ownerA()).get("/notification-deliveries?limit=200")).json.items as any[];
}

async function avoidWindowEdge() {
  const left = 600_000 - (Date.now() % 600_000);
  if (left < 8_000) await new Promise((r) => setTimeout(r, left + 200));
}

beforeAll(async () => {
  await resetDb();
  A = await seedTenant("alpha");
  B = await seedTenant("bravo");
  // promote alpha analyst to admin to cover the admin role
  await withTenant(getDb(), { tenantId: A.tenantId }, (tx) => tx.execute(sql`update memberships set role = 'admin' where user_id = ${A.analyst}`));
  agent = await startAgentStub();
  await new Promise<void>((r) => slackServer.listen(SLACK_PORT, "127.0.0.1", () => r()));
  await new Promise<void>((r) => smtp.listen(SMTP_PORT, "127.0.0.1", () => r()));
});
afterAll(async () => {
  await agent.close();
  await new Promise<void>((r) => slackServer.close(() => r()));
  await new Promise<void>((r) => smtp.close(() => r()));
});
beforeEach(async () => {
  const o = await ownerDb();
  await o.db.execute(sql`delete from notification_channels`);
  await o.db.execute(sql`delete from jobs where type like 'notify%'`);
  await o.close();
  slack.posts.length = 0; slack.fail = 0; slack.failBody = ""; mails.length = 0; lastAuth = {};
  delete process.env.VIGIL_ALERT_CAP;
});

describe("notification settings: access control and secrets", () => {
  it("viewer and analyst get 403 on every endpoint, reads included; admin and owner get 200", async () => {
    const o = await ownerA();
    const ch = (await o.post("/notification-channels", { kind: "slack", name: "s", webhookUrl: HOOK })).json;
    for (const [email, pw] of [["viewer@alpha.test", "pw-viewer-123456"], ["reviewer@alpha.test", "pw-reviewer-123456"]] as const) {
      const c = await as(email, pw);
      expect((await c.get("/notification-channels")).status).toBe(403);
      expect((await c.get("/notification-deliveries")).status).toBe(403);
      expect((await c.post("/notification-channels", { kind: "slack", name: "x", webhookUrl: HOOK })).status).toBe(403);
      expect((await c.patch(`/notification-channels/${ch.id}`, { enabled: false })).status).toBe(403);
      expect((await c.post(`/notification-channels/${ch.id}/test`)).status).toBe(403);
      expect((await c.req("DELETE", `/notification-channels/${ch.id}`)).status).toBe(403);
    }
    const admin = await adminA();
    expect((await admin.get("/notification-channels")).status).toBe(200);
    expect((await admin.post("/notification-channels", { kind: "email", name: "e", config: emailConfig(), password: "smtp-pass" })).status).toBe(200);
    expect((await o.get("/notification-channels")).json.items).toHaveLength(2);
  });

  it("other tenants cannot see or change channels", async () => {
    const ch = (await (await ownerA()).post("/notification-channels", { kind: "slack", name: "s", webhookUrl: HOOK })).json;
    const ob = await as("owner@bravo.test", "pw-owner-123456");
    expect((await ob.get("/notification-channels")).json.items).toHaveLength(0);
    expect((await ob.patch(`/notification-channels/${ch.id}`, { enabled: false })).status).toBe(404);
    expect((await ob.req("DELETE", `/notification-channels/${ch.id}`)).status).toBe(404);
    expect((await ob.post(`/notification-channels/${ch.id}/test`)).status).toBe(404);
  });

  it("never returns or audits secrets; blank keeps, new replaces, delete removes", async () => {
    const o = await ownerA();
    const slackCh = (await o.post("/notification-channels", { kind: "slack", name: "s", webhookUrl: HOOK, config: { label: "#soc" } })).json;
    const mailCh = (await o.post("/notification-channels", { kind: "email", name: "e", config: emailConfig(), password: "smtp-pass-SECRET" })).json;
    expect(slackCh.hasSecret).toBe(true);
    expect(slackCh.secretRef).toBeUndefined();
    const list = JSON.stringify((await o.get("/notification-channels")).json);
    expect(list).not.toContain("SECRETtoken");
    expect(list).not.toContain("smtp-pass-SECRET");
    expect(list).not.toContain("db:");

    // blank keeps
    expect((await o.patch(`/notification-channels/${mailCh.id}`, { password: "", minSeverity: "low" })).json.hasSecret).toBe(true);
    expect((await o.post(`/notification-channels/${mailCh.id}/test`)).json.ok).toBe(true);
    expect(mails.at(-1)!.pass).toBe("smtp-pass-SECRET");
    // new replaces
    await o.patch(`/notification-channels/${mailCh.id}`, { password: "rotated-pass" });
    expect((await o.post(`/notification-channels/${mailCh.id}/test`)).json.ok).toBe(true);
    expect(mails.at(-1)!.pass).toBe("rotated-pass");

    const secretsBefore = await countSecrets(A.tenantId);
    await o.req("DELETE", `/notification-channels/${slackCh.id}`);
    expect(await countSecrets(A.tenantId)).toBe(secretsBefore - 1);

    const audit = JSON.stringify((await o.get("/audit-logs?action=notification&limit=100")).json);
    expect(audit).toContain("notification_channel.created");
    expect(audit).toContain("notification_channel.tested");
    expect(audit).toContain("notification_channel.deleted");
    for (const s of ["SECRETtoken", "smtp-pass-SECRET", "rotated-pass"]) expect(audit).not.toContain(s);
  });
});

async function countSecrets(tenantId: string) {
  const [r] = await withTenant(getDb(), { tenantId }, (tx) => tx.execute(sql`select count(*)::int as n from vigil_secrets`)) as unknown as Array<{ n: number }>;
  return r!.n;
}

describe("notification settings: validation", () => {
  it("rejects Slack URLs outside the allowlist", async () => {
    const o = await ownerA();
    for (const url of ["https://evil.example/services/x", "http://hooks.slack.com/services/x", "https://hooks.slack.com/api/x",
      "https://user:pw@hooks.slack.com/services/x", "http://169.254.169.254/latest/meta-data", "not a url"]) {
      expect((await o.post("/notification-channels", { kind: "slack", name: `s-${Math.random()}`, webhookUrl: url })).status, url).toBe(400);
    }
    expect((await o.post("/notification-channels", { kind: "slack", name: "real", webhookUrl: "https://hooks.slack.com/services/T1/B1/abc" })).status).toBe(200);
  });

  it("rejects metadata SMTP hosts, insecure without opt-in, and header injection", async () => {
    const o = await ownerA();
    const bad = [
      emailConfig({ host: "169.254.169.254" }), emailConfig({ host: "metadata.google.internal" }), emailConfig({ host: "fe80::1" }),
      emailConfig({ allowInsecure: false }), emailConfig({ from: "vigil@alpha.test\r\nBcc: x@evil.test" }), emailConfig({ fromName: "Vigil\r\nBcc: x@evil.test" }),
      emailConfig({ to: ["not-an-address"] }), emailConfig({ to: [] }), emailConfig({ port: 70000 }),
    ];
    for (const config of bad) expect((await o.post("/notification-channels", { kind: "email", name: `e-${Math.random()}`, config })).status, JSON.stringify(config)).toBe(400);
  });

  it("re-checks the resolved SMTP address at send time", async () => {
    const spy = vi.spyOn(dns, "lookup").mockResolvedValue([{ address: "169.254.169.254", family: 4 }] as any);
    try { await expect(resolveSmtpHost("smtp.rebind.example")).rejects.toThrow(/blocked/); }
    finally { spy.mockRestore(); }
  });
});

describe("alert delivery", () => {
  it("enqueues in the incident transaction: a rollback sends nothing", async () => {
    await (await ownerA()).post("/notification-channels", { kind: "slack", name: "s", webhookUrl: HOOK, minSeverity: "low" });
    await expect(withTenant(getDb(), { tenantId: A.tenantId }, async (tx) => {
      const [rule] = await tx.select({ id: detectionRules.id }).from(detectionRules).limit(1);
      const now = new Date();
      const [f] = await tx.insert(findings).values({ tenantId: A.tenantId, ruleId: rule!.id, title: "rolled back", severity: "high", confidence: 1, groupKey: { sourceIp: "192.0.2.77" },
        eventIds: [], eventCount: 1, firstSeen: now, lastSeen: now, dedupKey: randomUUID() }).returning({ id: findings.id });
      await correlate(tx, A.tenantId, [f!.id]);
      const queued = await tx.select().from(jobs).where(sql`type = 'notify'`);
      expect(queued.length).toBe(1);
      throw new Error("boom");
    })).rejects.toThrow("boom");
    const o = await ownerDb();
    const [{ n }] = await o.db.execute(sql`select count(*)::int as n from jobs where type = 'notify'`) as unknown as Array<{ n: number }>;
    await o.close();
    expect(n).toBe(0);
    await runDue();
    expect(slack.posts).toHaveLength(0);
  });

  it("sends a new incident to Slack and email once, respecting min severity", async () => {
    const o = await ownerA();
    await o.post("/notification-channels", { kind: "slack", name: "s", webhookUrl: HOOK, minSeverity: "high" });
    await o.post("/notification-channels", { kind: "email", name: "e", config: emailConfig(), password: "pw", minSeverity: "medium" });
    await makeFinding(A.tenantId, "medium");
    await runDue();
    expect(slack.posts).toHaveLength(0);
    expect(mails).toHaveLength(1);

    const { incidentId, ip } = await makeFinding(A.tenantId, "critical");
    await runDue();
    await runDue(); // re-running must not resend
    expect(slack.posts).toHaveLength(1);
    expect(slack.posts[0]!.path).toBe("/services/T000/B000/SECRETtoken123456");
    expect(JSON.stringify(slack.posts[0]!.body)).toContain(ip);
    expect(JSON.stringify(slack.posts[0]!.body)).toContain(`/incidents/${incidentId}`);
    expect(mails).toHaveLength(2);
    expect(mails[1]!.to).toEqual(["soc@alpha.test"]);
    expect(mails[1]!.raw).toMatch(/Subject: \[Vigil\] CRITICAL #\d+/);

    // a second finding for the same entity attaches to the open incident: no new "created" alert
    await makeFinding(A.tenantId, "critical", ip);
    await runDue();
    expect(slack.posts).toHaveLength(1);
    const d = await deliveries();
    expect(d.filter((x) => x.status === "sent")).toHaveLength(3);
  });

  it("alerts once per severity step when an incident escalates (correlator and manual)", async () => {
    const o = await ownerA();
    await o.post("/notification-channels", { kind: "slack", name: "s", webhookUrl: HOOK, minSeverity: "low", events: ["incident.severity_raised"] });
    const { incidentId, ip } = await makeFinding(A.tenantId, "low");
    await runDue();
    expect(slack.posts).toHaveLength(0); // created event not subscribed
    await makeFinding(A.tenantId, "high", ip);
    await makeFinding(A.tenantId, "high", ip);
    await runDue();
    expect(slack.posts).toHaveLength(1);
    expect(slack.posts[0]!.body.text).toContain("severity raised");
    expect((await o.patch(`/incidents/${incidentId}`, { severity: "critical" })).status).toBe(200);
    expect((await o.patch(`/incidents/${incidentId}`, { severity: "medium" })).status).toBe(200); // lowering: no alert
    await runDue();
    expect(slack.posts).toHaveLength(2);
    expect(slack.posts[1]!.body.text).toContain("CRITICAL");
  });

  it("a failing channel is recorded and retried without resending to channels that succeeded", async () => {
    const o = await ownerA();
    await o.post("/notification-channels", { kind: "slack", name: "s", webhookUrl: HOOK, minSeverity: "low" });
    await o.post("/notification-channels", { kind: "email", name: "e", config: emailConfig(), password: "pw", minSeverity: "low" });
    slack.fail = 1; slack.failBody = "no_service /services/T000/B000/SECRETtoken123456";
    await makeFinding(A.tenantId, "high");
    await runDue();
    expect(mails).toHaveLength(1);
    let d = await deliveries();
    const failed = d.find((x) => x.channelName === "s")!;
    expect(failed.status).toBe("failed");
    expect(failed.lastError).toMatch(/HTTP 400/);
    expect(failed.lastError).not.toContain("SECRETtoken");
    await runDue();
    expect(slack.posts).toHaveLength(1);
    expect(mails).toHaveLength(1);
    d = await deliveries();
    expect(d.every((x) => x.status === "sent")).toBe(true);
    expect(d.find((x) => x.channelName === "s")!.attempts).toBe(2);
  });

  it("flood control suppresses past the cap and sends one summary", async () => {
    await avoidWindowEdge();
    process.env.VIGIL_ALERT_CAP = "3";
    await (await ownerA()).post("/notification-channels", { kind: "slack", name: "s", webhookUrl: HOOK, minSeverity: "low" });
    for (let i = 0; i < 5; i++) await makeFinding(A.tenantId, "high");
    await runDue();
    expect(slack.posts).toHaveLength(3);
    const d = await deliveries();
    expect(d.filter((x) => x.status === "suppressed")).toHaveLength(2);
    await runDue(); // summary job is scheduled for the end of the window; forced due here
    expect(slack.posts).toHaveLength(4);
    expect(slack.posts[3]!.body.text).toMatch(/^2 more incident alerts/);
    await runDue();
    expect(slack.posts).toHaveLength(4);
  });

  it("disabled channels receive nothing", async () => {
    const o = await ownerA();
    const ch = (await o.post("/notification-channels", { kind: "slack", name: "s", webhookUrl: HOOK, minSeverity: "low" })).json;
    await o.patch(`/notification-channels/${ch.id}`, { enabled: false });
    await makeFinding(A.tenantId, "critical");
    await runDue();
    expect(slack.posts).toHaveLength(0);
  });
});

describe("alert content", () => {
  const base = { id: "11111111-1111-1111-1111-111111111111", caseNumber: 7, severity: "high" as const, status: "new",
    primaryEntity: { field: "sourceIp", value: "203.0.113.9" }, firstSeen: new Date(0), lastSeen: new Date(0), rules: ["R<1>"] };

  it("escapes Slack mrkdwn and HTML, and strips CR/LF from the subject", () => {
    const m = buildIncidentMessage({ ...base, title: "<!channel> <script>alert(1)</script> & \r\nBcc: x@evil.test" }, "incident.created");
    const s = JSON.stringify(m.slack);
    expect(s).not.toContain("<!channel>");
    expect(s).toContain("&lt;!channel&gt;");
    expect(s).not.toContain("<script>");
    expect(m.html).not.toContain("<script>");
    expect(m.html).toContain("&lt;script&gt;");
    expect(m.html).toContain("R&lt;1&gt;");
    expect(m.subject).not.toMatch(/[\r\n]/);
  });

  it("redactEntities hides the entity value everywhere", () => {
    const m = buildIncidentMessage({ ...base, title: "Brute force from 203.0.113.9" }, "incident.created", { redact: true });
    for (const part of [m.subject, m.text, m.html, JSON.stringify(m.slack)]) expect(part).not.toContain("203.0.113.9");
    expect(m.text).toContain("sourceIp: [redacted]");
  });

  it("a header-injection title does not add headers to the sent email", async () => {
    const o = await ownerA();
    await o.post("/notification-channels", { kind: "email", name: "e", config: emailConfig(), minSeverity: "low" });
    await makeFinding(A.tenantId, "high", "192.0.2.200", "Bad\r\nBcc: attacker@evil.test\r\nX-Evil: 1");
    await runDue();
    expect(mails).toHaveLength(1);
    expect(mails[0]!.to).toEqual(["soc@alpha.test"]);
    const headers = mails[0]!.raw.split("\r\n\r\n")[0]!;
    expect(headers).toMatch(/^Subject: /im);
    expect(headers).not.toMatch(/^Bcc:/im);
    expect(headers).not.toMatch(/^X-Evil:/im);
    expect(mails[0]!.raw).not.toMatch(/^Bcc:/im);
  });
});

void (() => B);
