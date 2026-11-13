/**
 * Incident alerting (Slack incoming webhooks, SMTP email).
 *
 * Flow: the correlator / incident PATCH enqueues a `notify` job in the same transaction that changed the incident
 * (outbox — a rollback sends nothing). `notify` fans out one `notify_channel` job per matching channel, each backed
 * by a `notification_deliveries` row (unique per channel/incident/event/step → never sent twice). Channels fail and
 * retry independently. Past alertCap() sends per channel per ALERT_WINDOW, deliveries are `suppressed` and one
 * `notify_summary` job reports the count when the window closes.
 *
 * Only incident metadata leaves Vigil: case number, title, severity, status, primary entity (optionally redacted),
 * first/last seen, rule names and a link. Never raw evidence, payloads, credentials or AI output.
 */
import dns from "node:dns/promises";
import net from "node:net";
import nodemailer from "nodemailer";
import { and, eq, gte, inArray, sql } from "drizzle-orm";
import { SEVERITY_ORDER, type Severity } from "@vigil/core";
import { detectionRules, findings, incidents, notificationChannels, notificationDeliveries, withTenant, type Db, type Tx } from "@vigil/db";
import { env } from "../env.js";
import { badRequest } from "../lib/errors.js";
import { pgQueue } from "../lib/queue.js";
import { sanitizeError } from "../lib/sanitize.js";
import { secretStore } from "../lib/secrets.js";
import { BLOCKED_HOSTS, isBlockedIp } from "./models.js";

export const ALERT_EVENTS = ["incident.created", "incident.severity_raised"] as const;
export type AlertEvent = (typeof ALERT_EVENTS)[number];
/** Max individual alerts per channel per window (VIGIL_ALERT_CAP, default 20). */
export const alertCap = () => { const n = Number(process.env.VIGIL_ALERT_CAP); return Number.isInteger(n) && n > 0 ? n : 20; };
export const ALERT_WINDOW_MS = 10 * 60_000;
const TIMEOUT_MS = 10_000;

export interface SlackConfig { label?: string; redactEntities?: boolean }
export interface EmailConfig {
  host: string; port: number; security: "starttls" | "tls" | "none"; allowInsecure?: boolean; verifyCert: boolean;
  username?: string | null; from: string; fromName?: string | null; to: string[]; redactEntities?: boolean;
}
type Channel = typeof notificationChannels.$inferSelect;

// ---------- validation ----------
const DEFAULT_SLACK_ORIGIN = "https://hooks.slack.com";
function slackOrigins(): string[] {
  const extra = (process.env.VIGIL_SLACK_WEBHOOK_HOSTS ?? "").split(",").map((s) => s.trim().replace(/\/$/, "")).filter(Boolean);
  return [DEFAULT_SLACK_ORIGIN, ...extra];
}

/** Slack webhooks only go to hooks.slack.com (or origins the operator allowlisted), which rules out SSRF. */
export function assertSlackWebhook(raw: string): string {
  let u: URL;
  try { u = new URL(raw.trim()); } catch { throw badRequest("webhook URL is not a valid URL"); }
  if (u.username || u.password) throw badRequest("webhook URL must not contain credentials");
  if (!slackOrigins().includes(u.origin)) throw badRequest("webhook URL must start with https://hooks.slack.com/services/");
  if (u.origin === DEFAULT_SLACK_ORIGIN && !u.pathname.startsWith("/services/")) throw badRequest("webhook URL must start with https://hooks.slack.com/services/");
  u.hash = "";
  return u.toString();
}

export const stripCrlf = (s: string) => s.replace(/[\r\n\u2028\u2029]+/g, " ").trim();
export const EMAIL_ADDR_RE = /^[^@\s<>"',;:\\]+@[^@\s<>"',;:\\]+\.[^@\s<>"',;:\\]+$/;

export function assertSmtpHost(host: string): string {
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (!h || /[\s/:@]/.test(h) && !net.isIPv6(h)) throw badRequest("SMTP host must be a hostname or IP address");
  if (BLOCKED_HOSTS.has(h)) throw badRequest("cloud metadata endpoints are not allowed");
  if (net.isIP(h) && isBlockedIp(h)) throw badRequest("link-local / metadata addresses are not allowed");
  return h;
}

export function assertEmailConfig(c: EmailConfig): EmailConfig {
  const host = assertSmtpHost(c.host);
  if (!Number.isInteger(c.port) || c.port < 1 || c.port > 65535) throw badRequest("SMTP port must be 1–65535");
  if (c.security === "none" && !c.allowInsecure) throw badRequest("unencrypted SMTP needs allowInsecure: true");
  const from = c.from.trim().toLowerCase();
  if (/[\r\n]/.test(c.from) || !EMAIL_ADDR_RE.test(from)) throw badRequest("invalid from address");
  if (c.fromName && /[\r\n]/.test(c.fromName)) throw badRequest("from name must be a single line");
  if (c.username && /[\r\n]/.test(c.username)) throw badRequest("username must be a single line");
  const to = [...new Set(c.to.map((t) => t.trim().toLowerCase()))];
  if (!to.length || to.length > 20) throw badRequest("1–20 recipients required");
  for (const t of to) if (!EMAIL_ADDR_RE.test(t)) throw badRequest(`invalid recipient: ${t.slice(0, 80)}`);
  return { host, port: c.port, security: c.security, allowInsecure: c.security === "none", verifyCert: c.verifyCert !== false,
    username: c.username?.trim() || null, from, fromName: c.fromName ? stripCrlf(c.fromName).slice(0, 80) : null, to, redactEntities: !!c.redactEntities };
}

/** Resolve at send time and refuse metadata / link-local answers (defeats DNS rebinding after save-time checks). */
export async function resolveSmtpHost(host: string): Promise<string> {
  const h = assertSmtpHost(host);
  if (net.isIP(h)) return h;
  const addrs = await dns.lookup(h, { all: true, verbatim: true });
  if (!addrs.length) throw new Error("SMTP host did not resolve");
  if (addrs.some((a) => isBlockedIp(a.address))) throw new Error("SMTP host resolves to a blocked address");
  return addrs[0]!.address;
}

// ---------- message ----------
export interface IncidentSummary {
  id: string; caseNumber: number; title: string; severity: Severity; status: string;
  primaryEntity: { field?: string; value?: string } | null; firstSeen: Date; lastSeen: Date; rules: string[];
}
export interface Message { subject: string; text: string; html: string; slack: Record<string, unknown> }

const slackEsc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const htmlEsc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const incidentUrl = (id: string) => `${env.webOrigin.replace(/\/$/, "")}/incidents/${encodeURIComponent(id)}`;

export function buildIncidentMessage(i: IncidentSummary, event: AlertEvent, opts: { redact?: boolean; test?: boolean } = {}): Message {
  const ent = i.primaryEntity?.field && i.primaryEntity.value ? { field: i.primaryEntity.field, value: i.primaryEntity.value } : null;
  let title = stripCrlf(i.title).slice(0, 300);
  if (opts.redact && ent) title = title.split(ent.value).join("[redacted]");
  const entity = ent ? `${ent.field}: ${opts.redact ? "[redacted]" : ent.value}` : "—";
  const head = event === "incident.created" ? "New incident" : "Incident severity raised";
  const prefix = opts.test ? "[TEST] " : "";
  const sev = i.severity.toUpperCase();
  const url = incidentUrl(i.id);
  const rows: Array<[string, string]> = [
    ["Severity", sev], ["Status", i.status], ["Entity", entity],
    ["First seen", i.firstSeen.toISOString()], ["Last seen", i.lastSeen.toISOString()],
    ["Rules", i.rules.length ? i.rules.slice(0, 5).join(", ") : "—"],
  ];
  const subject = stripCrlf(`${prefix}[Vigil] ${sev} #${i.caseNumber}: ${title}`).slice(0, 200);
  const text = [`${prefix}${head}: #${i.caseNumber} ${title}`, ...rows.map(([k, v]) => `${k}: ${v}`), "", `Open in Vigil: ${url}`,
    ...(opts.test ? ["", "This is a test message sent from Vigil notification settings."] : [])].join("\n");
  const html = `<p><b>${htmlEsc(`${prefix}${head}`)}:</b> #${i.caseNumber} ${htmlEsc(title)}</p><table cellpadding="4">${
    rows.map(([k, v]) => `<tr><td><b>${htmlEsc(k)}</b></td><td>${htmlEsc(v)}</td></tr>`).join("")}</table><p><a href="${htmlEsc(url)}">Open in Vigil</a></p>${
    opts.test ? "<p><i>This is a test message sent from Vigil notification settings.</i></p>" : ""}`;
  const slack = {
    text: slackEsc(`${prefix}${head} ${sev} #${i.caseNumber}: ${title}`),
    blocks: [
      { type: "section", text: { type: "mrkdwn", text: `*${slackEsc(`${prefix}${head}`)}* — *${sev}* #${i.caseNumber}\n${slackEsc(title)}` } },
      { type: "section", fields: rows.slice(1).map(([k, v]) => ({ type: "mrkdwn", text: `*${slackEsc(k)}*\n${slackEsc(v)}` })) },
      { type: "section", text: { type: "mrkdwn", text: `<${url}|Open in Vigil>` } },
    ],
  };
  return { subject, text, html, slack };
}

function summaryMessage(count: number): Message {
  const url = `${env.webOrigin.replace(/\/$/, "")}/incidents`;
  const line = `${count} more incident alert${count === 1 ? "" : "s"} were not sent individually (limit ${alertCap()} per ${ALERT_WINDOW_MS / 60_000} minutes).`;
  return {
    subject: `[Vigil] ${count} incident alert${count === 1 ? "" : "s"} suppressed`,
    text: `${line}\nOpen Vigil: ${url}`,
    html: `<p>${htmlEsc(line)}</p><p><a href="${htmlEsc(url)}">Open Vigil</a></p>`,
    slack: { text: slackEsc(line), blocks: [{ type: "section", text: { type: "mrkdwn", text: `${slackEsc(line)}\n<${url}|Open Vigil>` } }] },
  };
}

// ---------- senders ----------
async function sendSlack(webhook: string, m: Message) {
  const url = assertSlackWebhook(webhook);
  let res: Response;
  try {
    res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(m.slack), redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch (e) {
    throw new Error(`Slack request failed: ${(e as Error).name === "TimeoutError" ? "timeout" : (e as Error).message}`);
  }
  if (res.status >= 300) throw new Error(`Slack returned HTTP ${res.status}${res.status < 500 ? `: ${(await res.text().catch(() => "")).slice(0, 100)}` : ""}`);
}

async function sendEmail(cfg: EmailConfig, password: string | null, m: Message) {
  const c = assertEmailConfig(cfg);
  const ip = await resolveSmtpHost(c.host);
  const transport = nodemailer.createTransport({
    host: ip, port: c.port,
    secure: c.security === "tls", requireTLS: c.security === "starttls", ignoreTLS: c.security === "none",
    auth: c.username && password ? { user: c.username, pass: password } : undefined,
    tls: { rejectUnauthorized: c.verifyCert, ...(net.isIP(c.host) ? {} : { servername: c.host }) },
    connectionTimeout: TIMEOUT_MS, greetingTimeout: TIMEOUT_MS, socketTimeout: TIMEOUT_MS,
    name: "vigil",
  });
  try {
    await transport.sendMail({
      from: c.fromName ? { name: c.fromName, address: c.from } : c.from, to: c.to,
      subject: stripCrlf(m.subject), text: m.text, html: m.html,
      headers: { "Auto-Submitted": "auto-generated", "X-Auto-Response-Suppress": "All" },
    });
  } finally { transport.close(); }
}

/** Send one message to a channel. Errors are scrubbed of the channel secret and sanitized before surfacing. */
export async function sendToChannel(tenantId: string, ch: Pick<Channel, "kind" | "config" | "secretRef">, m: Message): Promise<void> {
  const secret = ch.secretRef ? await secretStore.get(tenantId, ch.secretRef) : null;
  try {
    if (ch.kind === "slack") {
      if (!secret) throw new Error("no webhook URL stored");
      await sendSlack(secret, m);
    } else if (ch.kind === "email") await sendEmail(ch.config as EmailConfig, secret, m);
    else throw new Error(`unknown channel kind ${ch.kind}`);
  } catch (e) {
    let msg = (e as Error).message ?? String(e);
    if (secret) {
      msg = msg.split(secret).join("[redacted]");
      if (ch.kind === "slack") { try { const path = new URL(secret).pathname; if (path.length > 1) msg = msg.split(path).join("[redacted]"); } catch { /* not a URL */ } }
    }
    throw new Error(sanitizeError(msg, 400) ?? "delivery failed");
  }
}

// ---------- pipeline ----------
export function alertDedupeKey(event: AlertEvent, severity: Severity) { return event === "incident.severity_raised" ? severity : ""; }

/** Call inside the transaction that created / escalated the incident. */
export async function enqueueIncidentAlert(tx: Tx, tenantId: string, incidentId: string, event: AlertEvent, severity: Severity) {
  const key = alertDedupeKey(event, severity);
  await pgQueue.enqueue(tx, tenantId, "notify", { incidentId, event, severity }, { idempotencyKey: `notify:${incidentId}:${event}${key ? `:${key}` : ""}` });
}

export async function loadIncidentSummary(tx: Tx, incidentId: string): Promise<IncidentSummary | null> {
  const [i] = await tx.select().from(incidents).where(eq(incidents.id, incidentId));
  if (!i) return null;
  const rules = await tx.selectDistinct({ name: detectionRules.name }).from(findings).innerJoin(detectionRules, eq(detectionRules.id, findings.ruleId))
    .where(eq(findings.incidentId, incidentId)).limit(5);
  return { id: i.id, caseNumber: i.caseNumber, title: i.title, severity: i.severity as Severity, status: i.status,
    primaryEntity: i.primaryEntity as IncidentSummary["primaryEntity"], firstSeen: i.firstSeen, lastSeen: i.lastSeen, rules: rules.map((r) => r.name) };
}

/** `notify` job: fan out to every enabled channel subscribed to this event at or above its minimum severity. */
export async function handleNotify(db: Db, tenantId: string, p: { incidentId: string; event: AlertEvent; severity: Severity }) {
  await withTenant(db, { tenantId }, async (tx) => {
    const chans = await tx.select().from(notificationChannels).where(and(eq(notificationChannels.enabled, true), sql`${p.event} = any(${notificationChannels.events})`));
    const key = alertDedupeKey(p.event, p.severity);
    for (const ch of chans) {
      if (SEVERITY_ORDER[ch.minSeverity as Severity] > SEVERITY_ORDER[p.severity]) continue;
      const [d] = await tx.insert(notificationDeliveries).values({ tenantId, channelId: ch.id, incidentId: p.incidentId, event: p.event, dedupeKey: key })
        .onConflictDoNothing().returning({ id: notificationDeliveries.id });
      if (d) await pgQueue.enqueue(tx, tenantId, "notify_channel", { deliveryId: d.id }, { idempotencyKey: `notify-delivery:${d.id}`, maxAttempts: 5 });
    }
  });
}

const windowStart = (now = Date.now()) => new Date(Math.floor(now / ALERT_WINDOW_MS) * ALERT_WINDOW_MS);

/** `notify_channel` job: send one delivery. Throws on failure so the queue retries this channel only. */
export async function handleNotifyChannel(db: Db, tenantId: string, p: { deliveryId: string }) {
  const claim = await withTenant(db, { tenantId }, async (tx) => {
    const [row] = await tx.select({ d: notificationDeliveries, ch: notificationChannels }).from(notificationDeliveries)
      .innerJoin(notificationChannels, eq(notificationChannels.id, notificationDeliveries.channelId)).where(eq(notificationDeliveries.id, p.deliveryId));
    if (!row || row.d.status === "sent" || row.d.status === "suppressed") return null;
    if (!row.ch.enabled) {
      await tx.update(notificationDeliveries).set({ status: "suppressed", lastError: "channel disabled", updatedAt: new Date() }).where(eq(notificationDeliveries.id, row.d.id));
      return null;
    }
    // Serialize the cap check per channel; a reservation (sent_at set while pending) counts toward the cap.
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`notify:${row.ch.id}`}))`);
    const ws = windowStart();
    const [{ n }] = await tx.select({ n: sql<number>`count(*)::int` }).from(notificationDeliveries).where(and(
      eq(notificationDeliveries.channelId, row.ch.id), inArray(notificationDeliveries.status, ["sent", "pending", "failed"]),
      gte(notificationDeliveries.sentAt, ws), sql`${notificationDeliveries.id} <> ${row.d.id}`));
    if (n >= alertCap() && !row.d.sentAt) {
      await tx.update(notificationDeliveries).set({ status: "suppressed", lastError: "alert limit reached", updatedAt: new Date() }).where(eq(notificationDeliveries.id, row.d.id));
      await pgQueue.enqueue(tx, tenantId, "notify_summary", { channelId: row.ch.id }, {
        idempotencyKey: `notify-summary:${row.ch.id}:${ws.getTime()}`, runAfter: new Date(ws.getTime() + ALERT_WINDOW_MS), maxAttempts: 5 });
      return null;
    }
    await tx.update(notificationDeliveries).set({ sentAt: row.d.sentAt ?? new Date(), attempts: row.d.attempts + 1, updatedAt: new Date() }).where(eq(notificationDeliveries.id, row.d.id));
    const inc = await loadIncidentSummary(tx, row.d.incidentId);
    // An escalation alert reports the severity it escalated to, even if someone lowered it again before sending.
    if (inc && row.d.event === "incident.severity_raised" && row.d.dedupeKey in SEVERITY_ORDER) inc.severity = row.d.dedupeKey as Severity;
    return inc ? { ch: row.ch, inc, event: row.d.event as AlertEvent } : null;
  });
  if (!claim) return;
  const cfg = claim.ch.config as { redactEntities?: boolean };
  try {
    await sendToChannel(tenantId, claim.ch, buildIncidentMessage(claim.inc, claim.event, { redact: !!cfg.redactEntities }));
  } catch (e) {
    await withTenant(db, { tenantId }, (tx) => tx.update(notificationDeliveries).set({ status: "failed", lastError: (e as Error).message, updatedAt: new Date() }).where(eq(notificationDeliveries.id, p.deliveryId)));
    throw e;
  }
  await withTenant(db, { tenantId }, (tx) => tx.update(notificationDeliveries).set({ status: "sent", lastError: null, sentAt: new Date(), updatedAt: new Date() }).where(eq(notificationDeliveries.id, p.deliveryId)));
}

/** `notify_summary` job: one message per channel/window for everything suppressed by the cap. */
export async function handleNotifySummary(db: Db, tenantId: string, p: { channelId: string }) {
  const pending = await withTenant(db, { tenantId }, async (tx) => {
    const [ch] = await tx.select().from(notificationChannels).where(eq(notificationChannels.id, p.channelId));
    if (!ch || !ch.enabled) return null;
    const rows = await tx.select({ id: notificationDeliveries.id }).from(notificationDeliveries).where(and(
      eq(notificationDeliveries.channelId, p.channelId), eq(notificationDeliveries.status, "suppressed"), eq(notificationDeliveries.summarized, false),
      sql`${notificationDeliveries.lastError} = 'alert limit reached'`));
    return rows.length ? { ch, ids: rows.map((r) => r.id) } : null;
  });
  if (!pending) return;
  await sendToChannel(tenantId, pending.ch, summaryMessage(pending.ids.length));
  await withTenant(db, { tenantId }, (tx) => tx.update(notificationDeliveries).set({ summarized: true, updatedAt: new Date() }).where(inArray(notificationDeliveries.id, pending.ids)));
}

/** Synchronous test message for the settings page. */
export async function sendTestMessage(tenantId: string, ch: Channel): Promise<void> {
  const now = new Date();
  const sample: IncidentSummary = { id: "00000000-0000-0000-0000-000000000000", caseNumber: 0, title: "Test alert from Vigil", severity: ch.minSeverity as Severity,
    status: "new", primaryEntity: { field: "sourceIp", value: "203.0.113.10" }, firstSeen: now, lastSeen: now, rules: ["Example rule"] };
  await sendToChannel(tenantId, ch, buildIncidentMessage(sample, "incident.created", { test: true, redact: !!(ch.config as { redactEntities?: boolean }).redactEntities }));
}
