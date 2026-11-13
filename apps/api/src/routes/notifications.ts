import { z } from "zod";
import { and, desc, eq } from "drizzle-orm";
import { incidents, notificationChannels, notificationDeliveries } from "@vigil/db";
import { IdParam, newApp, route, tenantTx } from "../lib/context.js";
import { ApiError, badRequest, conflict, notFound } from "../lib/errors.js";
import { takeToken } from "../lib/ratelimit.js";
import { sanitizeError } from "../lib/sanitize.js";
import { secretStore } from "../lib/secrets.js";
import { ALERT_EVENTS, assertEmailConfig, assertSlackWebhook, sendTestMessage, type EmailConfig } from "../services/notifications.js";

export const notificationRoutes = newApp();

type Row = typeof notificationChannels.$inferSelect;
/** Never expose secret_ref or the secret itself. */
const publicChannel = (r: Row) => ({ ...r, secretRef: undefined, hasSecret: !!r.secretRef });

const Severity = z.enum(["info", "low", "medium", "high", "critical"]);
const Events = z.array(z.enum(ALERT_EVENTS)).min(1).max(ALERT_EVENTS.length);
const Common = { name: z.string().trim().min(1).max(80), enabled: z.boolean().default(true), minSeverity: Severity.default("high"), events: Events.default(["incident.created", "incident.severity_raised"]) };
const SlackConfig = z.object({ label: z.string().trim().max(80).optional(), redactEntities: z.boolean().default(false) });
const EmailConfigSchema = z.object({
  host: z.string().trim().min(1).max(253), port: z.number().int().min(1).max(65535), security: z.enum(["starttls", "tls", "none"]).default("starttls"),
  allowInsecure: z.boolean().optional(), verifyCert: z.boolean().default(true), username: z.string().max(254).nullish(),
  from: z.string().max(254), fromName: z.string().max(80).nullish(), to: z.array(z.string().max(254)).min(1).max(20), redactEntities: z.boolean().default(false),
});
const CreateBody = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("slack"), ...Common, config: SlackConfig.default({ redactEntities: false }), webhookUrl: z.string().min(1).max(500) }),
  z.object({ kind: z.literal("email"), ...Common, config: EmailConfigSchema, password: z.string().max(500).nullish() }),
]);
const PatchBody = z.object({
  name: Common.name.optional(), enabled: z.boolean().optional(), minSeverity: Severity.optional(), events: Events.optional(),
  config: z.record(z.string(), z.unknown()).optional(),
  /** Slack: new webhook URL. Absent/empty keeps the stored one. */
  webhookUrl: z.string().max(500).nullish(),
  /** Email: new SMTP password. Absent/empty keeps it; clearPassword removes it. */
  password: z.string().max(500).nullish(), clearPassword: z.boolean().optional(),
});

function validateConfig(kind: string, config: unknown) {
  if (kind === "slack") {
    const parsed = SlackConfig.safeParse(config ?? {});
    if (!parsed.success) throw badRequest("invalid Slack configuration", z.treeifyError(parsed.error));
    return parsed.data;
  }
  const parsed = EmailConfigSchema.safeParse(config);
  if (!parsed.success) throw badRequest("invalid email configuration", z.treeifyError(parsed.error));
  return assertEmailConfig(parsed.data as EmailConfig);
}

const auditView = (r: Pick<Row, "kind" | "name" | "enabled" | "minSeverity" | "events" | "config">) => {
  const c = r.config as Record<string, unknown>;
  return { kind: r.kind, name: r.name, enabled: r.enabled, minSeverity: r.minSeverity, events: r.events,
    target: r.kind === "slack" ? (c.label ?? null) : { host: c.host, port: c.port, security: c.security, recipients: (c.to as string[] | undefined)?.length ?? 0 } };
};

route(notificationRoutes, "get", "/notification-channels", { summary: "Incident alert channels (owner/admin)", tags: ["notifications"] }, async (c) =>
  tenantTx(c, "notifications:write", async (tx) => {
    const rows = await tx.select().from(notificationChannels).orderBy(notificationChannels.createdAt);
    const last = await tx.selectDistinctOn([notificationDeliveries.channelId], { channelId: notificationDeliveries.channelId, status: notificationDeliveries.status, at: notificationDeliveries.updatedAt, error: notificationDeliveries.lastError })
      .from(notificationDeliveries).orderBy(notificationDeliveries.channelId, desc(notificationDeliveries.updatedAt));
    const byId = new Map(last.map((l) => [l.channelId, l]));
    return c.json({ items: rows.map((r) => ({ ...publicChannel(r), lastDelivery: byId.get(r.id) ?? null })), events: ALERT_EVENTS });
  }));

route(notificationRoutes, "post", "/notification-channels", { summary: "Add an incident alert channel", tags: ["notifications"], body: CreateBody }, async (c, { body }) =>
  tenantTx(c, "notifications:write", async (tx, a) => {
    const config = validateConfig(body.kind, body.config);
    const secret = body.kind === "slack" ? assertSlackWebhook(body.webhookUrl) : (body.password || null);
    const [dup] = await tx.select({ id: notificationChannels.id }).from(notificationChannels).where(eq(notificationChannels.name, body.name));
    if (dup) throw conflict(`a channel named "${body.name}" already exists`);
    const secretRef = secret ? await secretStore.put(a.tenantId, secret) : null;
    const [row] = await tx.insert(notificationChannels).values({ tenantId: a.tenantId, kind: body.kind, name: body.name, enabled: body.enabled, minSeverity: body.minSeverity,
      events: [...new Set(body.events)], config, secretRef, createdBy: a.user.id }).returning();
    await a.audit({ action: "notification_channel.created", targetType: "notification_channel", targetId: row!.id, details: auditView(row!) });
    return c.json(publicChannel(row!));
  }));

route(notificationRoutes, "patch", "/notification-channels/{id}", { summary: "Update an incident alert channel", tags: ["notifications"], params: IdParam, body: PatchBody }, async (c, { params, body }) =>
  tenantTx(c, "notifications:write", async (tx, a) => {
    const [cur] = await tx.select().from(notificationChannels).where(eq(notificationChannels.id, params.id));
    if (!cur) throw notFound("notification channel");
    if (body.name && body.name !== cur.name) {
      const [dup] = await tx.select({ id: notificationChannels.id }).from(notificationChannels).where(eq(notificationChannels.name, body.name));
      if (dup) throw conflict(`a channel named "${body.name}" already exists`);
    }
    const config = body.config ? validateConfig(cur.kind, { ...(cur.config as object), ...body.config }) : cur.config;
    let secretRef = cur.secretRef, secretChanged = false;
    const newSecret = cur.kind === "slack" ? (body.webhookUrl ? assertSlackWebhook(body.webhookUrl) : null) : (body.password || null);
    if (newSecret) { secretRef = await secretStore.put(a.tenantId, newSecret); secretChanged = true; }
    else if (cur.kind === "email" && body.clearPassword) { secretRef = null; secretChanged = !!cur.secretRef; }
    const [row] = await tx.update(notificationChannels).set({
      ...(body.name ? { name: body.name } : {}), ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
      ...(body.minSeverity ? { minSeverity: body.minSeverity } : {}), ...(body.events ? { events: [...new Set(body.events)] } : {}),
      config, secretRef, updatedAt: new Date(),
    }).where(eq(notificationChannels.id, cur.id)).returning();
    if (secretChanged && cur.secretRef) await secretStore.delete(a.tenantId, cur.secretRef);
    await a.audit({ action: "notification_channel.updated", targetType: "notification_channel", targetId: cur.id, details: { from: auditView(cur), to: auditView(row!), secretChanged } });
    return c.json(publicChannel(row!));
  }));

route(notificationRoutes, "delete", "/notification-channels/{id}", { summary: "Delete an incident alert channel", tags: ["notifications"], params: IdParam }, async (c, { params }) =>
  tenantTx(c, "notifications:write", async (tx, a) => {
    const [cur] = await tx.select().from(notificationChannels).where(eq(notificationChannels.id, params.id));
    if (!cur) throw notFound("notification channel");
    await tx.delete(notificationChannels).where(eq(notificationChannels.id, cur.id));
    if (cur.secretRef) await secretStore.delete(a.tenantId, cur.secretRef);
    await a.audit({ action: "notification_channel.deleted", targetType: "notification_channel", targetId: cur.id, details: auditView(cur) });
    return c.json({ ok: true });
  }));

route(notificationRoutes, "post", "/notification-channels/{id}/test", { summary: "Send a test alert to a channel", tags: ["notifications"], params: IdParam }, async (c, { params }) =>
  tenantTx(c, "notifications:write", async (tx, a) => {
    if (!takeToken(`notify-test:${a.tenantId}`, 5, 5 / 60)) throw new ApiError(429, "rate_limited", "too many test messages; wait a minute");
    const [cur] = await tx.select().from(notificationChannels).where(eq(notificationChannels.id, params.id));
    if (!cur) throw notFound("notification channel");
    let ok = true, detail = "test message sent";
    try { await sendTestMessage(a.tenantId, cur); } catch (e) { ok = false; detail = sanitizeError((e as Error).message, 400) ?? "delivery failed"; }
    await a.audit({ action: "notification_channel.tested", targetType: "notification_channel", targetId: cur.id, details: { ok, detail } });
    return c.json({ ok, detail });
  }));

route(notificationRoutes, "get", "/notification-deliveries", {
  summary: "Recent alert deliveries", tags: ["notifications"],
  query: z.object({ channelId: z.string().uuid().optional(), limit: z.coerce.number().int().min(1).max(200).default(50) }),
}, async (c, { query }) =>
  tenantTx(c, "notifications:write", async (tx) => {
    const rows = await tx.select({ d: notificationDeliveries, channelName: notificationChannels.name, caseNumber: incidents.caseNumber, incidentTitle: incidents.title })
      .from(notificationDeliveries).innerJoin(notificationChannels, eq(notificationChannels.id, notificationDeliveries.channelId))
      .innerJoin(incidents, eq(incidents.id, notificationDeliveries.incidentId))
      .where(query.channelId ? and(eq(notificationDeliveries.channelId, query.channelId)) : undefined)
      .orderBy(desc(notificationDeliveries.createdAt)).limit(query.limit);
    return c.json({ items: rows.map((r) => ({ ...r.d, channelName: r.channelName, caseNumber: r.caseNumber, incidentTitle: r.incidentTitle })) });
  }));
