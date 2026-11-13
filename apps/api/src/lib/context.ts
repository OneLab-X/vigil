import { OpenAPIHono, createRoute, type RouteConfig } from "@hono/zod-openapi";
import type { Context, MiddlewareHandler } from "hono";
import { getCookie } from "hono/cookie";
import { and, eq, gt, sql } from "drizzle-orm";
import { z } from "zod";
import { memberships, sessions, users, withTenant, type Tx } from "@vigil/db";
import { getDb } from "../db.js";
import { sha256 } from "./crypto.js";
import { ApiError, forbidden } from "./errors.js";
import { can, type Permission, type Role } from "./rbac.js";
import { audit, type AuditEntry } from "./audit.js";
import { takeToken } from "./ratelimit.js";

export interface AuthUser { id: string; email: string; displayName: string; mustChangePassword?: boolean }
export type Vars = {
  requestId: string;
  ip: string | null;
  user: AuthUser | null;
  sessionId: string | null;
  csrf: string | null;
  tenantId: string | null;
  role: Role | null;
};
export type AppEnv = { Variables: Vars };
export type Ctx = Context<AppEnv>;

export const SESSION_COOKIE = "vigil_session";
export const CSRF_HEADER = "x-vigil-csrf";

export const newApp = () => new OpenAPIHono<AppEnv>({
  defaultHook: (result) => {
    if (!result.success) throw new ApiError(400, "validation_error", "request validation failed", z.treeifyError(result.error as any));
  },
});

export const requestContext: MiddlewareHandler<AppEnv> = async (c, next) => {
  c.set("requestId", c.req.header("x-request-id")?.slice(0, 64) || crypto.randomUUID());
  // Behind a trusted proxy set VIGIL_TRUST_PROXY=1; otherwise do not trust x-forwarded-for.
  const fwd = process.env.VIGIL_TRUST_PROXY === "1" ? c.req.header("x-forwarded-for")?.split(",")[0]?.trim() : undefined;
  const incoming = (c.env as any)?.incoming;
  c.set("ip", fwd ?? incoming?.socket?.remoteAddress ?? null);
  c.set("user", null); c.set("sessionId", null); c.set("tenantId", null); c.set("role", null); c.set("csrf", null);
  if (!takeToken(`api:${c.get("ip") ?? "unknown"}`, 300, 20)) throw new ApiError(429, "rate_limited", "too many requests");
  await next();
  c.header("x-request-id", c.get("requestId"));
};

/** Resolve the session cookie → user, active tenant and role (role re-read on every request). */
export const sessionAuth: MiddlewareHandler<AppEnv> = async (c, next) => {
  const token = getCookie(c, SESSION_COOKIE);
  if (token) {
    const db = getDb();
    const [row] = await db.select({ s: sessions, u: users }).from(sessions).innerJoin(users, eq(users.id, sessions.userId))
      .where(and(eq(sessions.tokenHash, sha256(token)), gt(sessions.expiresAt, new Date()), eq(users.isActive, true))).limit(1);
    if (row) {
      c.set("user", { id: row.u.id, email: row.u.email, displayName: row.u.displayName, mustChangePassword: row.u.mustChangePassword });
      c.set("sessionId", row.s.id);
      c.set("csrf", row.s.csrfToken);
      if (row.s.activeTenantId) {
        const role = await withTenant(db, { tenantId: row.s.activeTenantId, userId: row.u.id }, async (tx) => {
          const [m] = await tx.select({ role: memberships.role }).from(memberships)
            .where(and(eq(memberships.tenantId, row.s.activeTenantId!), eq(memberships.userId, row.u.id))).limit(1);
          return m?.role ?? null;
        });
        if (role) { c.set("tenantId", row.s.activeTenantId); c.set("role", role); }
      }
      if (Date.now() - row.s.lastSeenAt.getTime() > 60_000) {
        await db.update(sessions).set({ lastSeenAt: new Date() }).where(eq(sessions.id, row.s.id));
      }
    }
  }
  const m = c.req.method;
  if (m !== "GET" && m !== "HEAD" && m !== "OPTIONS" && c.get("user")) {
    const sent = c.req.header(CSRF_HEADER);
    if (!sent || sent !== c.get("csrf")) throw new ApiError(403, "csrf", "missing or invalid CSRF token");
  }
  // One-time (CLI-issued) passwords must be replaced before anything else can be used.
  if (c.get("user")?.mustChangePassword && !/\/api\/v1\/auth\/(me|logout|change-password)$/.test(c.req.path)) {
    throw new ApiError(403, "password_change_required", "change your one-time password first");
  }
  await next();
};

export function requireAuth(c: Ctx): AuthUser {
  const u = c.get("user");
  if (!u) throw new ApiError(401, "unauthenticated", "authentication required");
  return u;
}

export function requirePerm(c: Ctx, p: Permission): { user: AuthUser; tenantId: string; role: Role } {
  const user = requireAuth(c);
  const tenantId = c.get("tenantId");
  const role = c.get("role");
  if (!tenantId || !role) throw forbidden("no active tenant");
  if (!can(role, p)) throw forbidden(`missing permission ${p}`);
  return { user, tenantId, role };
}

/** Run fn in a tenant-scoped transaction (RLS) and give it an audit helper bound to the caller. */
export async function tenantTx<T>(c: Ctx, p: Permission, fn: (tx: Tx, a: { user: AuthUser; tenantId: string; role: Role; audit: (e: Omit<AuditEntry, "tenantId" | "actorType" | "actorId" | "requestId" | "ip">) => Promise<void> }) => Promise<T>): Promise<T> {
  const { user, tenantId, role } = requirePerm(c, p);
  return withTenant(getDb(), { tenantId, userId: user.id }, (tx) => fn(tx, {
    user, tenantId, role,
    audit: (e) => audit(tx, { ...e, tenantId, actorType: "user", actorId: user.id, requestId: c.get("requestId"), ip: c.get("ip") }),
  }));
}

// ---------- OpenAPI route helper ----------
export const Pagination = z.object({
  limit: z.coerce.number().int().min(1).max(500).default(50),
  offset: z.coerce.number().int().min(0).max(1_000_000).default(0),
});
export const IdParam = z.object({ id: z.string().uuid() });
const AnyJson = z.any();

interface RouteOpts<P, Q, B> {
  summary: string;
  tags: string[];
  params?: P;
  query?: Q;
  body?: B;
}

export function route<P extends z.ZodObject | undefined, Q extends z.ZodObject | undefined, B extends z.ZodType | undefined>(
  app: OpenAPIHono<AppEnv>, method: "get" | "post" | "patch" | "put" | "delete", path: string, opts: RouteOpts<P, Q, B>,
  handler: (c: Ctx, input: { params: P extends z.ZodType ? z.infer<P> : undefined; query: Q extends z.ZodType ? z.infer<Q> : undefined; body: B extends z.ZodType ? z.infer<B> : undefined }) => Promise<Response>,
) {
  const request: RouteConfig["request"] = {};
  if (opts.params) request.params = opts.params as any;
  if (opts.query) request.query = opts.query as any;
  if (opts.body) request.body = { content: { "application/json": { schema: opts.body as any } }, required: true };
  const r = createRoute({
    method, path, summary: opts.summary, tags: opts.tags, request,
    responses: { 200: { description: "OK", content: { "application/json": { schema: AnyJson } } } },
  });
  app.openapi(r, (async (c: any) => {
    const input = {
      params: opts.params ? c.req.valid("param") : undefined,
      query: opts.query ? c.req.valid("query") : undefined,
      body: opts.body ? c.req.valid("json") : undefined,
    };
    return handler(c, input as any);
  }) as any);
}

export const tsRange = z.object({
  start: z.string().datetime({ offset: true }).optional(),
  end: z.string().datetime({ offset: true }).optional(),
});

export { sql };
