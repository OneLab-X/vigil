import { z } from "zod";
import { and, eq, ne } from "drizzle-orm";
import { setCookie, deleteCookie } from "hono/cookie";
import { memberships, sessions, tenants, users, withUser } from "@vigil/db";
import { getDb } from "../db.js";
import { env } from "../env.js";
import { newApp, requireAuth, route, SESSION_COOKIE } from "../lib/context.js";
import { hashPassword, randomToken, sha256, verifyPassword } from "../lib/crypto.js";
import { ApiError, forbidden } from "../lib/errors.js";
import { audit } from "../lib/audit.js";
import { takeToken } from "../lib/ratelimit.js";
import { permissionsFor } from "../lib/rbac.js";

export const authRoutes = newApp();

route(authRoutes, "post", "/auth/login", {
  summary: "Sign in with email and password", tags: ["auth"],
  body: z.object({ email: z.string().email().max(320), password: z.string().min(1).max(512) }),
}, async (c, { body }) => {
  const ip = c.get("ip") ?? "unknown";
  const email = body.email.toLowerCase();
  if (!takeToken(`login:${ip}`, 10, 0.1) || !takeToken(`login:${email}`, 10, 0.05)) throw new ApiError(429, "rate_limited", "too many login attempts");
  const db = getDb();
  const [u] = await db.select().from(users).where(eq(users.email, email)).limit(1);
  const ok = await verifyPassword(body.password, u?.passwordHash ?? null);
  if (!u || !ok || !u.isActive) {
    await db.transaction((tx) => audit(tx, { tenantId: null, actorType: "user", actorId: null, action: "auth.login_failed", details: { email_hash: sha256(email).slice(0, 16) }, ip, requestId: c.get("requestId") }));
    throw new ApiError(401, "invalid_credentials", "invalid email or password");
  }
  const first = await withUser(db, u.id, (tx) => tx.select({ tenantId: memberships.tenantId }).from(memberships).where(eq(memberships.userId, u.id)).limit(1));
  const token = randomToken();
  const csrf = randomToken(24);
  await db.insert(sessions).values({ userId: u.id, tokenHash: sha256(token), csrfToken: csrf, activeTenantId: first[0]?.tenantId ?? null, expiresAt: new Date(Date.now() + env.sessionTtlHours * 3600_000), ip });
  await db.transaction((tx) => audit(tx, { tenantId: null, actorType: "user", actorId: u.id, action: "auth.login", ip, requestId: c.get("requestId") }));
  setCookie(c, SESSION_COOKIE, token, { httpOnly: true, sameSite: "Lax", secure: env.secureCookies, path: "/", maxAge: env.sessionTtlHours * 3600 });
  return c.json({ ok: true, csrf, mustChangePassword: u.mustChangePassword });
});

route(authRoutes, "post", "/auth/logout", { summary: "Sign out", tags: ["auth"] }, async (c) => {
  const sid = c.get("sessionId");
  if (sid) await getDb().delete(sessions).where(eq(sessions.id, sid));
  deleteCookie(c, SESSION_COOKIE, { path: "/" });
  return c.json({ ok: true });
});

route(authRoutes, "get", "/auth/me", { summary: "Current user, tenants and permissions", tags: ["auth"] }, async (c) => {
  const user = requireAuth(c);
  const rows = await withUser(getDb(), user.id, (tx) => tx.select({ id: tenants.id, name: tenants.name, slug: tenants.slug, role: memberships.role })
    .from(memberships).innerJoin(tenants, eq(tenants.id, memberships.tenantId)).where(eq(memberships.userId, user.id)));
  const role = c.get("role");
  return c.json({ user, csrf: c.get("csrf"), activeTenantId: c.get("tenantId"), role, permissions: role ? permissionsFor(role) : [], tenants: rows });
});

route(authRoutes, "post", "/auth/switch-tenant", {
  summary: "Switch the active tenant", tags: ["auth"], body: z.object({ tenantId: z.string().uuid() }),
}, async (c, { body }) => {
  const user = requireAuth(c);
  const db = getDb();
  const m = await withUser(db, user.id, (tx) => tx.select().from(memberships).where(and(eq(memberships.userId, user.id), eq(memberships.tenantId, body.tenantId))).limit(1));
  if (!m.length) throw forbidden("not a member of that tenant");
  await db.update(sessions).set({ activeTenantId: body.tenantId }).where(eq(sessions.id, c.get("sessionId")!));
  return c.json({ ok: true });
});

route(authRoutes, "post", "/auth/change-password", {
  summary: "Change own password (required after a one-time password)", tags: ["auth"],
  body: z.object({ currentPassword: z.string().min(1).max(512), newPassword: z.string().min(12).max(512) }),
}, async (c, { body }) => {
  const user = requireAuth(c);
  const ip = c.get("ip") ?? "unknown";
  if (!takeToken(`pwchange:${user.id}`, 5, 0.05)) throw new ApiError(429, "rate_limited", "too many attempts");
  const db = getDb();
  const [u] = await db.select().from(users).where(eq(users.id, user.id)).limit(1);
  if (!u || !(await verifyPassword(body.currentPassword, u.passwordHash))) throw new ApiError(400, "invalid_password", "current password is incorrect");
  if (body.newPassword === body.currentPassword) throw new ApiError(400, "weak_password", "new password must differ from the current one");
  await db.update(users).set({ passwordHash: await hashPassword(body.newPassword), mustChangePassword: false }).where(eq(users.id, u.id));
  // revoke every other session of this user
  await db.delete(sessions).where(and(eq(sessions.userId, u.id), ne(sessions.id, c.get("sessionId")!)));
  await db.transaction((tx) => audit(tx, { tenantId: null, actorType: "user", actorId: u.id, action: "auth.password_changed", ip, requestId: c.get("requestId") }));
  return c.json({ ok: true });
});
