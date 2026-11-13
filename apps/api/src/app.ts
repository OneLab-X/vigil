import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import { bodyLimit } from "hono/body-limit";
import { HTTPException } from "hono/http-exception";
import { newApp, requestContext, sessionAuth } from "./lib/context.js";
import { ApiError } from "./lib/errors.js";
import { env } from "./env.js";
import { authRoutes } from "./routes/auth.js";
import { connectionRoutes } from "./routes/connections.js";
import { dataRoutes } from "./routes/data.js";
import { incidentRoutes } from "./routes/incidents.js";
import { governanceRoutes } from "./routes/governance.js";
import { internalRoutes } from "./routes/internal.js";
import { readiness } from "./services/health.js";
import { modelRoutes } from "./routes/models.js";
import { operationsRoutes } from "./routes/operations.js";
import { notificationRoutes } from "./routes/notifications.js";
import { latencyMiddleware } from "./lib/latency.js";

export function buildApp() {
  const app = newApp();
  app.use("*", secureHeaders());
  app.use("/api/*", cors({ origin: env.webOrigin, credentials: true, allowHeaders: ["content-type", "x-vigil-csrf", "x-request-id"], allowMethods: ["GET", "POST", "PATCH", "PUT", "DELETE"] }));
  app.use("*", bodyLimit({ maxSize: 2 * 1024 * 1024 }));
  app.use("*", requestContext);
  // Records per-minute latency rollups (route template + status class only); reads tenantId set by sessionAuth.
  app.use("/api/*", latencyMiddleware());
  app.use("/api/*", sessionAuth);

  app.get("/healthz", (c) => c.json({ ok: true }));
  // Readiness: dependencies reachable. Returns component status only (no versions of secrets, no hostnames).
  app.get("/readyz", async (c) => { const r = await readiness(); return c.json(r, r.ok ? 200 : 503); });
  for (const r of [authRoutes, connectionRoutes, dataRoutes, incidentRoutes, governanceRoutes, modelRoutes, operationsRoutes, notificationRoutes]) app.route("/api/v1", r);
  app.route("/internal/v1", internalRoutes);

  app.doc31("/api/v1/openapi.json", { openapi: "3.1.0", info: { title: "Vigil Agentic SOC API", version: "1.0.0", description: "Versioned REST API. Session-cookie auth + x-vigil-csrf header for mutations." } });

  app.onError((err, c) => {
    if (err instanceof ApiError) return c.json({ error: { code: err.code, message: err.message, details: err.details }, requestId: c.get("requestId") }, err.status as any);
    if (err instanceof HTTPException) return c.json({ error: { code: "http_error", message: err.message } }, err.status);
    console.error(JSON.stringify({ level: "error", msg: "unhandled", requestId: c.get("requestId"), err: err.message, stack: env.nodeEnv === "production" ? undefined : err.stack }));
    return c.json({ error: { code: "internal", message: "internal error" }, requestId: c.get("requestId") }, 500);
  });
  return app;
}
