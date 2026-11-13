import { z } from "zod";
import { newApp, route } from "../lib/context.js";
import { getDb } from "../db.js";
import { invokeTool } from "../services/broker.js";
import { RunResultSchema, submitRunResult } from "../services/investigation.js";

/** Agent-worker endpoints. Authenticated solely by the per-run signed token. */
export const internalRoutes = newApp();

const bearer = (h: string | undefined) => (h?.startsWith("Bearer ") ? h.slice(7) : undefined);

route(internalRoutes, "post", "/broker/tools/{tool}", {
  summary: "Tool broker: execute an allow-listed, tenant-scoped tool for an agent run", tags: ["internal"],
  params: z.object({ tool: z.string().regex(/^[a-z_]{3,64}$/) }), body: z.record(z.string(), z.unknown()),
}, async (c, { params, body }) => c.json(await invokeTool(getDb(), bearer(c.req.header("authorization")), params.tool, body)));

route(internalRoutes, "post", "/runs/{id}/result", {
  summary: "Agent run completion (validated and grounded before acceptance)", tags: ["internal"],
  params: z.object({ id: z.string().uuid() }), body: RunResultSchema,
}, async (c, { params, body }) => c.json(await submitRunResult(getDb(), bearer(c.req.header("authorization")), params.id, body)));
