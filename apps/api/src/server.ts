import { serve } from "@hono/node-server";
import { buildApp } from "./app.js";
import { env } from "./env.js";
import { getDb } from "./db.js";
import { startWorker } from "./worker.js";
import { startLatencyFlusher } from "./lib/latency.js";

const app = buildApp();
serve({ fetch: app.fetch, port: env.port, hostname: env.host }, (i) => console.log(JSON.stringify({ level: "info", msg: "vigil api listening", port: i.port, worker: env.runWorker })));
if (env.runWorker) startWorker(getDb());
startLatencyFlusher(getDb());
