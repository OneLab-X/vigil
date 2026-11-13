/** Standalone background worker (ingestion, detection, agent dispatch, timeouts) — no HTTP listener. */
import fs from "node:fs";
import { getDb, closeDb } from "./db.js";
import { startWorker } from "./worker.js";

const heartbeat = process.env.VIGIL_WORKER_HEARTBEAT_FILE ?? "/tmp/vigil-worker-heartbeat";
const stop = startWorker(getDb(), () => { try { fs.writeFileSync(heartbeat, String(Date.now())); } catch { /* best effort */ } });
console.log(JSON.stringify({ level: "info", msg: "vigil worker started" }));
for (const sig of ["SIGTERM", "SIGINT"] as const) process.on(sig, async () => { stop(); await closeDb(); process.exit(0); });
