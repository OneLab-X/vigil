import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

function req(name: string, devDefault: string): string {
  const v = process.env[name];
  if (v) return v;
  if (process.env.NODE_ENV === "production") throw new Error(`missing required env ${name}`);
  return devDefault;
}

export const env = {
  nodeEnv: process.env.NODE_ENV ?? "development",
  port: Number(process.env.PORT ?? 8080),
  /** 127.0.0.1 for local dev; 0.0.0.0 inside containers (the API is only reachable on the internal network). */
  host: process.env.VIGIL_HOST ?? "127.0.0.1",
  version: process.env.VIGIL_VERSION ?? "dev",
  databaseUrl: req("VIGIL_DATABASE_URL", "postgres://vigil_app:vigil_app_dev@127.0.0.1:54329/vigil"),
  webOrigin: process.env.VIGIL_WEB_ORIGIN ?? "http://localhost:3000",
  /** 32-byte hex key for AES-GCM secret encryption and run-token HMAC. Dev default is NOT secret. */
  secretKey: req("VIGIL_SECRET_KEY", "6465762d6f6e6c792d6b65792d646f2d6e6f742d7573652d696e2d70726f6421"),
  dataDir: process.env.VIGIL_DATA_DIR ?? path.join(root, ".local"),
  agentsUrl: process.env.VIGIL_AGENTS_URL ?? "http://127.0.0.1:8090",
  /** URL the agent worker uses to reach the tool broker */
  brokerUrl: process.env.VIGIL_BROKER_URL ?? "http://127.0.0.1:8080",
  internalToken: req("VIGIL_INTERNAL_TOKEN", "dev-internal-token-change-me"),
  runWorker: process.env.VIGIL_RUN_WORKER !== "0",
  sessionTtlHours: Number(process.env.VIGIL_SESSION_TTL_HOURS ?? 12),
  maxPagesPerJob: Number(process.env.VIGIL_MAX_PAGES_PER_JOB ?? 50),
  ingestLagMinutes: Number(process.env.VIGIL_INGEST_LAG_MINUTES ?? 5),
  /** Operations page: a log source whose watermark is older than this is "lagging". */
  opsLagThresholdMinutes: Number(process.env.VIGIL_OPS_LAG_THRESHOLD_MINUTES ?? 30),
  secureCookies: process.env.NODE_ENV === "production",
};
