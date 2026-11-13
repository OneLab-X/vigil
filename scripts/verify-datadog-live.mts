/**
 * LIVE verification against a real Datadog org (read-only search APIs only). Requires a running API + worker.
 * Usage:
 *   DD_API_KEY=… DD_APP_KEY=… [DD_SITE=datadoghq.com] [DD_ORG=acme] [DD_INDEXES=main,security] \
 *   node --experimental-strip-types scripts/verify-datadog-live.mts [hours]
 * Use an application key scoped to logs_read_data (+ optional security_monitoring_signals_read, audit_logs_read).
 * Keys are read from the environment and never printed.
 */
import { verifyLive } from "./lib/verify-connector-live.mts";

const [hours = "6"] = process.argv.slice(2);
const env = process.env;
if (!env.DD_API_KEY || !env.DD_APP_KEY) { console.error("set DD_API_KEY and DD_APP_KEY"); process.exit(2); }
const site = env.DD_SITE ?? "datadoghq.com";
const orgName = env.DD_ORG ?? "datadog-live";

await verifyLive({
  provider: "datadog",
  displayName: `Datadog ${orgName}`,
  accountRef: `${orgName}@${site}`,
  config: { site, orgName, indexes: (env.DD_INDEXES ?? "*").split(",").map((s) => s.trim()).filter(Boolean) },
  credentials: { apiKey: env.DD_API_KEY, appKey: env.DD_APP_KEY },
  // enable every preset that returned data in the last 24h
  pick: (s) => s.available,
  hours: Number(hours),
});
