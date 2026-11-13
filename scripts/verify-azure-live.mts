/**
 * LIVE verification against a real Azure subscription (read-only). Requires a running API + worker.
 * Usage:
 *   AZURE_TENANT_ID=… AZURE_SUBSCRIPTION_ID=… [AZURE_CLIENT_ID=… AZURE_CLIENT_SECRET=…] \
 *   [AZURE_ENTRA_SOURCE=graph|log_analytics|none AZURE_WORKSPACE_ID=…] \
 *   node --experimental-strip-types scripts/verify-azure-live.mts [hours] [authMode]
 * authMode defaults to azure_cli (local dev, `az login`) when no client secret is set, else client_secret.
 * The client secret is read from the environment and never printed.
 */
import { verifyLive } from "./lib/verify-connector-live.mts";

const [hours = "24", modeArg] = process.argv.slice(2);
const env = process.env;
if (!env.AZURE_TENANT_ID || !env.AZURE_SUBSCRIPTION_ID) { console.error("set AZURE_TENANT_ID and AZURE_SUBSCRIPTION_ID"); process.exit(2); }
const authMode = modeArg ?? (env.AZURE_CLIENT_SECRET ? "client_secret" : "azure_cli");
const entraSource = env.AZURE_ENTRA_SOURCE ?? "graph";

await verifyLive({
  provider: "azure",
  displayName: `Azure ${env.AZURE_SUBSCRIPTION_ID.slice(0, 8)}`,
  accountRef: env.AZURE_SUBSCRIPTION_ID.toLowerCase(),
  config: { tenantId: env.AZURE_TENANT_ID, subscriptionId: env.AZURE_SUBSCRIPTION_ID, clientId: env.AZURE_CLIENT_ID, authMode, entraSource, workspaceId: env.AZURE_WORKSPACE_ID },
  credentials: authMode === "client_secret" ? { clientSecret: env.AZURE_CLIENT_SECRET } : undefined,
  hours: Number(hours),
});
