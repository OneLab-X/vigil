/**
 * LIVE verification against a real New Relic account (read-only NRQL via NerdGraph). Requires a running API + worker.
 * Usage:
 *   NEW_RELIC_USER_KEY=NRAK-… NEW_RELIC_ACCOUNT_ID=1234567 [NEW_RELIC_REGION=US|EU] [NEW_RELIC_WHERE="environment = 'prod'"] \
 *   node --experimental-strip-types scripts/verify-newrelic-live.mts [hours]
 * Use a User API key of a read-only user. The key is read from the environment and never printed.
 */
import { verifyLive } from "./lib/verify-connector-live.mts";

const [hours = "6"] = process.argv.slice(2);
const env = process.env;
if (!env.NEW_RELIC_USER_KEY || !env.NEW_RELIC_ACCOUNT_ID) { console.error("set NEW_RELIC_USER_KEY and NEW_RELIC_ACCOUNT_ID"); process.exit(2); }

await verifyLive({
  provider: "newrelic",
  displayName: `New Relic ${env.NEW_RELIC_ACCOUNT_ID}`,
  accountRef: String(Number(env.NEW_RELIC_ACCOUNT_ID)),
  config: { region: env.NEW_RELIC_REGION ?? "US", accountId: Number(env.NEW_RELIC_ACCOUNT_ID), ...(env.NEW_RELIC_WHERE ? { nrqlWhere: env.NEW_RELIC_WHERE } : {}) },
  credentials: { userApiKey: env.NEW_RELIC_USER_KEY },
  pick: (s) => s.available && s.recommended,
  hours: Number(hours),
});
