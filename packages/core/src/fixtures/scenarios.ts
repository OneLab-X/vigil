/**
 * SYNTHETIC replay scenarios for registry connectors (beyond the original GCP/AWS library in synthetic.ts).
 * Records are raw vendor-shaped payloads tagged with the source type they would be ingested under, so they are
 * normalized through the same registry normalizers as live data.
 */
import { getConnector, normalizerFor } from "../connectors/registry.js";
import "../connectors/builtin.js";
import type { CanonicalEvent } from "../types.js";
import { buildAzureScenarios } from "./azure.js";
import { buildDatadogScenarios } from "./datadog.js";
import { buildNewRelicScenarios } from "./newrelic.js";

export interface ConnectorScenario {
  id: string;
  connector: string;
  description: string;
  records: Array<{ sourceType: string; raw: unknown }>;
  /** connection config used to normalize (defaults to the fixture account) */
  config?: Record<string, unknown>;
  expectedRules: string[];
  expectedVerdict: "confirmed" | "likely" | "benign" | "inconclusive" | "needs_more_data";
}

const FIXTURE_CONFIG: Record<string, Record<string, unknown>> = {
  newrelic: { region: "US", accountId: 1234567 },
  datadog: { site: "datadoghq.com", orgName: "acme", indexes: ["*"] },
  azure: { tenantId: "11111111-2222-3333-4444-555555555555", subscriptionId: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", authMode: "azure_cli", entraSource: "graph" },
};
export const fixtureConfig = (connector: string) => FIXTURE_CONFIG[connector] ?? {};

export function buildConnectorScenarios(base?: Date): ConnectorScenario[] {
  return [...buildAzureScenarios(base), ...buildDatadogScenarios(base), ...buildNewRelicScenarios(base)];
}

/** Normalize a scenario's records through the connector registry. */
export function normalizeScenario(s: ConnectorScenario): CanonicalEvent[] {
  const def = getConnector(s.connector);
  if (!def) throw new Error(`unknown connector ${s.connector}`);
  const config = def.configSchema.parse(s.config ?? fixtureConfig(s.connector));
  return s.records.map((r) => normalizerFor(def, r.sourceType)(r.raw, { config, sourceType: r.sourceType }));
}
